/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * p4gate_nic.c - the whole P4Gate pipeline on the BlueField-3 (SmartNIC-only implementation, the "all-on-the-NIC" arm), DPDK.
 *
 *   per packet     parse Ethernet / IPv4 / TCP -> per-flow registers (packet count, length max / total, IAT min / max, K LLR accumulators through the
 *                  size / IAT range tables and the exact-match LLR table), exactly the registers of the P4 ingress (p4gate/core.h)
 *   at packet N    the small forest (rf_model.h) gives a class or DEFER (p4gate/gate.h);  accepted -> stop,  DEFER -> boosted trees (gbt_model.h)
 *   measurement    per RX burst (up to 32 packets): processing time from the return of rte_eth_rx_burst() to the last packet of the burst done, and the
 *                  time since the previous burst arrived; per completed flow: its class, whether the NIC model ran, and the time of the forest and of the model
 *
 *   sudo ./build/p4gate_nic -l 0-3 -a <pci> -- --gate score --ts hw --out results/nic_only        (traffic: tcpreplay test.pcap / test_fast.pcap)
 *   outputs  <out>_bursts.csv  <out>_flows.csv  and a summary on stdout; python tools/analyze_gate.py scores them against truth.csv
 *
 * Build:  make -f Makefile.p4gate p4gate_nic GEN=../CP/p4gate_online/<dataset>/nic        Parity (no DPDK): tests/test_p4gate.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <stdatomic.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_prefetch.h>
#include <rte_version.h>

#include "gate.h"

#define RX_RING_SIZE   2048
#define TX_RING_SIZE   1024
#define NUM_MBUFS      16383
#define MBUF_CACHE     512
#define MBUF_DATA_ROOM 9216           /* single-segment jumbo frames */
#define BURST_SIZE     32
#define MAX_CORES      RTE_MAX_LCORE

static struct {
    int ts_hw;                  /* use the NIC RX hardware timestamp for the IAT (else TSC at burst arrival) */
    double ns_per_tick;         /* hardware timestamp unit (1.0 = nanoseconds); the summary prints an estimate */
    int gate_mode;              /* GATE_SCORE | GATE_VOTES */
    uint32_t table_bits;        /* flows per worker = 2^table_bits */
    uint32_t max_bursts;        /* bursts kept per worker */
    uint32_t max_rows;          /* flow rows kept per worker */
    int port;
    const char *out;
} g_cfg = { 0, 1.0, GATE_SCORE, 18, 1u << 22, 1u << 20, 0, "p4gate_nic" };

static atomic_int g_stop = 0;
static int g_ts_off = -1;
static uint64_t g_ts_flag = 0;

struct burst_rec { uint32_t nb, proc_ns, gap_ns; uint16_t completed, deferred, nic, pad; };           /* 16 B */
struct flow_row {
    uint32_t flow_idx, src, dst;           /* flow_idx = address-encoded index of the replay (10.<set>.<hi>.<lo>) */
    uint16_t sport, dport;
    uint8_t  cls, deferred, label, nic_ran;
    uint16_t score_sum;
    uint8_t  n_defer, pad;
    uint32_t gate_ns, nic_ns;
    uint64_t rx_ns;
};

struct worker {
    uint16_t port, queue;
    struct flow_table tab;
    struct burst_rec *bursts;
    struct flow_row *rows;
    uint32_t nb, nrows, dropped_bursts, dropped_rows;
    uint64_t rx_pkts, flow_pkts, other_pkts, multiseg, completed, deferred, nic_runs;
    uint64_t hw_first_tsc, hw_first_ts, hw_last_tsc, hw_last_ts;
} __rte_cache_aligned;

static struct worker g_w[MAX_CORES];

static inline uint64_t tsc_to_ns(uint64_t c, double hz) { return (uint64_t)((double)c * 1e9 / hz); }

static int port_init(uint16_t port, struct rte_mempool *pool, uint16_t nq, uint16_t *out_nq)
{
    struct rte_eth_dev_info di;
    int ret = rte_eth_dev_info_get(port, &di);
    if (ret) { printf("dev_info_get failed: %s\n", strerror(-ret)); return ret; }
    if (nq > di.max_rx_queues) nq = di.max_rx_queues;
    if (nq > di.max_tx_queues) nq = di.max_tx_queues;

    struct rte_eth_conf conf;
    memset(&conf, 0, sizeof(conf));
    conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    conf.rxmode.mtu = 9000;
    conf.rx_adv_conf.rss_conf.rss_hf = (RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP) & di.flow_type_rss_offloads;    /* unidirectional flows stay on one queue */
    if (conf.rx_adv_conf.rss_conf.rss_hf == 0) conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
    if (g_cfg.ts_hw) {
        if (di.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP) conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TIMESTAMP;
        else { printf("WARNING: port has no RX timestamp offload, falling back to TSC\n"); g_cfg.ts_hw = 0; }
    }
    ret = rte_eth_dev_configure(port, nq, nq, &conf);
    if (ret < 0) { printf("dev_configure failed: %s\n", strerror(-ret)); return ret; }
    uint16_t nrxd = RX_RING_SIZE, ntxd = TX_RING_SIZE;
    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nrxd, &ntxd);
    if (ret < 0) return ret;
    struct rte_eth_rxconf rxc = di.default_rxconf;
    for (uint16_t q = 0; q < nq; q++) {
        ret = rte_eth_rx_queue_setup(port, q, nrxd, rte_eth_dev_socket_id(port), &rxc, pool);
        if (ret < 0) return ret;
    }
    struct rte_eth_txconf txc = di.default_txconf;
    txc.offloads = conf.txmode.offloads;
    for (uint16_t q = 0; q < nq; q++) {
        ret = rte_eth_tx_queue_setup(port, q, ntxd, rte_eth_dev_socket_id(port), &txc);
        if (ret < 0) return ret;
    }
    if (g_cfg.ts_hw) {
        ret = rte_mbuf_dyn_rx_timestamp_register(&g_ts_off, &g_ts_flag);
        if (ret) { printf("WARNING: rx timestamp dynfield registration failed (%d), falling back to TSC\n", ret); g_cfg.ts_hw = 0; }
    }
    ret = rte_eth_dev_start(port);
    if (ret < 0) return ret;
    rte_eth_promiscuous_enable(port);
    printf("port %u: %u queue(s), mtu 9000, hw timestamps %s\n", port, nq, g_cfg.ts_hw ? "on" : "off");
    *out_nq = nq;
    return 0;
}

static int lcore_main(void *arg)
{
    struct worker *w = arg;
    const double hz = (double)rte_get_tsc_hz();
    struct rte_mbuf *bufs[BURST_SIZE];
    uint64_t t_prev = 0;
    printf("core %u: queue %u, gate %s\n", rte_lcore_id(), w->queue, g_cfg.gate_mode == GATE_SCORE ? "score" : "votes");

    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        uint16_t nb = rte_eth_rx_burst(w->port, w->queue, bufs, BURST_SIZE);
        if (unlikely(nb == 0)) continue;
        const uint64_t t_rx = rte_rdtsc_precise();          /* the burst is in memory: the clock of the burst latency starts here */
        w->rx_pkts += nb;
        uint16_t completed = 0, deferred = 0, nic = 0;

        for (uint16_t i = 0; i < nb; i++) {
            struct rte_mbuf *m = bufs[i];
            if (i + 2 < nb) rte_prefetch0(rte_pktmbuf_mtod(bufs[i + 2], void *));
            if (unlikely(m->nb_segs != 1)) { w->multiseg++; continue; }
            const uint8_t *data = rte_pktmbuf_mtod(m, uint8_t *);
            const uint32_t len = rte_pktmbuf_data_len(m);

            struct pkt_info p;
            if (!parse_ipv4(data, len, &p)) { w->other_pkts++; continue; }        /* not IPv4 / TCP */
            w->flow_pkts++;
            uint64_t ts_ns;
            if (g_cfg.ts_hw && (m->ol_flags & g_ts_flag)) {
                const uint64_t hw = *RTE_MBUF_DYNFIELD(m, g_ts_off, rte_mbuf_timestamp_t *);
                if (!w->hw_first_ts) { w->hw_first_ts = hw; w->hw_first_tsc = t_rx; }
                w->hw_last_ts = hw; w->hw_last_tsc = t_rx;
                ts_ns = (uint64_t)((double)hw * g_cfg.ns_per_tick);
            } else {
                ts_ns = tsc_to_ns(t_rx, hz);                                       /* burst-granular */
            }
            struct flow_state *f = flow_lookup(&w->tab, &p);
            if (!f || !flow_update(f, p.iplen, ts_ns)) continue;

            /* ---- packet N of this flow: small forest, gate, and the big model only for DEFER ---- */
            const uint64_t g0 = rte_rdtsc();
            int32_t x[RF_NFEAT];
            gate_keys(f, x);
            const struct gate_result g = rf_gate(x, g_cfg.gate_mode);
            const uint64_t g1 = rte_rdtsc();
            uint8_t label = g.cls, ran = 0;
            uint64_t n1 = g1;
            if (g.defer) {                                       /* DEFER: the boosted trees give the label */
                float xf[N_FEAT], margin[GBT_NCLASS];
                nic_features(f, xf);
                label = (uint8_t)GBT_CLASS_MAP[gbt_predict(xf, margin)];
                n1 = rte_rdtsc();
                ran = 1; nic++;
            }
            completed++; deferred += g.defer;
            if (w->nrows < g_cfg.max_rows) {
                struct flow_row *r = &w->rows[w->nrows++];
                r->flow_idx = ((p.src >> 8) & 0xFF) << 8 | (p.src & 0xFF);
                r->src = p.src; r->dst = p.dst; r->sport = p.sport; r->dport = p.dport;
                r->cls = g.cls; r->deferred = g.defer; r->label = label; r->nic_ran = ran;
                r->score_sum = g.score_sum; r->n_defer = g.n_defer;
                r->gate_ns = (uint32_t)tsc_to_ns(g1 - g0, hz); r->nic_ns = ran ? (uint32_t)tsc_to_ns(n1 - g1, hz) : 0;
                r->rx_ns = ts_ns;
            } else w->dropped_rows++;
        }
        const uint64_t t_done = rte_rdtsc_precise();
        if (w->nb < g_cfg.max_bursts) {
            struct burst_rec *b = &w->bursts[w->nb++];
            b->nb = nb; b->proc_ns = (uint32_t)tsc_to_ns(t_done - t_rx, hz);
            b->gap_ns = t_prev ? (uint32_t)tsc_to_ns(t_rx - t_prev, hz) : 0;
            b->completed = completed; b->deferred = deferred; b->nic = nic;
        } else w->dropped_bursts++;
        t_prev = t_rx;
        w->completed += completed; w->deferred += deferred; w->nic_runs += nic;
        rte_pktmbuf_free_bulk(bufs, nb);                                          /* mirrored traffic: nothing is sent back */
    }
    return 0;
}

static void on_term(int s) { (void)s; atomic_store_explicit(&g_stop, 1, memory_order_relaxed); }

static int cmp_u32(const void *a, const void *b) { uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b; return (x > y) - (x < y); }

static void report(unsigned workers)
{
    char path[512];
    snprintf(path, sizeof(path), "%s_bursts.csv", g_cfg.out);
    FILE *f = fopen(path, "w");
    uint64_t nbursts = 0, npk = 0, comp = 0, def = 0, nic = 0, full = 0, flow_pkts = 0;
    if (f) fprintf(f, "core,burst,nb,proc_ns,gap_ns,completed,deferred,nic_runs\n");
    for (unsigned c = 0; c < workers; c++) {
        const struct worker *w = &g_w[c];
        for (uint32_t i = 0; f && i < w->nb; i++) {
            const struct burst_rec *b = &w->bursts[i];
            fprintf(f, "%u,%u,%u,%u,%u,%u,%u,%u\n", c, i, b->nb, b->proc_ns, b->gap_ns, b->completed, b->deferred, b->nic);
        }
        nbursts += w->nb; npk += w->rx_pkts; comp += w->completed; def += w->deferred; nic += w->nic_runs; full += w->tab.full_drops; flow_pkts += w->flow_pkts;
    }
    if (f) { fclose(f); printf("wrote %s_bursts.csv\n", g_cfg.out); }

    snprintf(path, sizeof(path), "%s_flows.csv", g_cfg.out);
    f = fopen(path, "w");
    if (f) fprintf(f, "core,flow_idx,src,dst,sport,dport,class,deferred,label,nic_ran,score_sum,n_defer,gate_ns,nic_ns,rx_ns\n");
    for (unsigned c = 0; c < workers; c++) {
        const struct worker *w = &g_w[c];
        for (uint32_t i = 0; f && i < w->nrows; i++) {
            const struct flow_row *r = &w->rows[i];
            fprintf(f, "%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%" PRIu64 "\n", c, r->flow_idx, r->src, r->dst, r->sport, r->dport, r->cls, r->deferred, r->label,
                    r->nic_ran, r->score_sum, r->n_defer, r->gate_ns, r->nic_ns, r->rx_ns);
        }
    }
    if (f) { fclose(f); printf("wrote %s_flows.csv\n", g_cfg.out); }

    printf("\n=== summary ===\nrx packets %" PRIu64 " (flow packets %" PRIu64 "), bursts %" PRIu64 ", flows completed %" PRIu64 ", deferred %" PRIu64 " (%.1f%%), NIC model runs %" PRIu64
           ", table-full drops %" PRIu64 "\n", npk, flow_pkts, nbursts, comp, def, comp ? 100.0 * (double)def / (double)comp : 0.0, nic, full);
    if (nbursts) {
        uint32_t *v = malloc(nbursts * sizeof(uint32_t));
        uint64_t k = 0;
        for (unsigned c = 0; c < workers; c++) for (uint32_t i = 0; i < g_w[c].nb; i++) v[k++] = g_w[c].bursts[i].proc_ns;
        qsort(v, k, sizeof(uint32_t), cmp_u32);
        printf("burst processing time (ns): p50 %u  p90 %u  p99 %u  p99.9 %u  max %u   (bursts of up to %d packets)\n", v[k / 2], v[k * 9 / 10], v[k * 99 / 100],
               v[k * 999 / 1000], v[k - 1], BURST_SIZE);
        free(v);
    }
    for (unsigned c = 0; c < workers; c++) {
        const struct worker *w = &g_w[c];
        if (w->hw_last_tsc > w->hw_first_tsc && w->hw_last_ts > w->hw_first_ts)
            printf("core %u: hw timestamp unit estimate = %.4f ns/tick (set --ts-ns-per-tick if not 1.0)\n", c,
                   tsc_to_ns(w->hw_last_tsc - w->hw_first_tsc, (double)rte_get_tsc_hz()) / (double)(w->hw_last_ts - w->hw_first_ts));
        if (w->dropped_bursts || w->dropped_rows) printf("WARNING core %u: %u bursts and %u rows dropped (raise --max-bursts / --max-rows)\n", c, w->dropped_bursts, w->dropped_rows);
    }
}

static int parse_app(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--gate") && i + 1 < argc) { i++; g_cfg.gate_mode = !strcmp(argv[i], "votes") ? GATE_VOTES : GATE_SCORE; }
        else if (!strcmp(argv[i], "--ts") && i + 1 < argc) { i++; g_cfg.ts_hw = !strcmp(argv[i], "hw"); }
        else if (!strcmp(argv[i], "--ts-ns-per-tick") && i + 1 < argc) g_cfg.ns_per_tick = atof(argv[++i]);
        else if (!strcmp(argv[i], "--table-bits") && i + 1 < argc) g_cfg.table_bits = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--max-bursts") && i + 1 < argc) g_cfg.max_bursts = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--max-rows") && i + 1 < argc) g_cfg.max_rows = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) g_cfg.port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--out") && i + 1 < argc) g_cfg.out = argv[++i];
        else {
            printf("usage: %s [EAL options] -- [--gate score|votes] [--ts hw|tsc] [--ts-ns-per-tick X] [--table-bits B] [--max-bursts N] [--max-rows N] "
                   "[--port P] [--out PREFIX]\n", argv[0]);
            return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_panic("Cannot init EAL\n");
    argc -= ret; argv += ret;
    if (parse_app(argc, argv)) return 1;
    signal(SIGINT, on_term); signal(SIGTERM, on_term);

    printf("DPDK %s | P4Gate on the NIC | N=%d K=%d | forest %d trees (%d nodes), defer votes >= %d, score threshold %d | GBT %d trees depth %d\n", rte_version(), NPKT, K_CLASSES,
           RF_NTREES, RF_NODES, RF_DEFER_VOTES, RF_THETA_SCORE, GBT_NTREES, GBT_DEPTH);
    unsigned lcores = rte_lcore_count();
    if (rte_eth_dev_count_avail() == 0) rte_exit(EXIT_FAILURE, "no ethernet port available\n");
    struct rte_mempool *pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE, 0, MBUF_DATA_ROOM, rte_socket_id());
    if (!pool) rte_exit(EXIT_FAILURE, "cannot create mbuf pool\n");
    uint16_t port = (uint16_t)g_cfg.port, nq = 0;
    if (port_init(port, pool, (uint16_t)lcores, &nq)) rte_exit(EXIT_FAILURE, "cannot init port %u\n", port);
    unsigned workers = lcores < nq ? lcores : nq;

    for (unsigned c = 0; c < workers; c++) {
        struct worker *w = &g_w[c];
        w->port = port; w->queue = (uint16_t)c;
        w->bursts = rte_zmalloc(NULL, (size_t)g_cfg.max_bursts * sizeof(struct burst_rec), 64);
        w->rows = rte_zmalloc(NULL, (size_t)g_cfg.max_rows * sizeof(struct flow_row), 64);
        w->tab.mask = (1u << g_cfg.table_bits) - 1;
        w->tab.e = rte_zmalloc(NULL, ((size_t)w->tab.mask + 1) * sizeof(struct flow_state), 64);
        if (!w->bursts || !w->rows || !w->tab.e) rte_exit(EXIT_FAILURE, "allocation failed (reduce --table-bits / --max-bursts / --max-rows)\n");
        if (c != rte_get_main_lcore()) rte_eal_remote_launch(lcore_main, w, c);
    }
    if (rte_get_main_lcore() < workers) lcore_main(&g_w[rte_get_main_lcore()]);
    else while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) sleep(1);

    rte_eal_mp_wait_lcore();
    report(workers);
    rte_eth_dev_stop(port); rte_eth_dev_close(port);
    rte_eal_cleanup();
    return 0;
}
