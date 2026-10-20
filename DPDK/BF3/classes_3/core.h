/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * p4gate/core.h - drop-in replacement of nic/core.h for the WORKING P4Gate program (spec "p4gate v0"), same names, so main.c compiles unchanged:
 *
 *     cc -I p4gate -I <out>/nic ... main.c         (see Makefile.p4gate)
 *
 * What the switch holds per flow (pipeline/p4gate.py is the Python twin; scripts/gen_p4gate_online.py writes the headers included below):
 *   pkt_len_max, pkt_len_total (16 bit, wraps), flow_iat_min / flow_iat_max (32 bit ns, IAT = low 32 bits of the timestamp difference, wraps at 4.29 s),
 *   one 16-bit LLR accumulator per class (offset binary +0x8000 as exported), pkt_count.
 * The STATE record carries exactly these values; the SmartNIC model reads [len_max, len_total, iat_min, iat_max, llr_0 .. llr_K-1] as float32.
 *
 *   RECORD path   STATE frame (EtherType 0x88B6) -> features -> gradient-boosted trees -> RESULT in place, MACs swapped.
 *   RAW path      IPv4 packets -> per-flow registers updated like the P4 ingress -> at packet NPKT the same record -> classify.   (NIC-only baseline)
 */
#ifndef SWNIC_CORE_H
#define SWNIC_CORE_H
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "p4gate_consts.h"   /* generated: K_CLASSES NPKT N_FEAT DEFER_VOTES, size / IAT range tables, CLASS_NAMES */
#include "p4gate_llr.h"      /* generated: LLR_P4[prev_bins][cur_bins][8] int16 (a missing pair is 0) */
#include "gbt_model.h"       /* generated: GBT_* arrays (XGBoost trees, flattened) */

#ifndef WPKT
#define WPKT NPKT            /* one window only: the switch decides and exports at the same packet */
#endif
#ifndef THETA
#define THETA 254            /* main.c "--defer-only" emulates a software switch; here every flow counts as deferred (NIC-only baseline) */
#endif

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BE16(x) (x)
#define BE32(x) (x)
#else
#define BE16(x) __builtin_bswap16(x)
#define BE32(x) __builtin_bswap32(x)
#endif

#define ETH_P_SWREC    0x88B6u
#define SWREC_VER      0x10
#define SWREC_STATE    1
#define SWREC_RESULT   2
#define SWREC_KMAX     8
#define SWNIC_VEC_LEN  N_FEAT

#pragma pack(push, 1)
struct swrec {                /* 44 B after the 14 B Ethernet header; mirrors nic/p4/p4gate_rec_headers.p4 */
    uint8_t  ver;             /*  0 */
    uint8_t  kind;            /*  1  SWREC_STATE / SWREC_RESULT */
    uint16_t flow_idx;        /*  2  register index of the flow on the switch */
    uint8_t  pkt_count;       /*  4 */
    uint8_t  sw_class;        /*  5  class the switch forest gave (informational) */
    uint8_t  sw_votes;        /*  6  confidence the switch used: DEFER score sum / 8 or agreement count (informational) */
    uint8_t  pad;             /*  7 */
    uint16_t len_max;         /*  8 */
    uint16_t len_total;       /* 10  16-bit register (wraps) */
    uint32_t iat_min;         /* 12  ns, low 32 bits */
    uint32_t iat_max;         /* 16 */
    uint16_t llr[SWREC_KMAX]; /* 20  offset binary (+0x8000) accumulators, unused slots 0 */
    uint8_t  label;           /* 36  result */
    uint8_t  flags;           /* 37  bit0: model ran, bit1: record rejected */
    uint16_t score;           /* 38  result: probability of label, Q16 */
    uint32_t nic_ns;          /* 40  result: SmartNIC residence time, ns */
};
#pragma pack(pop)
#define SWREC_ETH_LEN   14
#define SWREC_FRAME_LEN (SWREC_ETH_LEN + (int)sizeof(struct swrec))
_Static_assert(sizeof(struct swrec) == 44, "swrec must be 44 bytes");

/* ---- record path ---- */
static inline void rec_features(const struct swrec *r, float *x)
{
    x[0] = (float)BE16(r->len_max);
    x[1] = (float)BE16(r->len_total);
    x[2] = (float)BE32(r->iat_min);
    x[3] = (float)BE32(r->iat_max);
    for (int k = 0; k < K_CLASSES; k++) x[4 + k] = (float)BE16(r->llr[k]);
}

static inline int gbt_predict(const float *x, float *margin /* GBT_NCLASS, optional */)
{
    float m[GBT_NCLASS];
    for (int c = 0; c < GBT_NCLASS; c++) m[c] = GBT_BASE[c];
    for (int t = 0; t < GBT_NTREES; t++) {
        uint32_t n = GBT_ROOT[t];
        for (int d = 0; d < GBT_DEPTH; d++) {
            const struct gbt_node *nd = &GBT_NODES[n];
            n = nd->child + (uint32_t)(x[nd->feat] >= nd->thr);      /* x < thr -> left (child), else right (child + 1) */
        }
        m[GBT_TREE_CLASS[t]] += GBT_NODES[n].leaf;
    }
    int best = 0;
    for (int c = 1; c < GBT_NCLASS; c++) if (m[c] > m[best]) best = c;
    if (margin) for (int c = 0; c < GBT_NCLASS; c++) margin[c] = m[c];
    return best;
}

static inline uint16_t gbt_score_q16(const float *margin, int best)
{
    float s = 0.f;
    for (int c = 0; c < GBT_NCLASS; c++) s += expf(margin[c] - margin[best]);
    int q = (int)((1.f / s) * 65535.f + 0.5f);
    return (uint16_t)(q > 65535 ? 65535 : q);
}

static inline int swnic_classify_record(struct swrec *r)
{
    if (r->ver != SWREC_VER || r->kind != SWREC_STATE) { r->flags = 2; return -1; }
    float x[N_FEAT], margin[GBT_NCLASS];
    rec_features(r, x);
    int c = gbt_predict(x, margin);
    r->label = (uint8_t)GBT_CLASS_MAP[c];
    r->score = BE16(gbt_score_q16(margin, c));
    r->flags = 1;
    r->kind = SWREC_RESULT;
    return r->label;
}

static inline int swnic_handle_frame(uint8_t *frame, uint32_t len, int *label)
{
    if (len < (uint32_t)SWREC_FRAME_LEN) return 0;
    uint16_t et = (uint16_t)((frame[12] << 8) | frame[13]);
    if (et != ETH_P_SWREC) return 0;
    struct swrec *r = (struct swrec *)(frame + SWREC_ETH_LEN);
    int c = swnic_classify_record(r);
    uint8_t tmp[6];
    memcpy(tmp, frame, 6); memcpy(frame, frame + 6, 6); memcpy(frame + 6, tmp, 6);
    if (c < 0) return -1;
    *label = c;
    return 1;
}

/* ---- raw path: the registers of the P4 ingress, one flow at a time ---- */
struct flow_state {
    uint32_t src, dst;
    uint16_t sport, dport;
    uint8_t  proto, used, done, cnt;     /* cnt: pkt_count register (8 bit) */
    uint8_t  prev_bins, status, pad[2];
    uint32_t last_ts;                    /* reg_time_last_pkt: low 32 bits of the timestamp, ns */
    uint16_t len_max, len_total;
    uint32_t iat_min, iat_max;
    uint16_t cum[SWREC_KMAX];            /* llr_cumsum registers, 16 bit */
    uint32_t idx;                        /* arrival order of the flow (informational) */
};

static inline unsigned range_bin(const uint32_t *lo, const uint32_t *hi, const uint8_t *bin, int n, uint32_t v)
{
    for (int i = 0; i < n; i++) if (v >= lo[i] && v <= hi[i]) return bin[i];
    return 0;                            /* default nop: the bin stays 0 */
}

static inline void flow_reset(struct flow_state *f) { memset(f, 0, sizeof(*f)); }

/* One packet of a flow (same order of operations as Sim.packet in pipeline/p4gate.py).  Returns 1 at packet NPKT. */
static inline int flow_update(struct flow_state *f, uint32_t iplen, uint64_t ts_ns)
{
    if (f->done) return 0;
    const uint32_t ts32 = (uint32_t)ts_ns;
    const uint16_t l16 = (uint16_t)iplen;
    unsigned cur = range_bin(SIZE_LO, SIZE_HI, SIZE_BIN, N_SIZE_RANGES, iplen) << 4;
    if (!f->status) {                                         /* first packet: store, nothing to accumulate */
        f->status = 1; f->last_ts = ts32; f->cnt = 1;
        f->len_max = l16; f->len_total = l16; f->prev_bins = (uint8_t)cur;
        f->iat_min = f->iat_max = 0;
        memset(f->cum, 0, sizeof(f->cum));
        return 0;
    }
    f->cnt++;
    if (l16 > f->len_max) f->len_max = l16;
    f->len_total = (uint16_t)(f->len_total + l16);
    const uint32_t iat = ts32 - f->last_ts;                   /* mod 2^32 */
    f->last_ts = ts32;
    if (iat > f->iat_max) f->iat_max = iat;
    f->iat_min = (f->cnt <= 2 || iat < f->iat_min) ? iat : f->iat_min;
    cur |= range_bin(IAT_LO, IAT_HI, IAT_BIN, N_IAT_RANGES, iat >> 17);
    const unsigned prev = f->prev_bins;
    f->prev_bins = (uint8_t)cur;
    for (int k = 0; k < K_CLASSES; k++) f->cum[k] = (uint16_t)(f->cum[k] + (uint16_t)LLR_P4[prev][cur][k]);
    if (f->cnt == NPKT) { f->done = 1; return 1; }
    return 0;
}

static inline void flow_export(const struct flow_state *f, uint16_t flow_idx, struct swrec *r)
{
    memset(r, 0, sizeof(*r));
    r->ver = SWREC_VER; r->kind = SWREC_STATE; r->flow_idx = BE16(flow_idx);
    r->pkt_count = f->cnt;
    r->len_max = BE16(f->len_max); r->len_total = BE16(f->len_total);
    r->iat_min = BE32(f->iat_min); r->iat_max = BE32(f->iat_max);
    for (int k = 0; k < K_CLASSES; k++) r->llr[k] = BE16((uint16_t)(f->cum[k] + 0x8000u));
}

/* ---- IPv4 parsing + flow table (raw path), as nic/core.h ---- */
struct pkt_info { uint32_t src, dst, iplen; uint16_t sport, dport; uint8_t proto; };

static inline int parse_ipv4(const uint8_t *f, uint32_t len, struct pkt_info *p)
{
    if (len < 14 + 20 + 4) return 0;
    if (((f[12] << 8) | f[13]) != 0x0800) return 0;
    const uint8_t *ip = f + 14;
    if ((ip[0] >> 4) != 4) return 0;
    uint32_t ihl = (uint32_t)(ip[0] & 0x0F) * 4;
    if (ihl < 20 || len < 14 + ihl + 4) return 0;
    uint8_t proto = ip[9];
    if (proto != 6) return 0;                                 /* the program parses TCP ports only */
    p->iplen = (uint32_t)((ip[2] << 8) | ip[3]);
    p->src = (uint32_t)(ip[12] << 24 | ip[13] << 16 | ip[14] << 8 | ip[15]);
    p->dst = (uint32_t)(ip[16] << 24 | ip[17] << 16 | ip[18] << 8 | ip[19]);
    p->proto = proto;
    p->sport = (uint16_t)((ip[ihl] << 8) | ip[ihl + 1]);
    p->dport = (uint16_t)((ip[ihl + 2] << 8) | ip[ihl + 3]);
    return 1;
}

static inline uint64_t flow_hash(const struct pkt_info *p)
{
    uint64_t h = ((uint64_t)p->src << 32 | p->dst) * 0x9E3779B97F4A7C15ull;
    h ^= ((uint64_t)p->sport << 24 | (uint64_t)p->dport << 8 | p->proto) * 0xC2B2AE3D27D4EB4Full;
    h ^= h >> 29; h *= 0xBF58476D1CE4E5B9ull; h ^= h >> 32;
    return h;
}

struct flow_table {
    struct flow_state *e;
    uint32_t mask, count, full_drops;
};

static inline struct flow_state *flow_lookup(struct flow_table *t, const struct pkt_info *p)
{
    uint32_t i = (uint32_t)flow_hash(p) & t->mask;
    for (uint32_t probe = 0; probe <= t->mask && probe < 64; probe++, i = (i + 1) & t->mask) {
        struct flow_state *f = &t->e[i];
        if (!f->used) {
            flow_reset(f);
            f->used = 1; f->src = p->src; f->dst = p->dst; f->sport = p->sport; f->dport = p->dport; f->proto = p->proto;
            f->idx = t->count++;
            return f;
        }
        if (f->src == p->src && f->dst == p->dst && f->sport == p->sport && f->dport == p->dport && f->proto == p->proto) return f;
    }
    t->full_drops++;
    return NULL;
}

static inline int swnic_handle_raw(struct flow_table *t, const uint8_t *frame, uint32_t len, uint64_t ts_ns, struct swrec *rec, struct flow_state **fs)
{
    struct pkt_info p;
    if (!parse_ipv4(frame, len, &p)) return 0;
    struct flow_state *f = flow_lookup(t, &p);
    if (!f) return 0;
    if (flow_update(f, p.iplen, ts_ns)) {
        flow_export(f, (uint16_t)f->idx, rec);
        rec->sw_votes = 0;                                    /* THETA = 255: every completed flow is classified (NIC-only baseline) */
        if (fs) *fs = f;
        return 1;
    }
    return 0;
}
#endif
