/* -*- P4_16 -*- */
/*************************************************************************
 * P4Gate - merged data plane
 *
 *   ETC_NOMS_2024 : per-flow registers (Akem/Flowrest features), hash
 *                   collision check, classified-flag register, digest.
 *   P4 DGA        : bigram idea = table key -> value, accumulated.
 *                   Here the "bigram" is a pair of consecutive packets,
 *                   each described by (packet-size bin, IAT bin), and the
 *                   value is the log-likelihood ratio of that transition.
 *   SNI project   : TCP/TLS fixed-header parser, RF in the EGRESS, features
 *                   carried in recirc_h + features_h, class_result written
 *                   by the egress and read back in the ingress.
 *
 * Control-plane conventions (nothing in the P4 enforces them):
 *   table_size_bin : range on ipv4.total_len      -> size_bin (4 bit)
 *   table_iat_bin  : range on iat[31:17]          -> iat_bin  (4 bit)
 *                    iat_bin 0 is RESERVED: first packet of a flow (no IAT)
 *   cur_bins/prev_bins = {size_bin, iat_bin}
 *   table_llr      : exact (prev_bins, cur_bins)  -> llr_val
 *                    llr_val = round(S * log(P_a(cur|prev) / P_b(cur|prev)))
 *                    stored as 16-bit two's complement. A miss adds 0.
 *   llr_cumsum     : plain cumulative sum (first packet ignored, packet k>=2
 *                    adds LLR(k-1 -> k)). For a one-sided CUSUM clamp at 0
 *                    inside read_llr_cumsum.
 *   RF feature     : features.llr_cumsum = cumsum + 0x8000 (offset binary) so
 *                    the unsigned range tables order negative sums correctly.
 *************************************************************************/
#include <core.p4>
#include <tna.p4>
/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
const bit<16>       TYPE_IPV4 = 0x800;
const bit<16>       TYPE_RECIRC = 0x88B5;
const bit<8>        TYPE_TCP = 6;
const bit<32>       MAX_REGISTER_ENTRIES = 2048;
#define INDEX_WIDTH 11
#define NUM_LLR_ENTRIES 4096
/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/
/* Standard ethernet header */
header ethernet_h {
    mac_addr_t   dst_addr;
    mac_addr_t   src_addr;
    ether_type_t ether_type;
}
/* IPV4 header */
header ipv4_h {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      total_len;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      frag_offset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdr_checksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
}
/* TCP header (ports split from the rest, as in the SNI project) */
header tcp_ports_h {
    bit<16> src_port;
    bit<16> dst_port;
}
header tcp_h {
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}
/* TLS fixed headers only (no session id, ciphers, compressions, extensions) */
header tls_h {
    bit<8>  type;
    bit<16> version;
    bit<16> len;
}
header tls_handshake_h {
    bit<8> type;
}
header tls_client_hello_h {
    bit<24>  len;
    bit<16>  version;
    bit<256> random;
}
header tls_server_hello_h {
    bit<24> len;
    bit<16> version;
}

/*Custom header for recirculation*/
header recirc_h {
    bit<8>       class_result;
}

/* Features carried to the egress RF (same role as features_h in the SNI project) */
header features_h {
    bit<32> flow_iat_min;
    bit<16> pkt_len_max;
    bit<32> flow_iat_max;
    bit<16> pkt_len_total;
    bit<16> llr_cumsum;     // offset binary: cumsum + 0x8000
    bit<8>  pkt_count;
}

/***********************  H E A D E R S  ************************/
struct my_ingress_headers_t {
    ethernet_h         ethernet;
    recirc_h           recirc;
    features_h         features;
    ipv4_h             ipv4;
    tcp_ports_h        tcp_ports;
    tcp_h              tcp;
    tls_h              tls;
    tls_handshake_h    tls_handshake;
    tls_client_hello_h tls_client_hello;
    tls_server_hello_h tls_server_hello;
}

/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/
struct my_ingress_metadata_t {
    bit<1> is_first;
    bit<8> classified_flag;

    bit<1>  reg_status;
    bit<32> flow_ID;
    bit<(INDEX_WIDTH)> register_index;

    bit<16> hdr_srcport;
    bit<16> hdr_dstport;

    bit<8>  pkt_count;
    bit<32> time_last_pkt;

    bit<32> iat;
    bit<16> pkt_len_max;
    bit<16> pkt_len_total;

    bit<32> flow_iat_max;
    bit<32> flow_iat_min;

    /* LLR cumulative sum over (size bin, IAT bin) transitions */
    bit<8>  cur_bins;       // [7:4] size_bin, [3:0] iat_bin of this packet
    bit<8>  prev_bins;      // same layout, previous packet of the flow
    bit<16> llr_val;        // LLR of the (prev_bins -> cur_bins) transition
    bit<16> llr_cumsum;     // running sum for the flow

    bit<8> final_class;
}

struct flow_class_digest {  // maximum size allowed is 47 bytes

    ipv4_addr_t  source_addr;   // 32 bits
    ipv4_addr_t  destin_addr;   // 32 bits
    bit<16> source_port;
    bit<16> destin_port;
    bit<8> protocol;
    bit<8> class_value;
    bit<8> packet_num;
    bit<(INDEX_WIDTH)> register_index; // To send info to the controller
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }
    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }
    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_RECIRC : parse_recirc;
            TYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    /* Packet coming back from the egress RF: only the 5-tuple is needed */
    state parse_recirc {
       pkt.extract(hdr.recirc);
       transition parse_features;
    }

    state parse_features {
        pkt.extract(hdr.features);
        transition parse_ipv4_recirc;
    }

    state parse_ipv4_recirc {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP:  parse_tcp_ports_recirc;
            default: accept;
        }
    }

    state parse_tcp_ports_recirc {
        pkt.extract(hdr.tcp_ports);
        meta.hdr_dstport = hdr.tcp_ports.dst_port;
        meta.hdr_srcport = hdr.tcp_ports.src_port;
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.final_class=10;
        meta.cur_bins = 0;      // iat_bin stays 0 (reserved) for the first packet
        meta.llr_val = 0;       // a table_llr miss adds 0
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP:  parse_tcp_ports;
            default: accept;
        }
    }

    state parse_tcp_ports {
        pkt.extract(hdr.tcp_ports);
        meta.hdr_dstport = hdr.tcp_ports.dst_port;
        meta.hdr_srcport = hdr.tcp_ports.src_port;
        transition select(hdr.tcp_ports.dst_port) {
            443: parse_tcp;
            default: parse_returning_traffic;
        }
    }

    state parse_returning_traffic {
        transition select(hdr.tcp_ports.src_port) {
            443: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.data_offset) {
            0x05 : parse_tls;
            0x08 : parse_tcp_options_08;
            default: accept;
        }
    }

    state parse_tcp_options_08 {pkt.advance(96);transition parse_tls;}

    state parse_tls {
        pkt.extract(hdr.tls);
        transition select(hdr.tls.type){
            22: parse_tls_handshake;
            default: accept;
        }
    }

    state parse_tls_handshake {
        pkt.extract(hdr.tls_handshake);
        transition select(hdr.tls_handshake.type){
            1: parse_tls_client_hello;
            2: parse_tls_server_hello;
            default: accept;
        }
    }

    state parse_tls_client_hello {
        pkt.extract(hdr.tls_client_hello);
        transition accept;
    }

    state parse_tls_server_hello {
        pkt.extract(hdr.tls_server_hello);
        transition accept;
    }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
/***************** M A T C H - A C T I O N  *********************/
control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    /* Registers for flow management */
    Register<bit<8>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_classified_flag;
    /* Register read action */
    RegisterAction<bit<8>,bit<(INDEX_WIDTH)>,bit<8>>(reg_classified_flag)
    update_classified_flag = {
        void apply(inout bit<8> classified_flag, out bit<8> output) {
            if (hdr.recirc.isValid()){
                classified_flag = hdr.recirc.class_result;
            }
            output = classified_flag;
        }
    };

    Register<bit<1>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_status;
    /* Register read action */
    RegisterAction<bit<1>,bit<(INDEX_WIDTH)>,bit<1>>(reg_status)
    read_reg_status = {
        void apply(inout bit<1> status, out bit<1> output) {
            output = status;
            status = 1;
        }
    };

    Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_flow_ID;
    /* Register read action */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_flow_ID)
    update_flow_ID = {
        void apply(inout bit<32> flow_ID) {
            flow_ID = meta.flow_ID;
        }
    };
    /* Register read action */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_flow_ID)
    read_only_flow_ID = {
        void apply(inout bit<32> flow_ID, out bit<32> output) {
            output = flow_ID;
        }
    };

    Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_time_last_pkt;
    /* Register read action */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_time_last_pkt)
    read_time_last_pkt = {
        void apply(inout bit<32> time_last_pkt, out bit<32> output) {
            output = time_last_pkt;
            time_last_pkt = ig_prsr_md.global_tstamp[31:0];
        }
    };

    //registers for ML inference - features
    Register<bit<8>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_pkt_count;
    /* Register read action */
    RegisterAction<bit<8>,bit<(INDEX_WIDTH)>,bit<8>>(reg_pkt_count)
    read_pkt_count = {
        void apply(inout bit<8> pkt_count, out bit<8> output) {
            pkt_count = pkt_count + 1;
            output = pkt_count;
        }
    };

    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_pkt_len_max;
    /* Register read action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_pkt_len_max)
    read_pkt_len_max = {
        void apply(inout bit<16> pkt_len_max, out bit<16> output) {
            if (meta.is_first == 1){
                pkt_len_max = hdr.ipv4.total_len;
            }
            else if (hdr.ipv4.total_len > pkt_len_max){
                pkt_len_max  = hdr.ipv4.total_len;
            }
            output = pkt_len_max;
        }
    };

    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_pkt_len_total;
    /* Register read action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_pkt_len_total)
    read_pkt_len_total = {
        void apply(inout bit<16> pkt_len_total, out bit<16> output) {
            if (meta.is_first == 1){
                pkt_len_total = hdr.ipv4.total_len;
            }
            else{
                pkt_len_total = pkt_len_total + hdr.ipv4.total_len;
            }
            output = pkt_len_total;
        }
    };

    Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_flow_iat_max;
    /* Register read action */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_flow_iat_max)
    read_flow_iat_max = {
        void apply(inout bit<32> flow_iat_max, out bit<32> output) {
            if (meta.is_first != 1){
                if(meta.iat > flow_iat_max){
                    flow_iat_max = meta.iat;
                }
            }
            output = flow_iat_max;
        }
    };

    Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_flow_iat_min;
    /* Register read action */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_flow_iat_min)
    read_flow_iat_min = {
        void apply(inout bit<32> flow_iat_min, out bit<32> output) {
            if (meta.pkt_count <= 2){
                flow_iat_min = meta.iat;
            }
            else if(meta.iat < flow_iat_min){
                flow_iat_min = meta.iat;
            }
            output = flow_iat_min;
        }
    };

    //registers for the LLR cumulative sum
    Register<bit<8>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_prev_bins;
    /* Register read action: returns previous packet's bins, stores this packet's */
    RegisterAction<bit<8>,bit<(INDEX_WIDTH)>,bit<8>>(reg_prev_bins)
    read_prev_bins = {
        void apply(inout bit<8> prev_bins, out bit<8> output) {
            output = prev_bins;
            prev_bins = meta.cur_bins;
        }
    };

    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_llr_cumsum;
    /* Register read action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_llr_cumsum)
    read_llr_cumsum = {
        void apply(inout bit<16> llr_cumsum, out bit<16> output) {
            if (meta.is_first == 1){
                llr_cumsum = 0;
            }
            else{
                llr_cumsum = llr_cumsum + meta.llr_val;
            }
            output = llr_cumsum;
        }
    };


    /* Declaration of the hashes*/
    Hash<bit<32>>(HashAlgorithm_t.CRC32)              flow_id_calc;
    Hash<bit<(INDEX_WIDTH)>>(HashAlgorithm_t.CRC16)   idx_calc;

    /* Calculate hash of the 5-tuple to represent the flow ID */
    action get_flow_ID(bit<16> srcPort, bit<16> dstPort) {
        meta.flow_ID = flow_id_calc.get({hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,srcPort, dstPort, hdr.ipv4.protocol});
    }
    /* Calculate hash of the 5-tuple to use as 1st register index */
    action get_register_index(bit<16> srcPort, bit<16> dstPort) {
        meta.register_index = idx_calc.get({hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,srcPort, dstPort, hdr.ipv4.protocol});
    }

    /* Compute packet interarrival time (IAT)*/
    action get_iat_value(){
        meta.iat = ig_prsr_md.global_tstamp[31:0] - meta.time_last_pkt;
    }

    /* Forward to a specific port upon classification */
    action ipv4_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    /* Custom Do Nothing Action */
    action nop(){}

    /* Recirculate packet via loopback port 68 */
    action recirculate(bit<7> recirc_port) {
        ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];
        ig_tm_md.ucast_egress_port[6:0] = recirc_port;
        hdr.recirc.setValid();
        hdr.recirc.class_result = meta.final_class;
        hdr.ethernet.ether_type = TYPE_RECIRC;
    }

    /* Carry the flow features to the egress RF */
    action set_features() {
        hdr.features.setValid();
        hdr.features.flow_iat_min   = meta.flow_iat_min;
        hdr.features.pkt_len_max    = meta.pkt_len_max;
        hdr.features.flow_iat_max   = meta.flow_iat_max;
        hdr.features.pkt_len_total  = meta.pkt_len_total;
        hdr.features.llr_cumsum     = meta.llr_cumsum + 16w0x8000;
        hdr.features.pkt_count      = meta.pkt_count;
    }

    /* Bin actions: each table writes its half of cur_bins */
    action SetSizeBin(bit<4> size_bin) {
        meta.cur_bins[7:4] = size_bin;
    }
    action SetIatBin(bit<4> iat_bin) {
        meta.cur_bins[3:0] = iat_bin;
    }

    /* LLR of one (prev -> cur) transition, same role as map_ngram_hdr in P4 DGA */
    action map_llr(bit<16> llr_val) {
        meta.llr_val = llr_val;
    }

    /* Bin tables */
    table table_size_bin{
        key = {hdr.ipv4.total_len: range @name("size_bin");}
        actions = {@defaultonly nop; SetSizeBin;}
        size = 16;
        const default_action = nop();
    }
    table table_iat_bin{
        key = {meta.iat[31:17]: range @name("iat_bin");}
        actions = {@defaultonly nop; SetIatBin;}
        size = 16;
        const default_action = nop();
    }

    /* LLR table: sequence of (size, IAT) of packet A then packet B -> LLR */
    table table_llr {
        key = {
            meta.prev_bins: exact;
            meta.cur_bins: exact;
        }
        actions = {@defaultonly nop; map_llr;}
        size = NUM_LLR_ENTRIES;
        const default_action = nop();
    }

    /* Forwarding-Inference Block Table */
    action set_flow_class(bit<8> f_class) {
        meta.final_class = f_class;
    }
    table target_flows_table {
        key = {
            hdr.ipv4.src_addr: exact;
            hdr.ipv4.dst_addr: exact;
            meta.hdr_srcport: exact;
            meta.hdr_dstport: exact;
            hdr.ipv4.protocol: exact;
        }
        actions = {set_flow_class; @defaultonly drop;}
        size = 500;
        const default_action = drop();
    }

    apply {
        if (hdr.recirc.isValid()) {
            // second pass: the egress RF wrote its verdict in hdr.recirc.class_result
            get_register_index(meta.hdr_srcport, meta.hdr_dstport);

            meta.final_class = hdr.recirc.class_result;
            meta.pkt_count   = hdr.features.pkt_count;

            // remember the class of the flow
            meta.classified_flag = update_classified_flag.execute(meta.register_index);

            // send digest to the controller with the classification result
            ig_dprsr_md.digest_type = 1;

            hdr.recirc.setInvalid();
            hdr.features.setInvalid();
            hdr.ethernet.ether_type = TYPE_IPV4;
            ipv4_forward(260);
        }
        else {
            // filter for background or already classified traffic
            target_flows_table.apply();

            // get flow ID and register index
            bit<32> tmp_flow_ID;
            get_flow_ID(meta.hdr_srcport, meta.hdr_dstport);
            get_register_index(meta.hdr_srcport, meta.hdr_dstport);

            // size bin of this packet (header only, independent of flow state)
            table_size_bin.apply();

            if(meta.final_class==0){ //flow not classified

                // check if register for emptiness
                meta.reg_status = read_reg_status.execute(meta.register_index);

                // check if register array is empty
                if (meta.reg_status == 0){ // we do not yet know this flow
                    meta.is_first = 1;
                    update_flow_ID.execute(meta.register_index);
                    // modify timestamp register
                    meta.time_last_pkt = read_time_last_pkt.execute(meta.register_index);
                    meta.pkt_count     = read_pkt_count.execute(meta.register_index);
                    meta.pkt_len_max   = read_pkt_len_max.execute(meta.register_index);
                    meta.pkt_len_total = read_pkt_len_total.execute(meta.register_index);

                    // first packet: only store its bins, nothing to accumulate yet
                    meta.prev_bins     = read_prev_bins.execute(meta.register_index);
                    meta.llr_cumsum    = read_llr_cumsum.execute(meta.register_index);
                    ipv4_forward(260);
                }
                else { // not the first packet - get flow_ID from register
                    meta.is_first = 0;
                    tmp_flow_ID = read_only_flow_ID.execute(meta.register_index);
                    if(meta.flow_ID != tmp_flow_ID){ // hash collision
                        meta.pkt_count = 0; //hash col
                        // send digest to inform controller of the collision
                        ig_dprsr_md.digest_type = 1;
                        ipv4_forward(260);
                    }
                    else { // not first packet and not hash collision
                        //read and update packet count
                        meta.pkt_count     = read_pkt_count.execute(meta.register_index);

                        // read and update packet length features
                        meta.pkt_len_max   = read_pkt_len_max.execute(meta.register_index);
                        meta.pkt_len_total = read_pkt_len_total.execute(meta.register_index);

                        // modify timestamp register
                        meta.time_last_pkt = read_time_last_pkt.execute(meta.register_index);

                        // compute IAT value
                        get_iat_value();

                        //read and update IAT features
                        meta.flow_iat_max   =  read_flow_iat_max.execute(meta.register_index);
                        meta.flow_iat_min   =  read_flow_iat_min.execute(meta.register_index);

                        // LLR cumulative sum: bin IAT, fetch previous bins, look up the transition, accumulate
                        table_iat_bin.apply();
                        meta.prev_bins      = read_prev_bins.execute(meta.register_index);
                        table_llr.apply();
                        meta.llr_cumsum     = read_llr_cumsum.execute(meta.register_index);

                        // check if # of packets requirement is met
                        if(meta.pkt_count == 8){
                            // hand the features to the RF in the egress, verdict comes back via recirculation
                            set_features();
                            recirculate(68);
                        }
                        else{ // this happens to first  packets and packet number 9 onwards
                            meta.classified_flag = update_classified_flag.execute(meta.register_index);

                            if (meta.classified_flag != 0) {//No need to check again - already classified
                                //set value of ttl to classification result (stats only)
                                hdr.ipv4.ttl = meta.classified_flag;
                            }
                            ipv4_forward(260);
                        } //END OF CHECK FOR PREVIOUS CLASSIFICATION
                    } //END OF CHECK ON IF NO COLLISION
                } // END OF CHECK ON WHETHER FIRST CLASS
            }
            else {
                ipv4_forward(260);
            }
        }
    } //END OF APPLY
} //END OF INGRESS CONTROL

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Digest<flow_class_digest>() digest;

    apply {

        if (ig_dprsr_md.digest_type == 1) {
            // Pack digest and send to controller
            digest.pack({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, meta.hdr_srcport, meta.hdr_dstport, hdr.ipv4.protocol, meta.final_class, meta.pkt_count, meta.register_index});
        }

        /* we do not update checksum because we used ttl field for stats*/
        pkt.emit(hdr);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
struct my_egress_headers_t {
    ethernet_h   ethernet;
    recirc_h     recirc;
    features_h   features;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {

    bit<8> class0;
    bit<8> class1;
    bit<8> class2;
    bit<8> class3;
    bit<8> class4;

    /* features 0-3 keep the ETC_NOMS_2024 widths, the top 8 bits of each
       codeword are the LLR feature (feature 4). PLACEHOLDER widths: regenerate
       with the RF-to-P4 compiler after retraining the forest with the LLR feature */
    bit<210> codeword0;
    bit<228> codeword1;
    bit<213> codeword2;
    bit<229> codeword3;
    bit<212> codeword4;
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
   /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_RECIRC: parse_recirc;
            default: accept;
        }
    }

    state parse_recirc{
        pkt.extract(hdr.recirc);
        transition parse_features;
    }

    state parse_features{
        pkt.extract(hdr.features);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    /* Assign class if at leaf node */
    action SetClass0(bit<8> classe) {
        meta.class0 = classe;
    }
    action SetClass1(bit<8> classe) {
        meta.class1 = classe;
    }
    action SetClass2(bit<8> classe) {
        meta.class2 = classe;
    }
    action SetClass3(bit<8> classe) {
        meta.class3 = classe;
    }
    action SetClass4(bit<8> classe) {
        meta.class4 = classe;
    }

    /* Custom Do Nothing Action */
    action nop(){}

    /* Feature table actions */
    action SetCode0(bit<29> code0, bit<30> code1, bit<23> code2, bit<31> code3, bit<28> code4) {
        meta.codeword0[201:173] = code0;
        meta.codeword1[219:190] = code1;
        meta.codeword2[204:182] = code2;
        meta.codeword3[220:190] = code3;
        meta.codeword4[203:176] = code4;
    }
    action SetCode1(bit<53> code0, bit<64> code1, bit<63> code2, bit<60> code3, bit<42> code4) {
        meta.codeword0[172:120] = code0;
        meta.codeword1[189:126] = code1;
        meta.codeword2[181:119] = code2;
        meta.codeword3[189:130] = code3;
        meta.codeword4[175:134] = code4;
    }
    action SetCode2(bit<57> code0, bit<48> code1, bit<60> code2, bit<54> code3, bit<52> code4) {
        meta.codeword0[119:63] = code0;
        meta.codeword1[125:78] = code1;
        meta.codeword2[118:59] = code2;
        meta.codeword3[129:76] = code3;
        meta.codeword4[133:82] = code4;
    }
    action SetCode3(bit<63> code0, bit<78> code1, bit<59> code2, bit<76> code3, bit<82> code4) {
        meta.codeword0[62:0]  = code0;
        meta.codeword1[77:0]  = code1;
        meta.codeword2[58:0]  = code2;
        meta.codeword3[75:0]  = code3;
        meta.codeword4[81:0]  = code4;
    }
    /* LLR feature, 8 bits per tree is a PLACEHOLDER */
    action SetCode4(bit<8> code0, bit<8> code1, bit<8> code2, bit<8> code3, bit<8> code4) {
        meta.codeword0[209:202] = code0;
        meta.codeword1[227:220] = code1;
        meta.codeword2[212:205] = code2;
        meta.codeword3[228:221] = code3;
        meta.codeword4[211:204] = code4;
    }

    /* Feature tables */
    table table_feature0{
        key = {hdr.features.flow_iat_min[31:17]: range @name("feature0");}
        actions = {@defaultonly nop; SetCode0;}
        size = 64;
        const default_action = nop();
    }
    table table_feature1{
        key = {hdr.features.pkt_len_max: range @name("feature1");}
        actions = {@defaultonly nop; SetCode1;}
        size = 160;
        const default_action = nop();
    }
    table table_feature2{
        key = {hdr.features.flow_iat_max[31:24]: range @name("feature2");}
        actions = {@defaultonly nop; SetCode2;}
        size = 112;
        const default_action = nop();
    }
    table table_feature3{
        key = {hdr.features.pkt_len_total: range @name("feature3");}
        actions = {@defaultonly nop; SetCode3;}
        size = 244;
        const default_action = nop();
    }
    table table_feature4{
        key = {hdr.features.llr_cumsum: range @name("feature4");}
        actions = {@defaultonly nop; SetCode4;}
        size = 64;
        const default_action = nop();
    }

    /* Code tables */
    table code_table0{
        key = {meta.codeword0: ternary;}
        actions = {@defaultonly nop; SetClass0;}
        size = 203;
        const default_action = nop();
    }
    table code_table1{
        key = {meta.codeword1: ternary;}
        actions = {@defaultonly nop; SetClass1;}
        size = 221;
        const default_action = nop();
    }
    table code_table2{
        key = {meta.codeword2: ternary;}
        actions = {@defaultonly nop; SetClass2;}
        size = 206;
        const default_action = nop();
    }
    table code_table3{
        key = {meta.codeword3: ternary;}
        actions = {@defaultonly nop; SetClass3;}
        size = 222;
        const default_action = nop();
    }
    table code_table4{
        key = {meta.codeword4: ternary;}
        actions = {@defaultonly nop; SetClass4;}
        size = 205;
        const default_action = nop();
    }

    action set_default_result() {
        hdr.recirc.class_result = 0;
    }

    action set_final_class(bit<8> class_result) {
        hdr.recirc.class_result = class_result;
    }

    table voting_table {
        key = {
            meta.class0: exact;
            meta.class1: exact;
            meta.class2: exact;
            meta.class3: exact;
            meta.class4: exact;
        }
        actions = {set_final_class; @defaultonly set_default_result;}
        size = 5256;
        const default_action = set_default_result();
    }

    apply {
        if(hdr.features.isValid()){
            // apply feature tables to assign codes
            table_feature0.apply();
            table_feature1.apply();
            table_feature2.apply();
            table_feature3.apply();
            table_feature4.apply();

            // apply code tables to assign labels
            code_table0.apply();
            code_table1.apply();
            code_table2.apply();
            code_table3.apply();
            code_table4.apply();

            // decide final class
            voting_table.apply();
        }
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;