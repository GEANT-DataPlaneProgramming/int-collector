#define KBUILD_MODNAME "xdp_collector"
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

#define ETHTYPE_IP 0x0800

// #define IPPROTO_UDP 17
// #define IPPROTO_TCP 6

// get from cflags
// detail: https://stackoverflow.com/questions/25254043/is-it-
// possible-to-compare-ifdef-values-for-conditional-use
#define INT_DST_PORT _INT_DST_PORT
#define MAX_INT_HOP _MAX_INT_HOP

#define TO_EGRESS 0
#define TO_INGRESS 1
#define BROADCAST_MAC 0xFFFFFFFFFFFF
#define NULL32 0xFFFFFFFF
#define NULL16 0xFFFF

// __packed__ size
#define ETH_SIZE 14
#define IPHDR_SIZE 20
#define TCPHDR_SIZE 20
#define UDPHDR_SIZE 8
#define INT_SHIM_SIZE 4
#define INT_TAIL_SIZE 4

// TODO: set these values from use space
#define HOP_LATENCY _HOP_LATENCY
#define FLOW_LATENCY _FLOW_LATENCY
#define QUEUE_OCCUP _QUEUE_OCCUP
#define QUEUE_CONGEST _QUEUE_CONGEST
#define TX_UTILIZE _TX_UTILIZE
#define TIME_GAP_W _TIME_GAP_W //ns
#define WRAPPED 1

#define CURSOR_ADVANCE(_target, _cursor, _len,_data_end) \
    ({  _target = _cursor; _cursor += _len; \
        if(unlikely(_cursor > _data_end)) return XDP_DROP; })

#define CURSOR_ADVANCE_NO_PARSE(_cursor, _len, _data_end) \
    ({  _cursor += _len; \
        if(unlikely(_cursor > _data_end)) return XDP_DROP; })


#define ABS(a, b) ((a>b)? (a-b):(b-a))
//--------------------------------------------------------------------
// Protocols
    struct ports_t {
    u16 source;
    u16 dest;
} __attribute__((packed));

struct eth_tp {
    u64 dst:48;
    u64 src:48;
    u16 type;
} __attribute__((packed));

struct telemetry_report_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    u8  ver:4,
        nProto:4;
    u8  d:1,
        q:1,
        f:1,
        rsvd1:5;
    u16 rsvd2:10,
        hw_id:6;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    u8  nProto:4,
        ver:4;
    u8  rsvd1:5,
        f:1,
        q:1,
        d:1;
    u16 hw_id:6,
        rsvd2:10;
#else
#error  "Please fix <asm/byteorder.h>"
#endif

    u32 seqNumber;
    u32 ingressTimestamp;
} __attribute__((packed));

struct telemetry_report_v10_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    u8  ver:4,
        len:4;
    u16 nProto:3,
        repMdBits:6,
        reserved:6,
        d:1;
    u8  q:1,
        f:1,
        hw_id:6;
    u32 sw_id;
    u32 seqNumber;
    u32 ingressTimestamp;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    u8  len:4,
        ver:4;
    u16 d:1,
        reserved:6,
        repMdBits:6,
        nProto:3;
    u8  hw_id:6,
        f:1,
        q:1;
    u32 sw_id;
    u32 seqNumber;
    u32 ingressTimestamp;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    // u32 sw_id;
    // u32 seqNumber;
    // u32 ingressTimestamp;
} __attribute__((packed));

struct INT_shim_t {
    u8 type;
    u8 shimRsvd1;
    u8 length;
    u8 shimRsvd2;
} __attribute__((packed));


struct INT_shim_v10_t {
    u8 type;
    u8 shimRsvd1;
    u8 length;

#if defined(__BIG_ENDIAN_BITFIELD)
    u8  DSCP:6,
        r:2;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    u8  r:2,
        DSCP:6;
#else
#error  "Please fix <asm/byteorder.h>"
#endif

} __attribute__((packed));

struct INT_md_fix_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    u8  ver:4,
        rep:2,
        c:1,
        e:1;
    u8  rsvd1:3,
        insCnt:5;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    u8  e:1,
        c:1,
        rep:2,
        ver:4;
    u8  insCnt:5,
        rsvd1:3;
#else
#error  "Please fix <asm/byteorder.h>"
#endif

    u8 maxHopCnt;
    u8 totalHopCnt;
    u16 ins;
    u16 rsvd2;
} __attribute__((packed));

struct INT_md_fix_v10_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    u8  ver:4,
        rep:2,
        c:1,
        e:1;
    u8  m:1,
        rsvd_1:7;
    u8  rsvd_2:3,
        hopMlen:5,
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    u8  e:1,
        c:1,
        rep:2,
        ver:4;
    u8  rsvd_1:7,
        m:1;
    u8  hopMlen:5,
        rsvd_2:3;

#else
#error  "Please fix <asm/byteorder.h>"
#endif

    u8  remainHopCnt:8;
    u16 ins;
    u16 rsvd2;
} __attribute__((packed));

struct INT_tail_t {
    u8 nextProto;
    u16 destPort;
    u8 originDSCP;
} __attribute__((packed));


// Data

struct stat_t {
    u64 pkt_cnt;
    u64 len_cnt;
};

struct flow_id_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u16 ip_proto;
};

struct ingr_id_t {
    u32 sw_id;
    u16 in_p_id;
};

struct ingr_info_t {
    u32 ingr_time;
};

struct egr_id_t {
    u32 sw_id;
    u16 p_id;
};

struct egr_info_t {
    u32 tx_utilize;
    u32 egr_time;
};

struct queue_id_t {
    u32 sw_id;
    u8 q_id;
};

struct queue_info_t {
    u16 occup;
    // u16 congest;
    u32 q_time;
};


// Events

struct flow_info_t {
    // flow
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u16 ip_proto;

    // u64 pkt_cnt;
    // u64 byte_cnt;

    u8 num_INT_hop;

    u32 sw_ids[MAX_INT_HOP];
    u16 in_port_ids[MAX_INT_HOP];
    u16 e_port_ids[MAX_INT_HOP];
    u32 hop_latencies[MAX_INT_HOP];
    u16 queue_ids[MAX_INT_HOP];
    u16 queue_occups[MAX_INT_HOP];
    u64 ingr_times[MAX_INT_HOP];
    u64 egr_times[MAX_INT_HOP];
    // u16 queue_congests[MAX_INT_HOP];
    u32 lv2_in_e_port_ids[MAX_INT_HOP];
    u32 tx_utilizes[MAX_INT_HOP];

    u32 flow_latency;
    u32 flow_sink_time;

    u8 is_n_flow;

// #ifdef USE_INFLUXDB
    u8 is_flow;
// #endif

    u8 is_hop_latency;
    u8 is_queue_occup;
    u8 is_tx_utilize;
    u32 seq_num;
    u32 switchID;
};

BPF_PERF_OUTPUT(events);

BPF_TABLE("lru_hash", struct flow_id_t, struct flow_info_t, tb_flow, 100000);
// nothing to store in tb_ingr yet
// BPF_TABLE("hash", struct ingr_id_t, struct ingr_info_t, tb_ingr, 256);
BPF_TABLE("lru_hash", struct egr_id_t, struct egr_info_t, tb_egr, 3000);
BPF_TABLE("lru_hash", struct queue_id_t, struct queue_info_t, tb_queue, 3000);
// BPF_TABLE("hash", u32, struct flow_info_t, tb_test, 256);


//--------------------------------------------------------------------

int collector(struct xdp_md *ctx) {

    // bpf_trace_printk("recv pkt! \n");

    // return XDP_DROP;

    void* data_end = (void*)(long)ctx->data_end;
    void* cursor = (void*)(long)ctx->data;

    /*
        Parse outer: Ether->IP->UDP
    */

   //ETHERNET
    struct eth_tp *eth;
    CURSOR_ADVANCE(eth, cursor, sizeof(*eth), data_end);

    if (unlikely(ntohs(eth->type) != ETHTYPE_IP))
        return XDP_PASS;
    //IPv4
    struct iphdr *ip;
    CURSOR_ADVANCE(ip, cursor, sizeof(*ip), data_end);

    if (unlikely(ip->protocol != IPPROTO_UDP))
        return XDP_PASS;
    //UDP
    struct udphdr *udp;
    CURSOR_ADVANCE(udp, cursor, sizeof(*udp), data_end);

    struct ports_t *in_ports;
    CURSOR_ADVANCE(in_ports, cursor, sizeof(*in_ports), data_end);

    if (unlikely(ntohs(in_ports->dest) != INT_DST_PORT))
        return XDP_PASS;

    u8 remain_size = (ip->protocol == IPPROTO_UDP)?
                    (UDPHDR_SIZE - sizeof(*in_ports)) :
                    (TCPHDR_SIZE - sizeof(*in_ports));
    // u8 remain_size = UDPHDR_SIZE - sizeof(*in_ports);
    CURSOR_ADVANCE_NO_PARSE(cursor, remain_size, data_end);

    /*
    Parse inner: Etherent->IP->UDP->INT_TELE->SHIM
    */
    CURSOR_ADVANCE_NO_PARSE(cursor, ETH_SIZE, data_end);
    CURSOR_ADVANCE_NO_PARSE(cursor, IPHDR_SIZE, data_end);
    CURSOR_ADVANCE_NO_PARSE(cursor, UDPHDR_SIZE, data_end);

    struct telemetry_report_v10_t *tm_rp;
    CURSOR_ADVANCE(tm_rp, cursor, sizeof(*tm_rp), data_end);

    CURSOR_ADVANCE_NO_PARSE(cursor, INT_SHIM_SIZE, data_end);

    struct INT_shim_v10_t *INT_shim;
    CURSOR_ADVANCE(INT_shim, cursor, sizeof(*INT_shim), data_end);

    // struct INT_md_fix_t *INT_md_fix;
    struct INT_md_fix_v10_t *INT_md_fix;
    CURSOR_ADVANCE(INT_md_fix, cursor, sizeof(*INT_md_fix), data_end);


    /*
        Parse INT data
    */

    u8 INT_data_len = INT_shim->length - 3; // 3 is sizeof INT shim and md fix headers in words
    // should use this but is it slower?
    // u8 num_INT_hop = INT_data_len/INT_md_fix->hopMlen;
    u8 num_INT_hop = 6; // max
    if((u8)(INT_md_fix->hopMlen << 2) + INT_md_fix->hopMlen == INT_data_len)      num_INT_hop = 5;
    else if((u8)(INT_md_fix->hopMlen << 2) == INT_data_len)                       num_INT_hop = 4;
    else if((u8)(INT_md_fix->hopMlen << 1) + INT_md_fix->hopMlen == INT_data_len) num_INT_hop = 3;
    else if((u8)(INT_md_fix->hopMlen << 1) == INT_data_len)                       num_INT_hop = 2;
    else if(INT_md_fix->hopMlen == INT_data_len)                                  num_INT_hop = 1;
    else if(0 == INT_data_len)                                                    num_INT_hop = 0;

    struct flow_info_t flow_info = {
        .src_ip = ntohl(ip->saddr),
        .dst_ip = ntohl(ip->daddr),
        .src_port = ntohs(in_ports->source),
        .dst_port = ntohs(in_ports->dest),
        .ip_proto = ip->protocol,

        .num_INT_hop = num_INT_hop,
        // .flow_sink_time = ntohl(tm_rp->ingressTimestamp),
        // .seq_num = ntohl(tm_rp->seqNumber),
        // .switchID = ntohl(tm_rp->sw_id)
    };

    u16 INT_ins = ntohs(INT_md_fix->ins);
    // Assume that sw_id is alway presented.
    if ((INT_ins >> 15) & 0x01 != 1) return XDP_DROP;

    u8 is_in_e_port_ids  = (INT_ins >> 14) & 0x1;
    u8 is_hop_latencies  = (INT_ins >> 13) & 0x1;
    u8 is_queue_occups 	 = (INT_ins >> 12) & 0x1;
    u8 is_ingr_times 	 = (INT_ins >> 11) & 0x1;
    u8 is_egr_times 	 = (INT_ins >> 10) & 0x1;
    u8 is_lv2_in_e_port_ids = (INT_ins >> 9) & 0x1;
    u8 is_tx_utilizes 	 = (INT_ins >> 8) & 0x1;

    u32* INT_data;
    u64* TIMESTAMPS_data;
    u8 _num_INT_hop = num_INT_hop;
    #pragma unroll
    for (u8 i = 0; i < MAX_INT_HOP; i++) {
        CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
        flow_info.sw_ids[i] = ntohl(*INT_data);

        if (is_in_e_port_ids) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            flow_info.in_port_ids[i] = (ntohl(*INT_data) >> 16) & 0xffff;
            flow_info.e_port_ids[i] = ntohl(*INT_data) & 0xffff;
        }
        if (is_hop_latencies) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            flow_info.hop_latencies[i] = ntohl(*INT_data);
            flow_info.flow_latency += flow_info.hop_latencies[i];
        }
        if (is_queue_occups) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            flow_info.queue_ids[i] = (ntohl(*INT_data) >> 24) & 0xffff;
            flow_info.queue_occups[i] = ntohl(*INT_data) & 0xffff;
        }
        if (is_ingr_times) {
            CURSOR_ADVANCE(TIMESTAMPS_data, cursor, sizeof(*TIMESTAMPS_data), data_end);
            flow_info.ingr_times[i] = ntohl(*INT_data);
        }
        if (is_egr_times) {
            CURSOR_ADVANCE(TIMESTAMPS_data, cursor, sizeof(*TIMESTAMPS_data), data_end);
            flow_info.egr_times[i] = ntohl(*INT_data);
        }
        if (is_lv2_in_e_port_ids) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            flow_info.lv2_in_e_port_ids[i] = ntohl(*INT_data);
        }
        if (is_tx_utilizes) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            flow_info.tx_utilizes[i] = ntohl(*INT_data);
        }

        // no need for the final round
        if (i < MAX_INT_HOP - 1) {
            _num_INT_hop--;
            if (_num_INT_hop <= 0)
                break;
        }
    }


    // parse INT tail
    // struct INT_tail_t *INT_tail;
    // CURSOR_ADVANCE_NO_PARSE(cursor, INT_TAIL_SIZE, data_end);

    /*
        Path store and change-detection
    */

    u8 is_update = 0;

    struct flow_id_t flow_id = {};
    flow_id.src_ip = flow_info.src_ip;
    flow_id.dst_ip = flow_info.dst_ip;
    flow_id.src_port = flow_info.src_port;
    flow_id.dst_port = flow_info.dst_port;
    flow_id.ip_proto = flow_info.ip_proto;

    struct flow_info_t *flow_info_p = tb_flow.lookup(&flow_id);
    if (unlikely(!flow_info_p)) {

        flow_info.is_n_flow = 1;
        is_update = 1;

        if (is_hop_latencies) {
            switch (num_INT_hop) {
                case 1: flow_info.is_hop_latency = 0x01; break;
                case 2: flow_info.is_hop_latency = 0x03; break;
                case 3: flow_info.is_hop_latency = 0x07; break;
                case 4: flow_info.is_hop_latency = 0x0f; break;
                case 5: flow_info.is_hop_latency = 0x1f; break;
                case 6: flow_info.is_hop_latency = 0x3f; break;
                // MAX 6 for now
                // case 7: flow_info.is_hop_latency = 0x7f; break;
                // case 8: flow_info.is_hop_latency = 0xff; break;
                default: break;
            }
        }

        // flow_info.pkt_cnt++;
        // flow_info.byte_cnt += ntohs(ip->tot_len);

    } else {
        // only need periodically push for flow info, so we can know the live status of the flow
        if (is_hop_latencies & (ABS(flow_info.flow_latency, flow_info_p->flow_latency) > FLOW_LATENCY))
        {

            flow_info.is_flow = 1;
            is_update = 1;
        }

        _num_INT_hop = num_INT_hop;
        #pragma unroll
        for (u8 i = 0; i < MAX_INT_HOP; i++) {


            if (unlikely(flow_info.sw_ids[i] != flow_info_p->sw_ids[i])) {
                is_update = 1;
                flow_info.is_flow = 1;
                if (is_hop_latencies) {
                    flow_info.is_hop_latency |= 1 << i;
                }
            }

            if (unlikely(is_hop_latencies &
                (ABS(flow_info.hop_latencies[i], flow_info_p->hop_latencies[i]) > HOP_LATENCY))) {

                flow_info.is_hop_latency |= 1 << i;
                is_update = 1;
            }

            // no need for the final round
            if (i < MAX_INT_HOP - 1) {
                _num_INT_hop--;
                if (_num_INT_hop <= 0)
                    break;
            }
        }

        // flow_info.pkt_cnt = flow_info_p->pkt_cnt + 1;
        // flow_info.byte_cnt = flow_info_p->byte_cnt + ntohs(ip->tot_len);
    }

    if (is_update)
        tb_flow.update(&flow_id, &flow_info);



    /*
        Egress info
    */

    struct egr_info_t *egr_info_p;
    struct egr_id_t egr_id = {};
    struct egr_info_t egr_info;

    _num_INT_hop = num_INT_hop;
    #pragma unroll
    for (u8 i = 0; i < MAX_INT_HOP; i++) {
        if (is_in_e_port_ids & is_tx_utilizes) {
            if (_num_INT_hop <= 0)
                break;

            egr_id.sw_id  = flow_info.sw_ids[i];
            egr_id.p_id = flow_info.e_port_ids[i];

            egr_info.egr_time    = flow_info.egr_times[i];
            egr_info.tx_utilize  = flow_info.tx_utilizes[i];

            is_update = 0;

            egr_info_p = tb_egr.lookup(&egr_id);
            if(unlikely(!egr_info_p)) {

                flow_info.is_tx_utilize |= 1 << i;
                is_update = 1;
            }
            else {
                if (unlikely(ABS(egr_info.tx_utilize, egr_info_p->tx_utilize) > TX_UTILIZE)) {

                    flow_info.is_tx_utilize |= 1 << i;
                    is_update = 1;
                }
            }

            if (is_update)
                tb_egr.update(&egr_id, &egr_info);

            _num_INT_hop--;
        }
    }


    /*
        Queue info
    */

    struct queue_info_t *queue_info_p;
    struct queue_id_t queue_id = {};
    struct queue_info_t queue_info = {};

    _num_INT_hop = num_INT_hop;
    #pragma unroll
    for (u8 i = 0; i < MAX_INT_HOP; i++) {
        if (is_queue_occups) {
            if (_num_INT_hop <= 0)
                break;

            queue_id.sw_id = flow_info.sw_ids[i];
            queue_id.q_id = flow_info.queue_ids[i];

            queue_info.occup = flow_info.queue_occups[i];
            queue_info.q_time = flow_info.egr_times[i];

            is_update = 0;

            queue_info_p = tb_queue.lookup(&queue_id);
            if(unlikely(!queue_info_p)) {

                flow_info.is_queue_occup |= 1 << i;
                is_update = 1;

            } else {

                if (unlikely(ABS(queue_info.occup, queue_info_p->occup) > QUEUE_OCCUP)) {
                    flow_info.is_queue_occup |= 1 << i;
                    is_update = 1;
                }
            }

            if (is_update)
                tb_queue.update(&queue_id, &queue_info);

            _num_INT_hop--;
        }
    }


    // submit event info to user space
    if (unlikely(flow_info.is_n_flow |
        flow_info.is_hop_latency | flow_info.is_queue_occup | flow_info.is_tx_utilize
        | flow_info.is_flow
        )
    )
        events.perf_submit(ctx, &flow_info, sizeof(flow_info));

DROP:
    return XDP_DROP;
}
