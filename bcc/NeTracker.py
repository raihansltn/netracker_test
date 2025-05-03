#!/usr/bin/env python
from bcc import BPF
from struct import pack
import socket
import sys

bpf_text = """
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <linux/bpf_endian.h>
#include <linux/version.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define IPPROTO_TCP 6
#define SYN_FLAG 0x02
#define FIN_ACK_FLAG (0x01 | 0x10) // FIN and ACK flags

//key
struct conn_key_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
} __attribute__((packed));

//eBPF hash map to store connection timestamps
BPF_HASH(conn_map, struct conn_key_t, u64, 1024);

//TC ingress hook function
int tc_ingress(struct __sk_buff *ctx) {
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;
    struct tcphdr *tcp;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    if (l3->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    tcp = (struct tcphdr *)(l3 + 1);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    if (tcp->syn && !(tcp->ack)) { //track SYN packet
        struct conn_key_t key = {
            .src_ip = bpf_ntohl(l3->saddr),
            .dst_ip = bpf_ntohl(l3->daddr),
            .src_port = bpf_ntohs(tcp->source),
            .dst_port = bpf_ntohs(tcp->dest),
        };

        u64 start_time = bpf_ktime_get_ns();
        //bpf_trace_printk("Debug - Adding conn key: %u:%u -> %u:%u\\n", key.src_ip, key.src_port, key.dst_ip, key.dst_port);
        conn_map.update(&key, &start_time);
    }
    return TC_ACT_OK;
}

//TC egress hook function
int tc_egress(struct __sk_buff *ctx) {
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;
    struct tcphdr *tcp;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    if (l3->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    tcp = (struct tcphdr *)(l3 + 1);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    if (tcp->fin && tcp->ack) {
        struct conn_key_t key = { //flipped for egress lookup
            .src_ip = bpf_ntohl(l3->daddr),
            .dst_ip = bpf_ntohl(l3->saddr),
            .src_port = bpf_ntohs(tcp->dest),
            .dst_port = bpf_ntohs(tcp->source),
        };
        //bpf_trace_printk("Debug - Looking for FIN-ACK key: %u:%u -> %u:%u\\n", key.src_ip, key.src_port, key.dst_ip, key.dst_port);
        u64 *start_time = conn_map.lookup(&key);
        if (start_time) {
            u64 end_time = bpf_ktime_get_ns();
            u64 elapsed_time = end_time - *start_time;
            u32 src_ip_n = bpf_ntohl(l3->daddr);
            u32 dst_ip_n = bpf_ntohl(l3->saddr);
            u16 src_port_n = bpf_ntohs(tcp->dest);
            u16 dst_port_n = bpf_ntohs(tcp->source);
            bpf_trace_printk("[TC] Total RTT (SYN - FIN-ACK) for %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u: %llu ns\\n",
                             (src_ip_n >> 24) & 0xFF, (src_ip_n >> 16) & 0xFF, (src_ip_n >> 8) & 0xFF, src_ip_n & 0xFF, src_port_n,
                             (dst_ip_n >> 24) & 0xFF, (dst_ip_n >> 16) & 0xFF, (dst_ip_n >> 8) & 0xFF, dst_ip_n & 0xFF, dst_port_n,
                             elapsed_time);
            conn_map.delete(&key);
        }
    }

    return TC_ACT_OK;
}
"""

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        exit(1)

    interface = sys.argv[1]

    b = BPF(text=bpf_text)

    ingress_fn = b.load_func("tc_ingress", BPF.SCHED_CLS)
    egress_fn = b.load_func("tc_egress", BPF.SCHED_CLS)

    try:
        b.attach_cls_ingress(dev=interface, handle=0xFFFFFFFF, fd=ingress_fn)
        b.attach_cls_egress(dev=interface, handle=0xFFFFFFFF, fd=egress_fn)
    except Exception as e:
        print(f"Error attaching TC filters: {e}")
        exit(1)

    print(f"Tracing TCP SYN and FIN-ACK packets on interface '{interface}'...")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            try:
                output = b.trace_readline()
                print(output, end='')
            except KeyboardInterrupt:
                break
    finally:
        b.remove_cls(dev=interface, handle=0xFFFFFFFF, ingress=True)
        b.remove_cls(dev=interface, handle=0xFFFFFFFF, egress=True)
        print("\nDetached TC filters.")
