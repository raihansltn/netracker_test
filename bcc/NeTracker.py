#!/usr/bin/env python3
from bcc import BPF
from struct import pack
import socket
from time import sleep

bpf_text = """
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <arpa/inet.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define IPPROTO_TCP 6
#define SYN_FLAG 0x02

// Key for the connection map
struct conn_key_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

// eBPF hash map to store connection timestamps
BPF_HASH(conn_map, struct conn_key_t, __u64, 1024);

// TC ingress hook function
int tc_ingress(struct sk_buff *skb) {
    void *data_end = skb->data_end;
    void *data = skb->data;
    struct ethhdr *eth = data;

    if (data + sizeof(struct ethhdr) > data_end) {
        return TC_ACT_OK;
    }

    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return TC_ACT_OK;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (ip->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    struct tcphdr *tcp = (void *)(ip + ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (tcp->syn && !(tcp->ack)) { // Track SYN packet
        struct conn_key_t key = {
            .src_ip = ip->saddr,
            .dst_ip = ip->daddr,
            .src_port = tcp->source,
            .dst_port = tcp->dest,
        };

        __u64 start_time = bpf_ktime_get_ns();
        bpf_trace_printk("Debug - Adding conn key: %u:%u -> %u:%u\\n", ntohl(key.src_ip), ntohs(key.src_port), ntohl(key.dst_ip), ntohs(key.dst_port));
        conn_map.update(&key, &start_time);
    }

    return TC_ACT_OK;
}

// TC egress hook function
int tc_egress(struct sk_buff *skb) {
    void *data_end = skb->data_end;
    void *data = skb->data;
    struct ethhdr *eth = data;

    if (data + sizeof(struct ethhdr) > data_end) {
        return TC_ACT_OK;
    }

    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return TC_ACT_OK;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (ip->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    struct tcphdr *tcp = (void *)(ip + ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (tcp->syn && tcp->ack) {
        struct conn_key_t key = { // Flipped to match SYN
            .src_ip = ip->daddr,
            .dst_ip = ip->saddr,
            .src_port = tcp->dest,
            .dst_port = tcp->source,
        };

        bpf_trace_printk("Debug - Looking for key: %u:%u -> %u:%u\\n", ntohl(key.src_ip), ntohs(key.src_port), ntohl(key.dst_ip), ntohs(key.dst_port));
        __u64 *start_time = conn_map.lookup(&key);
        if (start_time) {
            bpf_trace_printk("Debug - Found conn key at egress: %u:%u -> %u:%u\\n", ntohl(key.src_ip), ntohs(key.src_port), ntohl(key.dst_ip), ntohs(key.dst_port));
            bpf_trace_printk("Debug - TC ingress hit\\n");
            bpf_trace_printk("Debug - TC egress hit\\n");
            __u64 elapsed_time = bpf_ktime_get_ns() - *start_time;
            bpf_trace_printk("[TC] SYN-ACK RTT for %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u: %llu ns\\n",
                             (ntohl(key.src_ip) >> 24) & 0xFF, (ntohl(key.src_ip) >> 16) & 0xFF,
                             (ntohl(key.src_ip) >> 8) & 0xFF, ntohl(key.src_ip) & 0xFF, ntohs(key.src_port),
                             (ntohl(key.dst_ip) >> 24) & 0xFF, (ntohl(key.dst_ip) >> 16) & 0xFF,
                             (ntohl(key.dst_ip) >> 8) & 0xFF, ntohl(key.dst_ip) & 0xFF, ntohs(key.dst_port),
                             elapsed_time);
            conn_map.delete(&key);
            bpf_trace_printk("Debug - Reach End\\n");
        }
    }

    return TC_ACT_OK;
}
"""

b = BPF(text=bpf_text)

#get ingress and egress funcs
ingress_fn = b.load_func("tc_ingress", BPF.SCHED_CLS)
egress_fn = b.load_func("tc_egress", BPF.SCHED_CLS)

interface = "eth0"

#attach bpf progs to hooks
try:
    b.attach_tc(func=ingress_fn, dev=interface, handle=0xFFF1, parent=BPF.TC_H_INGRESS, kind="clsact")
    b.attach_tc(func=egress_fn, dev=interface, handle=0xFFF2, parent=BPF.TC_H_EGRESS, kind="clsact")
    print(f"Attached BPF program to ingress and egress of interface {interface}")

    try:
        while True:
            sleep(1)
    except KeyboardInterrupt:
        pass
finally:
    b.remove_tc(dev=interface, handle=0xFFF1, parent=BPF.TC_H_INGRESS, kind="clsact")
    b.remove_tc(dev=interface, handle=0xFFF2, parent=BPF.TC_H_EGRESS, kind="clsact")
    print(f"Detached BPF program from interface {interface}")
