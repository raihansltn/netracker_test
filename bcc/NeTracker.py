from bcc import BPF
from pyroute2 import IPRoute
import socket
import struct

bpf_text = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>

#define TC_ACT_OK 0

struct conn_key_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
};

BPF_HASH(conn_map, struct conn_key_t, u64, 1024);

int tc_ingress(struct __sk_buff *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    if (tcp->syn && !tcp->ack) {
        struct conn_key_t key = {
            .src_ip = ip->saddr,
            .dst_ip = ip->daddr,
            .src_port = bpf_ntohs(tcp->source),
            .dst_port = bpf_ntohs(tcp->dest),
        };
        u64 ts = bpf_ktime_get_ns();
        conn_map.update(&key, &ts);
    }
    return TC_ACT_OK;
}

int tc_egress(struct __sk_buff *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    if (tcp->syn && tcp->ack) {
        struct conn_key_t key = {
            .src_ip = ip->daddr,
            .dst_ip = ip->saddr,
            .src_port = bpf_ntohs(tcp->dest),
            .dst_port = bpf_ntohs(tcp->source),
        };

        u64 *start = conn_map.lookup(&key);
        if (start) {
            u64 delta = bpf_ktime_get_ns() - *start;
            bpf_trace_printk("[BCC] SYN-ACK RTT: %u -> %u: %llu ns\\n", key.src_ip, key.dst_ip, delta);
            conn_map.delete(&key);
        }
    }
    return TC_ACT_OK;
}
"""

#load BPF program
b = BPF(text=bpf_text)
fn_ingress = b.load_func("tc_ingress", BPF.SCHED_CLS)
fn_egress = b.load_func("tc_egress", BPF.SCHED_CLS)

#attach to interface via tc
import subprocess

iface = "wlan0"

def run_tc(cmd):
    subprocess.call(cmd, shell=True)

run_tc(f"tc qdisc del dev {iface} clsact 2>/dev/null")
run_tc(f"tc qdisc add dev {iface} clsact")
run_tc(f"tc filter add dev {iface} ingress bpf da obj /dev/null sec classifier/tc_ingress")
run_tc(f"tc filter add dev {iface} egress bpf da obj /dev/null sec classifier/tc_egress")

#use bcc to attach
b.attach_sched_cls(fn_ingress, iface=iface, direction="ingress")
b.attach_sched_cls(fn_egress, iface=iface, direction="egress")

print("Monitoring SYN-ACK RTTs... Hit Ctrl+C to exit.")
try:
    b.trace_print()
except KeyboardInterrupt:
    print("Detaching...")
    run_tc(f"tc qdisc del dev {iface} clsact")

