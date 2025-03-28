#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <linux/in.h>
#include </usr/src/linux-headers-6.11.0-21-generic/tools/bpf/resolve_btfids/libbpf/include/bpf/bpf_helpers.h>
#include </usr/src/linux-headers-6.11.0-21-generic/tools/bpf/resolve_btfids/libbpf/include/bpf/bpf_endian.h>

struct key_t {
    __u32 src_ip;
    __u32 dst_ip;
};

// Define a BPF hash map to store timestamps of SYN packets
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct key_t);
    __type(value, __u64);
} pkt_start SEC(".maps");

// Function to monitor SYN packets
static __always_inline int monitor_syn(struct __sk_buff *skb) {
    void *data_end = (void *)(unsigned long)skb->data_end;
    void *data = (void *)(unsigned long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Ensure it's an IPv4 packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Ensure it's a TCP packet
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    // Only process SYN packets
    if (!(tcp->syn && !tcp->ack))
        return TC_ACT_OK;

    struct key_t key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr
    };
    __u64 ts = bpf_ktime_get_ns();  // Get timestamp

    __u64 *start_ts = bpf_map_lookup_elem(&pkt_start, &key);
    if (start_ts) {
        __u64 elapsed_time = ts - *start_ts;
        bpf_printk("SYN from %pI4 -> %pI4 took %llu ns\n",
                   &ip->saddr, &ip->daddr, elapsed_time);
        bpf_map_delete_elem(&pkt_start, &key);  // Remove entry
    } else {
        bpf_map_update_elem(&pkt_start, &key, &ts, BPF_ANY);
    }

    return TC_ACT_OK;
}

// Attach to ingress (incoming packets)
SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    return monitor_syn(skb);
}

// Attach to egress (outgoing packets)
SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    return monitor_syn(skb);
}

char _license[] SEC("license") = "GPL";
