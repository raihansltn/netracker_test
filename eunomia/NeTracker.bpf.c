#include </home/toughrebel/Documents/Project/netracker_test/eunomia/vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800  /* Internet Protocol packet */
#define IPPROTO_TCP 6
#define SYN_FLAG 0x02

//eBPF hash map to store connection timestamps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} conn_map SEC(".maps");

//TC ingress hook function
SEC("tc_ing")
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

    if (tcp->syn && !tcp->ack) { //track SYN packet
        __u32 src_ip = bpf_ntohl(l3->saddr);
        __u64 timestamp = bpf_ktime_get_ns();
        bpf_map_update_elem(&conn_map, &src_ip, &timestamp, BPF_ANY);
    }

    return TC_ACT_OK;
}

//TC egress hook function
SEC("tc_eg")
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

    if (tcp->syn && !tcp->ack) { //track SYN packet
        __u32 src_ip = bpf_ntohl(l3->saddr);
        __u64 *start_time = bpf_map_lookup_elem(&conn_map, &src_ip);
        if (start_time) {
            __u64 elapsed_time = bpf_ktime_get_ns() - *start_time;
            bpf_printk("[TC] SYN IP %u.%u.%u.%u took %llu ns to traverse",
                       (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF, 
                       (src_ip >> 8) & 0xFF, src_ip & 0xFF, elapsed_time);
            bpf_map_delete_elem(&conn_map, &src_ip);
        }
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";