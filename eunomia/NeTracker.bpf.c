#include </home/toughrebel/Documents/Project/netracker_test/eunomia/vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800  /* Internet Protocol packet */
#define IPPROTO_TCP 6
#define SYN_FLAG 0x02

//key
struct conn_key_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
} __attribute__((packed));

//eBPF hash map to store connection timestamps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct conn_key_t);
    __type(value, __u64);
    __uint(max_entries, 1024);
} conn_map SEC(".maps");

//TC ingress hook function
SEC("tc/ingress")
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
        struct conn_key_t key = {
            .src_ip = bpf_ntohl(l3->saddr),
            .dst_ip = bpf_ntohl(l3->daddr),
            .src_port = bpf_ntohs(tcp->source),
            .dst_port = bpf_ntohs(tcp->dest),
        };

        __u64 start_time = bpf_ktime_get_ns();
        bpf_printk("Debug - Adding conn key: %u:%u -> %u:%u", key.src_ip, key.src_port, key.dst_ip, key.dst_port); 
        bpf_map_update_elem(&conn_map, &key, &start_time, BPF_ANY);
    }
    return TC_ACT_OK;
}

//TC egress hook function
SEC("tc/egress")
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
    if (tcp->syn && tcp->ack) {
        struct conn_key_t key = { //this is flipped now to match the SYN
            .src_ip = bpf_ntohl(l3->daddr),
            .dst_ip = bpf_ntohl(l3->saddr),
            .src_port = bpf_ntohs(tcp->dest),
            .dst_port = bpf_ntohs(tcp->source),
        };
        bpf_printk("Debug - Looking for key: %u:%u -> %u:%u", key.src_ip, key.src_port, key.dst_ip, key.dst_port);
        __u64 *start_time = bpf_map_lookup_elem(&conn_map, &key);
        if (start_time) {
            bpf_printk("Debug - Found conn key at egress: %u:%u -> %u:%u", key.src_ip, key.src_port, key.dst_ip, key.dst_port);
            bpf_printk("Debug - TC ingress hit");
            bpf_printk("Debug - TC egress hit");
            __u64 elapsed_time = bpf_ktime_get_ns() - *start_time;
            bpf_printk("[TC] SYNK-ACK RTT for %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u: %llu ns\n",
		    (bpf_ntohl(key.src_ip) >> 24) & 0xFF, (bpf_ntohl(key.src_ip) >> 16) & 0xFF,
		    (bpf_ntohl(key.src_ip) >> 8) & 0xFF, bpf_ntohl(key.src_ip) & 0xFF, bpf_ntohs(key.src_port),
		    (bpf_ntohl(key.dst_ip) >> 24) & 0xFF, (bpf_ntohl(key.dst_ip) >> 16) & 0xFF,
		    (bpf_ntohl(key.dst_ip) >> 8) & 0xFF, bpf_ntohl(key.dst_ip) & 0xFF, bpf_ntohs(key.dst_port),
		    elapsed_time);
            bpf_map_delete_elem(&conn_map, &key);
            bpf_printk("Debug - Reach End");
        }
    }
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
