//go:build ignore
/* 
 * Monitoring packet drops via kfree_skb and xdp
 * */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} drop_count_map SEC(".maps");

SEC("tracepoint/skb/kfree_skb")
int trace_skb_drops(struct trace_event_raw_kfree_skb *ctx) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&drop_count_map, &key);
    bpf_printk("Update SKB counter");
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    return 0;
}

SEC("tracepoint/xdp/xdp_devmap_xmit")
int trace_xdp_drops(struct trace_event_raw_xdp_devmap_xmit *ctx) {
    __u32 key = 1;
    __u64 *count = bpf_map_lookup_elem(&drop_count_map, &key);
    bpf_printk("Update XDP counter");
    if (count) {
	__sync_fetch_and_add(count, ctx->drops);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
