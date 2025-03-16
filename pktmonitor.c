//go:build ignore
/* 
 * Tracing XDP and TC programs 
 * */
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 5);
} xdp_action_count_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 9);
} tc_action_count_map SEC(".maps");

SEC("fexit/xdp")
int BPF_PROG(fexit_xdp, struct xdp_buff *xdp, int ret) {
    bpf_printk("XDP Fexit triggered.");
    __u64 *count = bpf_map_lookup_elem(&xdp_action_count_map, &ret);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    return 0;
}

SEC("fexit/tc")
int BPF_PROG(fexit_tc, struct sk_buff *skb, int ret) {
    bpf_printk("TC Fexit triggered.");
    __u64 *count = bpf_map_lookup_elem(&tc_action_count_map, &ret);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
