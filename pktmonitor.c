//go:build ignore
/* 
 * Tracing XDP and TC programs 
 * */
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0

// XDP
SEC("fentry/xdp")
int BPF_PROG(fentry_xdp, struct xdp_buff *xdp) {
    bpf_printk("XDP Fentry triggered.");
    return 0;
}

SEC("fexit/xdp")
int BPF_PROG(fexit_xdp, struct xdp_buff *xdp, int ret) {
    bpf_printk("XDP Fexit triggered.");
    return 0;
}

SEC("xdp")
int xdp_dummy(struct xdp_md *ctx) {
    return XDP_PASS;
}

// TC
SEC("fentry/tc")
int BPF_PROG(fentry_tc, struct sk_buff *skb) {
    bpf_printk("TC Fentry triggered.");
    return 0;
}

SEC("fexit/tc")
int BPF_PROG(fexit_tc, struct sk_buff *skb, int ret) {
    bpf_printk("TC Fexit triggered.");
    return 0;
}

SEC("tc")
int tc_dummy(struct __sk_buff *ctx) {
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
