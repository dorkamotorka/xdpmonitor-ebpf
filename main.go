package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf pktdrop pktdrop.c

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs pktdropObjects
	if err := loadPktdropObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()
	
	// Attach skb:kfree_skb Tracepoint
	tp, err := link.Tracepoint("skb", "kfree_skb", objs.TraceSkbDrops, nil)
	if err != nil {
		log.Fatalf("Attaching skb:kfree_skb Tracepoint: %s", err)
	}
	defer tp.Close()

	// Attach xdp:xdp_devmap_xmit Tracepoint
	tp2, err := link.Tracepoint("xdp", "xdp_devmap_xmit", objs.TraceXdpDrops, nil)
	if err != nil {
		log.Fatalf("Attaching xdp:xdp_devmap_xmit Tracepoint: %s", err)
	}
	defer tp2.Close()

	fmt.Scanln()
}
