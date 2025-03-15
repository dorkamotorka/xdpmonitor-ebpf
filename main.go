package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf pktmonitor pktmonitor.c

import (
	"log"
	"fmt"
	"net"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"context"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
)

func getFuncName(prog *ebpf.Program) (string, error) {
	info, err := prog.Info()
        if err != nil {
                return "", fmt.Errorf("failed to get program info: %w", err)
        }

        if _, ok := info.BTFID(); !ok {
                return "", fmt.Errorf("program does not have BTF ID")
        }

        insns, err := info.Instructions()
        if err != nil {
                return "", fmt.Errorf("failed to get program instructions: %w", err)
        }

        for _, insn := range insns {
                if sym := insn.Symbol(); sym != "" {
                        return sym, nil 
                }
        }

	return "", fmt.Errorf("no entry function found in program")
}

func lookupAndPrintXdpStats(ebpfMap *ebpf.Map) {
	actionKeys := map[string]uint32{
		"XDP_ABORTED":  0,
		"XDP_DROP":     1,
		"XDP_PASS":     2,
		"XDP_TX":       3,
		"XDP_REDIRECT": 4,
	}

	for action, key := range actionKeys {
		var value uint64
		if err := ebpfMap.Lookup(&key, &value); err != nil {
			log.Fatal(err)
		}
		log.Printf("%s: %d", action, value)
	}
}

func lookupAndPrintTcStats(ebpfMap *ebpf.Map) {
	tcActionKeys := map[string]uint32{
		//"TC_ACT_UNSPEC":     uint32(-1),
		"TC_ACT_OK":         0,
		"TC_ACT_RECLASSIFY": 1,
		"TC_ACT_SHOT":       2,
		"TC_ACT_PIPE":       3,
		"TC_ACT_STOLEN":     4,
		"TC_ACT_QUEUED":     5,
		"TC_ACT_REPEAT":     6,
		"TC_ACT_REDIRECT":   7,
		"TC_ACT_TRAP":       8,
	}

	for action, key := range tcActionKeys {
		var value uint64
		if err := ebpfMap.Lookup(&key, &value); err != nil {
			log.Fatal(err)
		}
		log.Printf("%s: %d", action, value)
	}
}

func main() {
	var device string
	flag.StringVarP(&device, "device", "d", "lo", "device to attach XDP program")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	ifi, err := net.InterfaceByName(device)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", device, err)
	}

	spec, err := loadPktmonitor()
	if err != nil {
		log.Fatalf("Failed to load pktmonitor bpf spec: %v", err)
		return
	}

	xdpDummy := spec.Programs["xdp_dummy"]
	xdpDummyProg, err := ebpf.NewProgram(xdpDummy)
	if err != nil {
		log.Fatalf("Failed to create XDP dummy program: %v", err)
	}
	defer xdpDummyProg.Close()

	tcDummy := spec.Programs["tc_dummy"]
	tcDummyProg, err := ebpf.NewProgram(tcDummy)
	if err != nil {
		log.Fatalf("Failed to create TC dummy program: %v", err)
	}
	defer tcDummyProg.Close()

	// Get function name of the dummy program to attach fentry/fexit hooks
	// And configure fentry/fexit hooks target
	xdpFuncName, err := getFuncName(xdpDummyProg)
	if err != nil {
		log.Printf("Failed to get function name: %v", err)
		return
	}
	xdpFexit := spec.Programs["fexit_xdp"]
	xdpFexit.AttachTarget = xdpDummyProg
	xdpFexit.AttachTo = xdpFuncName

	tcFuncName, err := getFuncName(tcDummyProg)
	if err != nil {
		log.Printf("Failed to get function name: %v", err)
		return
	}
	tcFexit := spec.Programs["fexit_tc"]
	tcFexit.AttachTarget = tcDummyProg
	tcFexit.AttachTo = tcFuncName

	// Now load and assign eBPF program 
	// We couldn't use loadpktmonitorObjects directly since it doesn't allow us to modify spec like AttachTarget, AttachTo before loading
	var obj pktmonitorObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load bpf obj: %v\n%-20v", err, ve)
		} else {
			log.Fatalf("Failed to load bpf obj: %v", err)
		}
	}
	defer obj.Close()

	// Attach dummy XDP program to trace
	xdplink, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpDummyProg,
		Interface: ifi.Index,
		//Flags: link.XDPDriverMode,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer xdplink.Close()

	// Attach fexit to XDP
	xdpfexit, err := link.AttachTracing(link.TracingOptions{
                Program:   obj.FexitXdp,
                //AttachType: ebpf.AttachTraceFExit,
        })
        if err != nil {
                log.Fatalf("Failed to attach fexit program: %v", err)
        }
        defer xdpfexit.Close()

	// Attach dummy TC program to trace
	tclink, err := link.AttachTCX(link.TCXOptions{
		Program:   tcDummyProg,
		Attach:	   ebpf.AttachTCXIngress,
		Interface: ifi.Index,
	})
	if err != nil {
			log.Fatal("Attaching TC:", err)
	}
	defer tclink.Close()

	// Attach fexit to TC
	tcfexit, err := link.AttachTracing(link.TracingOptions{
                Program:   obj.FexitTc,
                //AttachType: ebpf.AttachTraceFExit,
        })
        if err != nil {
                log.Fatalf("Failed to attach fexit program: %v", err)
        }
        defer tcfexit.Close()

	log.Println("Programs attached and running...")
	log.Printf("Try sending a dummy network packet to the %s.", device)

	for {
		lookupAndPrintXdpStats(obj.XdpActionCountMap)
		lookupAndPrintTcStats(obj.TcActionCountMap)

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(1 * time.Second)
	}
}
