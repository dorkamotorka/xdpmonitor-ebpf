package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf xdpmonitor xdpmonitor.c

import (
	"log"
	"fmt"
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

var (
	xdpKeys = map[string]uint32{
		"XDP_ABORTED": 0, "XDP_DROP": 1, "XDP_PASS": 2, "XDP_TX": 3, "XDP_REDIRECT": 4,
	}
	xdpKeyOrder = []string{"XDP_ABORTED", "XDP_DROP", "XDP_PASS", "XDP_TX", "XDP_REDIRECT"}
)

func getFuncName(prog *ebpf.Program) (string, error) {
	info, err := prog.Info()
        if err != nil {
                return "", fmt.Errorf("failed to get program info: %w", err)
        }

	// Ensure the program is a XDP program
	if info.Type != ebpf.XDP {
		return "", fmt.Errorf("program is not a XDP program")
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

func lookupAndPrintStats(ebpfMap *ebpf.Map, keys map[string]uint32, keyOrder []string, title string) {
	fmt.Println("\n" + title + ":")
	for _, action := range keyOrder { // Iterate using ordered slice
		key := keys[action]
		var value uint64
		if err := ebpfMap.Lookup(&key, &value); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s: %d\n", action, value)
	}
}

func main() {
	var xdpProgID int
	flag.IntVarP(&xdpProgID, "xdp_program_id", "x", 0, "XDP program ID to trace")
	flag.Parse()

	if xdpProgID == 0 {
		fmt.Println("You need to specify XDP program ID")
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	spec, err := loadXdpmonitor()
	if err != nil {
		log.Fatalf("Failed to load xdpmonitor bpf spec: %v", err)
		return
	}

	// Load eBPF program from ID
	xdpProg, err := ebpf.NewProgramFromID(ebpf.ProgramID(xdpProgID))
	if err != nil {
		log.Printf("Failed to load XDP program ID %d: %v", xdpProgID, err)
	}
	defer xdpProg.Close()

	xdpFuncName, err := getFuncName(xdpProg)
	if err != nil {
		log.Printf("Failed to get function name: %v", err)
		return
	}

	xdpFexit := spec.Programs["fexit_xdp"]
	xdpFexit.AttachTarget = xdpProg
	xdpFexit.AttachTo = xdpFuncName

	// Now load and assign eBPF program 
	// We couldn't use loadxdpmonitorObjects directly since it doesn't allow us to modify spec like AttachTarget, AttachTo before loading
	var obj xdpmonitorObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load bpf obj: %v\n%-20v", err, ve)
		} else {
			log.Fatalf("Failed to load bpf obj: %v", err)
		}
	}
	defer obj.Close()

	// Attach fexit to XDP
	xdpfexit, err := link.AttachTracing(link.TracingOptions{
		Program:   obj.FexitXdp,
		//AttachType: ebpf.AttachTraceFExit,
	})
	if err != nil {
		log.Fatalf("Failed to attach fexit program: %v", err)
	}
	defer xdpfexit.Close()

	fmt.Printf("Tracing XDP Program with ID %d...", xdpProgID)

	for {
		fmt.Print("\033[H\033[J") // Clear screen
		lookupAndPrintStats(obj.XdpActionCountMap, xdpKeys, xdpKeyOrder, "XDP Actions")

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(1 * time.Second)
	}
}
