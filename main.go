package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf xdpmonitor xdpmonitor.c

import (
        "context"
        "errors"
        "fmt"
        "log"
        "os"
        "os/signal"
        "syscall"
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

        if info.Type != ebpf.XDP {
                return "", fmt.Errorf("program is not an XDP program")
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

func lookupAndPrintStats(ebpfMap *ebpf.Map, keys map[string]uint32, keyOrder []string, prevValues map[string]uint64, prevTime *time.Time) {
        fmt.Println("\nXDP Actions:")
	now := time.Now()
 	deltaTime := now.Sub(*prevTime).Seconds()
 	if deltaTime == 0 {
 		return // Avoid division by zero
 	}
        for _, action := range keyOrder {
                key := keys[action]
                var value uint64
                if err := ebpfMap.Lookup(&key, &value); err != nil {
                        log.Fatalf("Failed to lookup map: %v", err)
                }
		prev := prevValues[action]
 		prevValues[action] = value
 		rate := float64(value-prev) / deltaTime
 		fmt.Printf("%s: %d (Rate: %.2f/s)\n", action, value, rate)
        }
	*prevTime = now
}

func main() {
        var xdpProgID int
        flag.IntVarP(&xdpProgID, "xdp-program-id", "i", 0, "XDP program ID to trace")
        flag.Parse()

        if xdpProgID == 0 {
                fmt.Println("You need to specify XDP program ID")
                return
        }

        ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
        defer cancel()

        if err := rlimit.RemoveMemlock(); err != nil {
                log.Fatalf("Failed to remove rlimit memlock: %v", err)
        }

        spec, err := loadXdpmonitor()
        if err != nil {
                log.Fatalf("Failed to load xdpmonitor bpf spec: %v", err)
        }

        xdpProg, err := ebpf.NewProgramFromID(ebpf.ProgramID(xdpProgID))
        if err != nil {
                log.Fatalf("Failed to load XDP program ID %d: %v", xdpProgID, err)
        }
        defer xdpProg.Close()

        xdpFuncName, err := getFuncName(xdpProg)
        if err != nil {
                log.Fatalf("Failed to get function name: %v", err)
        }

        spec.Programs["fexit_xdp"].AttachTarget = xdpProg
        spec.Programs["fexit_xdp"].AttachTo = xdpFuncName

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

        xdpfexit, err := link.AttachTracing(link.TracingOptions{
                Program: obj.FexitXdp,
        })
        if err != nil {
                log.Fatalf("Failed to attach fexit program: %v", err)
        }
        defer xdpfexit.Close()

        fmt.Printf("Tracing XDP Program with ID %d...\n", xdpProgID)

        ticker := time.NewTicker(1 * time.Second)
        defer ticker.Stop()

	prevValues := make(map[string]uint64)
 	prevTime := time.Now()

        for {
                select {
                case <-ctx.Done():
                        return
                case <-ticker.C:
                        fmt.Print("\033[H\033[J")
                        lookupAndPrintStats(obj.XdpActionCountMap, xdpKeys, xdpKeyOrder, prevValues, &prevTime)
                }
        }
}
