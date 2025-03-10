# pktdrop-ebpf
Repository for monitoring packet drops across the whole Kernel Networking stack using eBPF

```
sudo bpftool map list # Get eBPF Map ID
sudo bpftool map lookup id <ID> key 0 0 0 0
sudo bpftool map lookup id <ID> key 1 0 0 0
```
