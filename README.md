# xdpmonitor-ebpf

A tool for monitoring XDP actions using eBPF—essentially, tracing eBPF with eBPF.

While working on various eBPF projects, I often needed to trace XDP eBPF return codes. For example, in one project, I built a simple eBPF/XDP-based firewall and wanted to measure the rate at which packets were dropped. However, most existing tools couldn't capture drops at the XDP level. This is precisely why XDP-based firewalls are effective—they drop packets before they reach the Linux networking stack. To solve this, I had to take a different approach.

In another case, multiple XDP programs were dropping packets, and I needed to understand the exact actions each program imposed on incoming traffic.

xdpmonitor-ebpf goes beyond just tracking packet drops. It attaches to the specified XDP program (using the `-i` or `--xdp-program-id` flag) and monitors all possible actions an XDP program can enforce on packets.

## How to use it

First, using `bpftool` find the XDP program ID:
```
$ sudo bpftool prog
```

Then just run the `xdpmonitor-ebpf`:
```
$ sudo ./xdpmonitor-ebpf -i <xdp-program-id>
```
