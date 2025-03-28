from bcc import BPF
import argparse
import os
import time

EBPF_PROGRAM_FILE = "NeTracker.bpf.c"

def get_interface():
    """Finds the default network interface"""
    with os.popen("ip route | grep default") as f:
        route_info = f.read().split()
        if len(route_info) >= 5:
            return route_info[4]
        return "eth0"  # Default if auto-detection fails

# Parse arguments
parser = argparse.ArgumentParser(description="Attach eBPF TC program")
parser.add_argument("-i", "--interface", type=str, default=get_interface(),
                    help="Network interface (default: detected)")
args = parser.parse_args()
iface = args.interface

# Load eBPF program
print(f"Loading eBPF TC program on {iface}...")
bpf = BPF(src_file=EBPF_PROGRAM_FILE)

# Load ingress and egress functions
tc_ingress_fn = bpf.load_func("tc_ingress", BPF.SCHED_CLS)
tc_egress_fn = bpf.load_func("tc_egress", BPF.SCHED_CLS)

# Attach eBPF to ingress & egress
bpf.attach_tc("tc_ingress", iface, BPF.TC_INGRESS)
bpf.attach_tc("tc_egress", iface, BPF.TC_EGRESS)

print("eBPF program attached. Monitoring...")

# Read logs from `bpf_trace_printk`
try:
    while True:
        time.sleep(1)
        while True:
            line = bpf.trace_readline()
            if not line:
                break
            print(line)
except KeyboardInterrupt:
    print("\nDetaching eBPF program...")
    bpf.remove_tc("tc_ingress", iface, BPF.TC_INGRESS)
    bpf.remove_tc("tc_egress", iface, BPF.TC_EGRESS)
    print("NeTracker detached")
