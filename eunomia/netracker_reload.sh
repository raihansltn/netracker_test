#!/bin/bash

# === Config ===
BPF_OBJ="NeTracker.bpf.o"
BPF_SRC="NeTracker.bpf.c"
PIN_PATH="/sys/fs/bpf/netracker"
IFACE="wlan0"

# === Compile the BPF program ===
echo "[*] Compiling $BPF_SRC..."
clang -O2 -g -target bpf -c "$BPF_SRC" -o "$BPF_OBJ"
if [ $? -ne 0 ]; then
    echo "[!] Compilation failed!"
    exit 1
fi

# === Clean up old pinned programs ===
echo "[*] Cleaning old pinned programs from $PIN_PATH..."
sudo rm -f "$PIN_PATH/tc_ingress" "$PIN_PATH/tc_egress"

# === Create pin path if missing ===
sudo mkdir -p "$PIN_PATH"

# === Load and pin all programs ===
echo "[*] Loading and pinning programs..."
sudo bpftool prog loadall "$BPF_OBJ" "$PIN_PATH"
if [ $? -ne 0 ]; then
    echo "[!] Failed to load programs!"
    exit 1
fi

# === Find pinned program IDs ===
INGRESS_ID=$(sudo bpftool prog show pinned "$PIN_PATH/tc_ingress" | awk '/id/ {print $2}')
EGRESS_ID=$(sudo bpftool prog show pinned "$PIN_PATH/tc_egress" | awk '/id/ {print $2}')

if [ -z "$INGRESS_ID" ] || [ -z "$EGRESS_ID" ]; then
    echo "[!] Failed to find program IDs after load."
    exit 1
fi

# === Clean existing tc filters ===
echo "[*] Cleaning up existing tc filters on $IFACE..."
sudo tc qdisc del dev "$IFACE" clsact 2>/dev/null
sudo tc qdisc add dev "$IFACE" clsact

# === Attach using tc filter ===
echo "[*] Attaching ingress and egress programs via tc..."
sudo tc filter add dev $IFACE ingress bpf da pinned $PIN_PATH/tc_ingress
sudo tc filter add dev $IFACE egress bpf da pinned $PIN_PATH/tc_egress

echo "[+] Reload complete. BPF programs active on $IFACE."

