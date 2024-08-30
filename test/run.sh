#! /bin/bash
# Farbod Shahinfar 2024
if [ -z "$KASHK_DIR" ]; then
	echo "KASHK_DIR is not defined"
	exit 1
fi
if [ -z "$NET_IFACE" ]; then
	echo "Missing the NET_IFACE"
	exit 1
fi

CURDIR=$(realpath $(dirname $0))
BPF_GEN_DIR=$KASHK_DIR
BPF_GEN=$KASHK_DIR/bpf_gen.sh
BPF_COMPILE_SCRIPT=$BPF_GEN_DIR/compile_scripts/compile_bpf_source.sh

BUILD_DIR=$CURDIR/build
BPF_BINARY=/$BUILD_DIR/_test_bpf.o
BPF_GENERATED_FILE=$CURDIR/bpf.c


mkdir -p $BUILD_DIR/


if [ -f $BPF_BINARY ]; then rm -f $BPF_BINARY; fi

# Compile the BPF program
bash $BPF_COMPILE_SCRIPT $BPF_GENERATED_FILE $BPF_BINARY

# Test if it loads into the kernel
# bash $BPF_GEN_DIR/compile_scripts/load.sh $BPF_BINARY

# Load and run the BPF program
# sudo $BPF_GEN_DIR/compile_scripts/loader -b $BPF_BINARY --skskb verdict
sudo $BPF_GEN_DIR/compile_scripts/loader -b $BPF_BINARY -i $NET_IFACE --xdp xdp_prog
