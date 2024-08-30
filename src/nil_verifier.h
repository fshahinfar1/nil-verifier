#ifndef _NIL_VERIFIER_H
#define _NIL_VERIFIER_H
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_verifier.h>
/* #include <uapi/linux/bpf_common.h> */
int nil_bpf_check(struct bpf_prog **prog, union bpf_attr *attr, bpfptr_t uattr,
		__u32 uattr_size);
#endif
