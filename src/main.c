/* Farbod Shahinfar 2024
 * */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <khook/engine.h>

#include "nil_verifier.h"

/*
 * I can not just disable the bpf_check function. It not only does the checks,
 * but also performs responsibilities of so many other tools which makes it a
 * design nightmare.
 *   (1) It optimzes the loops, dead-code, ...
 *   (2) Links the helper-function invocation to the currect function
 *   (3) Rewrite the context pointer
 *   ...
 *
 * The rewriting phase depends on the values computed during the check. This
 * creates a very tight coupling between functions. Bad software engineering
 * choices every where.
 * */

KHOOK_EXT(int, bpf_check, struct bpf_prog **, union bpf_attr *, bpfptr_t, __u32);
int khook_bpf_check(struct bpf_prog **prog, union bpf_attr *attr,
		bpfptr_t uattr, __u32 uattr_size)
{
	printk("Inside bpf_check\n");
	return nil_bpf_check(prog, attr, uattr, uattr_size);
}

static int __init nil_verifier_init(void)
{
	printk("NIL verifier loaded\n");
	return khook_init(NULL);
}

static void __exit nil_verifier_exit(void)
{
	printk("NIL verifier unloaded\n");
	khook_cleanup();
}

module_init(nil_verifier_init);
module_exit(nil_verifier_exit);
MODULE_LICENSE("GPL");
