#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <khook/engine.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/local.h>
#include <asm/irq_vectors.h>
#include <asm/set_memory.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/mwait.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/capability.h>
#include <linux/cdev.h>
#include <linux/cpuidle.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/sort.h>
#include <linux/moduleparam.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/smp.h>
#include <linux/uaccess.h>
#include <linux/signal.h>


#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_verifier.h>


KHOOK_EXT(int, do_check, struct bpf_verifier_env *);
static int khook_do_check(struct bpf_verifier_env *env)
{
	printk("Inside do check!");
	return 0;
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
