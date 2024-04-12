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


static int __init khello_init(void)
{
	printk("Hello from kernel\n");
	return 0;
}

static void __exit khello_exit(void)
{
	printk("Goodby from the kernel\n");
}

module_init(khello_init);
module_exit(khello_exit);
MODULE_LICENSE("GPL");
