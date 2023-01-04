#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/vmalloc.h>
#include <asm/pgtable.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include "otx2_thread.h"

static LIST_HEAD(tinfo_lh);
static atomic_t tnum;
static DEFINE_SPINLOCK(tinfo_lock);
static struct proc_dir_entry *proc_entry;

static u8 sample_pkt[256];

struct tinfo *otx2_thread_get_free_tinfo(void)
{
	struct tinfo *iter;
	list_for_each_entry(iter, &tinfo_lh, list) {
		if (!iter->ended) {
			continue;
		}

		iter->ended = false;
		/* clear prog */
		memset(iter->mem, 0, iter->sz);
		return iter;
	}
	return NULL;
}

static int otx2_thread_fn(void *data)
{
	struct tinfo *info = data;
	func_ptr_t func;
	int ret;

	while (!kthread_should_stop()) {

		func = info->func;
		if (!func) {
			schedule();
			continue;
		}
		xchg(&info->func, 0);

		ret = func(sample_pkt);
		info->ended = true;
		pr_err("ret from %s : 0x%x\n", info->tname, ret);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}

	return 0;
}

static u32 sample_code_01[] __maybe_unused = {
	0xd503201f,  /* NOP */
	0xd503201f,  /* NOP */
	0x52999980,    /* move w0, 0xcccc	  */
	0xd65f03c0,    /* RET */
};

static u32 sample_code_02[] __maybe_unused = {
	0xd503201f,  /* NOP */
	0xd503201f,  /* NOP */
	0x529dddc0,
	0xd65f03c0,    /* RET */
};

static u32 sample_code_03[] __maybe_unused = {
	0xd503201f,  /* NOP */
	0xd503201f,  /* NOP */
	0x529fffe0,
	0xd65f03c0,    /* RET */
};

static int otx2_thread_tinfo_alloc(void)
{
	struct tinfo *info;

	/* Allocate */
	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		pr_info("No memory for task info\n");
		return -ENOMEM;
	}
	memset(info, 0, sizeof(*info));

	/* Initialize */
	info->t = current;
	INIT_LIST_HEAD(&info->list);

	info->mem = __vmalloc(PAGE_SIZE, GFP_KERNEL, PAGE_KERNEL_EXEC);
	if (!info->mem) {
		pr_info("No memory for program memory\n");
		return -ENOMEM;
	}

	info->ended = true;

	/* Add to list */
	spin_lock(&tinfo_lock);
	list_add_tail(&info->list, &tinfo_lh);
	spin_unlock(&tinfo_lock);

	snprintf(info->tname, sizeof(info->tname), "thread%d", atomic_inc_return(&tnum));
	info->t = kthread_create(otx2_thread_fn, info, info->tname);

	/* Thread throws "task thread2:291 blocked for more than 362 seconds."
	 * avoid by waking up once
	 */
	wake_up_process(info->t);

	return 0;
}

int otx2_thread_start_prog(struct tinfo *tinfo, int jited_len)
{
	tinfo->sz = jited_len;
	tinfo->func = tinfo->mem;

	wake_up_process(tinfo->t);
	return 0;
}

static ssize_t otx2_thread_proc_write(struct file *file,
				      const char __user *buf, size_t count, loff_t *ppos)
{
//	otx2_thread_set_prog((u8 *)sample_code_03, sizeof(sample_code_03));
	return count;
}

static const struct file_operations otx2_thread_proc_ops = {
	.write   = otx2_thread_proc_write,
};

int otx2_thread_init(void)
{
	int ret;
	ret = otx2_thread_tinfo_alloc();
	if (ret) {
		pr_err("Thread1 alloc failed\n");
		return 0;
	}

	proc_entry = proc_create("execute-prog", 0644, NULL, &otx2_thread_proc_ops);
	return 0;
}

void otx2_thread_cleanup(void)
{
	struct tinfo *iter;

	while (!list_empty(&tinfo_lh)) {
		iter  = list_entry(tinfo_lh.next, struct tinfo, list);
		pr_info("Trying to stop thread %s\n", iter->tname);
		wake_up_process(iter->t);
		kthread_stop(iter->t);

		spin_lock(&tinfo_lock);
		list_del_init(&iter->list);
		spin_unlock(&tinfo_lock);

		msleep(1);
		pr_info("Deleted thread %s\n", iter->tname);
		vfree(iter->mem);
		kfree(iter);
		continue;
	}

	proc_remove(proc_entry);
}
