#include <linux/netdevice.h>
#include <linux/filter.h>
#include <linux/proc_fs.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include "otx2_common.h"
#include "otx2_xdp_debug.h"
#include "otx2_thread.h"
#include "otx2_xdp.h"
#include "otx2_bpf.h"

static struct proc_dir_entry *proc_entry;

struct otx2_xdp_t {
	struct net_device *pma_dev;
	/* Goblal mutex.
	 */
	struct mutex mutex;
};

struct otx2_xdp_t otx2_xdp_gbl = {
	.pma_dev = NULL,
	.mutex = __MUTEX_INITIALIZER(otx2_xdp_gbl.mutex),
};

enum oxt2_insn_flag {
	OTX2_INSN_FLAG_SUBPROG_START = BIT_ULL(0),
	OTX2_INSN_FLAG_JMP_DST = BIT_ULL(1),
	OTX2_INSN_FLAG_VERIFIER = BIT_ULL(2),
	OTX2_INSN_FLAG_FIXUP_INSN = BIT_ULL(3),
};

void oxt2_bpf_cp_arch_ctx2mem(struct otx2_bpf_arch_ctx *ctx, u32 *exec_mem, int *offset)
{
	int idx = *offset;
	int i;

	ctx->offset = idx;

	for (i = 0; i < ctx->bpf2bi_cnt; i++, idx++) {
		exec_mem[idx] = ctx->bi[i];
	}

	*offset = idx;
}

void otx2_print_arch_insn(struct otx2_bpf_prog *obp, u32 *exec_mem)
{
	struct otx2_bpf_arch_ctx *ctx;
	struct otx2_bpf_insn *insn;
	int off = 0;
	int i;

	pr_err("prologue\n");
	ctx = &obp->prologue;
	for ( i = 0; i < ctx->bpf2bi_cnt; i++, off++) {
		pr_err("0x%04x  off=%d\n", ntohl(exec_mem[off]), off);
	}

	pr_err("Body \n");

	list_for_each_entry(insn, &obp->lhead, list) {

		ctx = &insn->ctx;
		for (i = 0; i < ctx->bpf2bi_cnt; i++, off++) {
			pr_err("0x%04x idx=%d off=%d\n", ntohl(exec_mem[off]), insn->idx, off);
		}
		pr_err("\n");
	}

	pr_err("epilogue\n");
	ctx = &obp->epilogue;
	for ( i = 0; i < ctx->bpf2bi_cnt; i++, off++) {
		pr_err("0x%4x off=%d\n", ntohl(exec_mem[off]), off);
	}

	pr_err("offset = %d obp->offset=%d\n", off, obp->jited_len);
}

void otx2_prog_pass(struct otx2_bpf_prog *obp,  u32 *exec_mem)
{
	struct otx2_bpf_insn *insn;
	struct otx2_bpf_arch_ctx *ctx;
	int offset = 0;
	ctx = &obp->prologue;

	oxt2_bpf_cp_arch_ctx2mem(ctx, exec_mem, &offset);

	/* Another pass to record jump information. */
	list_for_each_entry(insn, &obp->lhead, list) {
		build_insn(&insn->insn, &insn->ctx, false, (u64)exec_mem, obp);
		oxt2_bpf_cp_arch_ctx2mem(&insn->ctx, exec_mem, &offset);
	}

	ctx = &obp->epilogue;
	oxt2_bpf_cp_arch_ctx2mem(ctx, exec_mem, &offset);
	obp->jited_len = offset * 4;

	pr_err("Second pass\n");

	/* now do second pass to do fixup */
	list_for_each_entry(insn, &obp->lhead, list) {
		int tmp;

		if (!(insn->flags & OTX2_INSN_FLAG_FIXUP_INSN)) {
			continue;
		}

		tmp = insn->ctx.offset;
		memset(&insn->ctx, 0, sizeof(struct otx2_bpf_arch_ctx));

		build_insn(&insn->insn, &insn->ctx, true, (u64)exec_mem, obp);
		oxt2_bpf_cp_arch_ctx2mem(&insn->ctx, exec_mem, &tmp);
	}

}

/**
 * oxt2_is_hw_prog_active - Checks if Hw program is already set
 */
bool oxt2_is_hw_prog_active(struct net_device *dev)
{
	struct otx2_nic *pf = netdev_priv(dev);
	return !!pf->xdp_hw.attach_info.prog;
}

static int otx2_verify_insn(struct bpf_verifier_env *env,
			    int insn_idx, int prev_insn_idx)
{
	return 0;
}

static int otx2_bpf_finalize(struct bpf_verifier_env *env)
{
	return 0;
}

static int otx2_bpf_opt_replace_insn(struct bpf_verifier_env *env,
				     u32 off, struct bpf_insn *insn)
{
	return 0;
}

static int otx2_bpf_opt_remove_insns(struct bpf_verifier_env *env,
				     u32 off, u32 cnt)
{
	struct otx2_bpf_prog *obp = env->prog->aux->offload->dev_priv;
	struct bpf_insn_aux_data *aux_data = env->insn_aux_data;
	struct otx2_bpf_insn *insn;
	unsigned int idx = aux_data[off].orig_idx;
	int i;

	insn = &obp->obins[idx];

	for (i = 0; i < cnt; i++, insn++) {

		/* doesn't count if it already has the flag */
		if (insn->flags & OTX2_INSN_FLAG_VERIFIER)
			i--;

		insn->flags |= OTX2_INSN_FLAG_VERIFIER;
		list_del_init(&insn->list);
	}

	return 0;
}

struct otx2_bpf_insn *otx2_bpf_get_insn(struct otx2_bpf_insn *insn, int n)
{
	while (n-- && insn) {
		insn = list_next_entry(insn, list);
	}

	return insn;
}

int otx2_bpf_mark_jmp_insn(struct otx2_bpf_prog *obp)
{
	struct otx2_bpf_insn *insn;

	/* Another pass to record jump information. */
	list_for_each_entry(insn, &obp->lhead, list) {
		struct otx2_bpf_insn *dst_insn;

		u64 code = insn->insn.code;
		u8 class = BPF_CLASS(code);
		unsigned int dst_idx;

		if (class != BPF_JMP &&
		    class != BPF_JMP32)
			continue;

		if (BPF_OP(code) == BPF_EXIT) {
			insn->flags |= OTX2_INSN_FLAG_FIXUP_INSN;
			continue;
		}

		/* if helper call; skip
		 */
		if (code == (BPF_JMP | BPF_CALL) &&
		    insn->insn.src_reg != BPF_PSEUDO_CALL) {
			pr_err("insn->insn.imm= 0x%x BPF_FUNC_map_lookup_elem=0x%x\n",
					insn->insn.imm, BPF_FUNC_map_lookup_elem);

			if (insn->insn.imm == BPF_FUNC_map_lookup_elem) {
				pr_err("it is matching BPF_FUNC_map_lookup_elem\n");
			}

			continue;
		}

		if (BPF_OP(code) == BPF_CALL)
			dst_idx = insn->idx + 1 + insn->insn.imm;
		else
			/* JMP instructions
			 */
			dst_idx = insn->idx + 1 + insn->insn.off;

		if (dst_idx >= obp->bpf_prog->len) {
			pr_err("%s: JMP to an invalid idx=%d, len=%d\n",
			       __func__, dst_idx, obp->bpf_prog->len);
			return -EINVAL;
		}

		dst_insn = otx2_bpf_get_insn(insn, dst_idx - insn->idx);
		insn->to_jmp = dst_insn;

		pr_err("Jumping from insn->idx=%d to dst_ins->idx=%d\n",
		       insn->idx, dst_insn->idx);

		if (BPF_OP(code) == BPF_CALL) {
			insn->flags |= OTX2_INSN_FLAG_FIXUP_INSN;
			dst_insn->flags |= OTX2_INSN_FLAG_SUBPROG_START;
			continue;
		}

		/* code is jmp
		 */
		dst_insn->flags |= OTX2_INSN_FLAG_JMP_DST;
	}

	return 0;
}

static int  otx2_bpf_prepare_ins_list(struct bpf_prog *prog)
{
	struct otx2_bpf_prog *obp = kzalloc(sizeof(*obp), GFP_KERNEL);
	struct otx2_bpf_insn *dst;
	struct bpf_insn *src;
	int err, i;

	if (!obp) {
		pr_err("%s: unable to allocate memory for oxt2_prog\n",
		       __func__);
		err = -ENOMEM;
		goto fail_otx2_prog;
	}

	obp->bpf_prog = prog;
	obp->jited = false;
	obp->jited_len = 0;
	mutex_init(&obp->mutex);
	INIT_LIST_HEAD(&obp->lhead);

	obp->obins = kzalloc(sizeof(struct otx2_bpf_insn) * prog->len, GFP_KERNEL);
	if (!obp->obins) {
		err = -ENOMEM;
		goto fail_insn_mem;
	}

	dst = obp->obins;
	src = prog->insnsi;
	for (i = 0; i < prog->len; i++, src++, dst++) {
		dst->insn = *src;
		list_add_tail(&dst->list, &obp->lhead);
		dst->idx = i;
	}

	prog->aux->offload->dev_priv = obp;

	return 0;

fail_insn_mem:
	kfree(obp);

fail_otx2_prog:
	return err;

}

static int otx2_bpf_verifier_prep(struct bpf_prog *prog)
{
	return otx2_bpf_prepare_ins_list(prog);
}

void otx2_print_insn_ctx(struct otx2_bpf_arch_ctx *ctx, const char *func)
{
	int i;
	pr_err(" ++++ %s +++ \n", func);

	for (i = 0; i < ctx->bpf2bi_cnt; i++) {
		pr_err("0x%4x\n", ntohl(ctx->bi[i]));
	}

}

static int otx2_bpf_translate(struct bpf_prog *prog)
{

#if 0
	int err = bpf_prog_alloc_jited_linfo(prog);
	struct bpf_prog_aux *aux = prog->aux;
	int i;
#endif
	int err;
	struct otx2_bpf_prog *obp;

	obp = prog->aux->offload->dev_priv;

	err = otx2_bpf_mark_jmp_insn(obp);
	if (err) {
		pr_err("Error during marking\n");
		return -EINVAL;
	}

#if 0

	exec_mem = kzalloc(sizeof(PAGE_SIZE), GFP_KERNEL);
	if (err)
		return err;
#endif

	build_prologue(&obp->prologue, prog);
	build_epilogue(&obp->epilogue, prog);
	return 0;

#if 0

	prog = bpf_int_jit_compile(prog);
	if (!prog->jited) {
		bpf_prog_free_jited_linfo(prog);
#ifdef CONFIG_BPF_JIT_ALWAYS_ON
		return -ENOTSUPP;
#endif
	} else {
		bpf_prog_free_unused_jited_linfo(prog);
	}
	bpf_prog_lock_ro(prog);

	//	err = bpf_check_tail_call(prog);

	for (i = 0; i < aux->used_map_cnt; i++) {
		struct bpf_map *map = aux->used_maps[i];
		struct bpf_array *array;

		if (maobp->map_type != BPF_MAP_TYPE_PROG_ARRAY)
			continue;

		array = container_of(map, struct bpf_array, map);
		if (!bpf_prog_array_compatible(array, prog))
			return -EINVAL;
	}
#endif

}

static void otx2_bpf_destroy(struct bpf_prog *prog)
{

}

const struct bpf_prog_offload_ops otx2_bpf_dev_ops = {
	.insn_hook	= otx2_verify_insn,
	.finalize	= otx2_bpf_finalize,
	.replace_insn	= otx2_bpf_opt_replace_insn,
	.remove_insns	= otx2_bpf_opt_remove_insns,
	.prepare	= otx2_bpf_verifier_prep,
	.translate	= otx2_bpf_translate,
	.destroy	= otx2_bpf_destroy,
};

#define BUFSIZE 50
char name[BUFSIZE];

static ssize_t otx2_xdp_proc_write(struct file *file,
				   const char __user *buf, size_t count, loff_t *ppos)
{
	struct otx2_nic *pf;
	struct npc_disable_entry_req *req;
	struct net_device *dev;
	int err;

	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;

	if(copy_from_user(name, buf, count))
		return -EFAULT;

	name[count - 1] = 0;

	dev = dev_get_by_name(&init_net, name);
	if (!dev) {
		pr_err("No netdev by name %s\n", name);
		return -EFAULT;
	}
	/* Holding ref  ? */
	dev_put(dev);

	pf = netdev_priv(dev);
	mutex_lock(&pf->mbox.lock);

	/* Disable npc entries of pma dev */
	req = otx2_mbox_alloc_msg_npc_disable_entry(&pf->mbox);
	if (!req) {
		mutex_unlock(&pf->mbox.lock);
		return -ENOMEM;
	}
	req->npcifunc = pf->pcifunc;
	err = otx2_sync_mbox_msg(&pf->mbox);
	if (err) {
		mutex_unlock(&pf->mbox.lock);
		pr_err("Disabling pmadev npc failed\n");
		return -EFAULT;
	}

	mutex_unlock(&pf->mbox.lock);
	otx2_xdp_gbl.pma_dev = dev;

	return count;
}

static ssize_t otx2_xdp_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	int len=0;
	char my_buf[BUFSIZE];

	if(*ppos > 0 || count < BUFSIZE)
		return 0;

	len += sprintf(my_buf, "%s", name);

	if(copy_to_user((void *)buf, name, len))
		return -EFAULT;

	*ppos = len;
	return len;
}

static const struct file_operations otx2_xdp_proc_ops = {
	.write   = otx2_xdp_proc_write,
	.read =  otx2_xdp_proc_read,
};

void otx2_xdp_proc_create(void)
{
	proc_entry = proc_create("pma", 0644, NULL, &otx2_xdp_proc_ops);
}

/**
 * otx2_xdp_offload_dev_unregister - Un register offload dev
 */
void otx2_xdp_offload_dev_unregister(struct net_device *dev)
{
	struct bpf_offload_dev *bpf_dev;
	struct otx2_nic *pf = netdev_priv(dev);

	bpf_dev = pf->xdp_hw.bpf_dev;

	if (!!bpf_dev) {
		pr_err("%s: No offload device found for %s\n", __func__, dev->name);
		return;
	}

	bpf_offload_dev_netdev_unregister(bpf_dev, dev);
	bpf_offload_dev_destroy(bpf_dev);
}

/**
 * otx2_xdp_offload_dev_register -  register offload dev
 */
int otx2_xdp_offload_dev_register(struct net_device *dev)
{
	struct bpf_offload_dev *bpf_dev;
	struct otx2_nic *pf = netdev_priv(dev);

	bpf_dev = bpf_offload_dev_create(&otx2_bpf_dev_ops, &otx2_xdp_gbl);
	if (!bpf_dev) {
		pr_err("%s: offload dev creation failed\n", __func__);
		return -ENOMEM;
	}
	pf->xdp_hw.bpf_dev = bpf_dev;

	return 0;

	return bpf_offload_dev_netdev_register(bpf_dev, dev);
}

/**
 * otx2_setup_hw_xdp - sets up xdp on to HW
 */
int otx2_setup_hw_xdp(struct net_device *dev, struct netdev_bpf *bpf)
{
#if 0
	struct otx2_nic *npf = netdev_priv(dev);
	struct otx2_nic *pmapf = netdev_priv(otx2_xdp_gbl.pma_dev);
	struct npc_update_action_req *req;
#endif
	struct tinfo *tinfo;
	struct net_device *lbk1_dev;
	struct otx2_bpf_prog *obp;
	struct otx2_nic *pf;
	u16 lbk1_pfunc;

	if (!bpf->prog)
		return 0;

	obp = bpf->prog->aux->offload->dev_priv;

	DUMP_bpf_prog(bpf->prog);

	DUMP_bpf_prog_aux(bpf->prog->aux);

	if (!bpf->prog->aux->offload) {
		NL_SET_ERR_MSG_MOD(bpf->extack, "xdpoffload of non-bound program");
		return -EINVAL;
	}

	if (!bpf_offload_dev_match(bpf->prog, dev)) {
		NL_SET_ERR_MSG_MOD(bpf->extack, "program bound to different dev");
		return -EINVAL;
	}

#if 0
	/* did not allocate a offload dev */
	state = bpf->prog->aux->offload->dev_priv;
	if (WARN_ON(strcmp(state->state, "xlated"))) {
		NL_SET_ERR_MSG_MOD(bpf->extack, "offloading program in bad state");
		return -EINVAL;
	}
#endif
	if (!otx2_xdp_gbl.pma_dev) {
		NL_SET_ERR_MSG_MOD(bpf->extack, "PMA dev is not configured yet");
		return -EINVAL;
	}

	lbk1_dev = dev_get_by_name(&init_net, "lbk1");
	if (!lbk1_dev) {
		pr_err("No netdev by name lkb1\n");
		return -EINVAL;
	}
	pf = netdev_priv(lbk1_dev);
	lbk1_pfunc =  pf->pcifunc;
	dev_put(lbk1_dev);

	if (pf->xdp_hw.npc_configured)
		goto copy_prog;

#if 0

	mutex_lock(&pf->mbox.lock);

	req = otx2_mbox_alloc_msg_npc_update_action(&pf->mbox);
	if (!req) {
		mutex_unlock(&pf->mbox.lock);
		return -ENOMEM;
	}

	/* Modify xdp netdevice's action pcifunc to pma netdev */
	req->npcifunc = pmapf->pcifunc;
	req->opcifunc =  npf->pcifunc;

	pr_err("Modiy NPC pcifunc from 0x%x(%s) to 0x%x(%s)\n",
	       npf->pcifunc, dev->name, pmapf->pcifunc, otx2_xdp_gbl.pma_dev->name);

	err = otx2_sync_mbox_msg(&pf->mbox);
	if (err) {
		pr_err("Setting req->opcifunc=0x%x to  req->npcifunc=0x%x failed\n",
		       req->opcifunc, req->npcifunc);
		mutex_unlock(&pf->mbox.lock);
		return -EFAULT;
	}

	req = otx2_mbox_alloc_msg_npc_update_action(&pf->mbox);
	if (!req) {
		mutex_unlock(&pf->mbox.lock);
		return -ENOMEM;
	}

	/* Modify lbk1 device's action pcifunc to xdp netdev */
	req->npcifunc = npf->pcifunc;
	req->opcifunc =  lbk1_pfunc;
	pr_err("Modiy NPC pcifunc from 0x%x(%s) to 0x%x(%s)\n",
	       lbk1_pfunc, lbk1_dev->name, npf->pcifunc, dev->name);

	err = otx2_sync_mbox_msg(&pf->mbox);
	if (err) {
		pr_err("Setting req->opcifunc=0x%x to  req->npcifunc=0x%x failed\n",
		       req->opcifunc, req->npcifunc);
		mutex_unlock(&pf->mbox.lock);
		return -EFAULT;
	}

	mutex_unlock(&pf->mbox.lock);

	pf->xdp_hw.npc_configured = true;
#endif

copy_prog:

	tinfo = otx2_thread_get_free_tinfo();
	if (!tinfo) {
		pr_err("No free thread available\n");
		return 0;
	}

	otx2_prog_pass(obp, (u32 *)tinfo->mem);
	otx2_print_arch_insn(obp, (u32 *)tinfo->mem);

	pr_err("tinfo->mem=%pK\n", tinfo->mem);

//	otx2_thread_start_prog(tinfo, obp->jited_len);

	xdp_attachment_setup(&pf->xdp_hw.attach_info, bpf);

	return 0;
}
