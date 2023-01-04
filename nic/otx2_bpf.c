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

enum oxt2_bpf_insn_flag {
	OTX2_BPF_INSN_FLAG_SUBPROG_START = BIT_ULL(0),
	OTX2_BPF_INSN_FLAG_JMP_DST = BIT_ULL(1),
	OTX2_BPF_INSN_FLAG_VERIFIER = BIT_ULL(2),
	OTX2_BPF_INSN_FLAG_FIXUP_INSN = BIT_ULL(3),
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

void otx2_bpf_print_arch_insn(struct otx2_bpf_prog *obp, u32 *exec_mem)
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

void otx2_bpf_prog_pass(struct otx2_bpf_prog *obp,  u32 *exec_mem)
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

		if (!(insn->flags & OTX2_BPF_INSN_FLAG_FIXUP_INSN)) {
			continue;
		}

		tmp = insn->ctx.offset;
		memset(&insn->ctx, 0, sizeof(struct otx2_bpf_arch_ctx));

		build_insn(&insn->insn, &insn->ctx, true, (u64)exec_mem, obp);
		oxt2_bpf_cp_arch_ctx2mem(&insn->ctx, exec_mem, &tmp);
	}

}
