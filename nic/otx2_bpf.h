
#ifndef OTX2_BPF_H_
#define OTX2_BPF_H_

struct otx2_bpf_arch_ctx {
	u32 bi[16];
	u8 bpf2bi_cnt;
	u32 offset;
};

struct otx2_bpf_insn {
	struct otx2_bpf_arch_ctx ctx;
	struct otx2_bpf_insn *to_jmp;
	struct list_head list;
	struct bpf_insn insn;
	u64 flags;
	int idx;
};

struct otx2_bpf_prog {
	struct otx2_bpf_arch_ctx epilogue;
	struct otx2_bpf_arch_ctx prologue;
	struct otx2_bpf_insn *obins;
	struct bpf_prog *bpf_prog;
	struct list_head lhead;
	struct mutex mutex;
	int jited_len;
	bool jited;
};

int build_prologue(struct otx2_bpf_arch_ctx *ctx, struct bpf_prog *prog);
void build_epilogue(struct otx2_bpf_arch_ctx *ctx, struct bpf_prog *prog);
int build_insn(const struct bpf_insn *insn, struct otx2_bpf_arch_ctx *ctx,
		      bool extra_pass, u64 img_addr, struct otx2_bpf_prog *p);

#endif /* OTX2_BPF_H_ */
