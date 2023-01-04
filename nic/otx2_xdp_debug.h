
#ifndef OTX2_XDP_DEBUG_H
#define OTX2_XDP_DEBUG_H

#if 0

struct bpf_offload_dev {
	const struct bpf_prog_offload_ops *ops;
	struct list_head netdevs;
	void *priv;
};

#endif

#define DUMP_bpf_offload_dev(a)				\
do {							\
	u8 *ptr = (u8 *)((a)->priv);			\
	pr_err("%p: ops=%p\n", a, (a)->ops);		\
	if ((a)->priv) {				\
		pr_err("priv= 0x%x 0x%x 0x%x 0x%x\n",	\
		ptr[0], ptr[1], ptr[2], ptr[3]);	\
	}						\
} while(0);

#if 0

struct bpf_prog_offload {
	struct bpf_prog		*prog;
	struct net_device	*netdev;
	struct bpf_offload_dev	*offdev;
	void			*dev_priv;
	struct list_head	offloads;
	bool			dev_state;
	bool			opt_failed;
	void			*jited_image;
	u32			jited_len;
};

#define DUMP_bpf_prog_offload(a)						\
do {										\
	struct nsim_bpf_bound_prog *state;					\
	state = (a)->dev_priv;							\
	pr_err("%p: prog=%p dev=%s dev_state=%d opt_failed=%d jited_len=%u\n",	\
	(a), (a)->prog, (a)->netdev->name, (a)->dev_state,			\
	(a)->opt_failed, jited_len);						\
	pr_err("prog=%p state=%s is_loaded=%d\n",				\
		state->prog, state->state, state->is_loaded);			\
	if ((a)->jited_image) {							\
		pr_err("jited image 0x%x 0x%x 0x%x 0x%x\n",(a)->jited_image[0], \
		(a)->jited_image[1], (a)->jited_image[2], (a)->jited_image[3]);	\
	}									\
while(0);

#endif

#if 0

#endif

#if 0
struct bpf_prog_aux {
	atomic_t refcnt;
	u32 used_map_cnt;
	u32 max_ctx_offset;
	u32 max_pkt_offset;
	u32 max_tp_access;
	u32 stack_depth;
	u32 id;
	u32 func_cnt; /* used by non-func prog as the number of func progs */
	u32 func_idx; /* 0 for non-func prog, the index in func array for func prog */
	bool verifier_zext; /* Zero extensions has been inserted by verifier. */
	bool offload_requested;
	struct bpf_prog **func;
	void *jit_data; /* JIT specific data. arch dependent */
	struct latch_tree_node ksym_tnode;
	struct list_head ksym_lnode;
	const struct bpf_prog_ops *ops;
	struct bpf_map **used_maps;
	struct bpf_prog *prog;
	struct user_struct *user;
	u64 load_time; /* ns since boottime */
	struct bpf_map *cgroup_storage[MAX_BPF_CGROUP_STORAGE_TYPE];
	char name[BPF_OBJ_NAME_LEN];
#ifdef CONFIG_SECURITY
	void *security;
#endif
	struct bpf_prog_offload *offload;
	struct btf *btf;
	struct bpf_func_info *func_info;
	/* bpf_line_info loaded from userspace.  linfo->insn_off
	 * has the xlated insn offset.
	 * Both the main and sub prog share the same linfo.
	 * The subprog can access its first linfo by
	 * using the linfo_idx.
	 */
	struct bpf_line_info *linfo;
	/* jited_linfo is the jited addr of the linfo.  It has a
	 * one to one mapping to linfo:
	 * jited_linfo[i] is the jited addr for the linfo[i]->insn_off.
	 * Both the main and sub prog share the same jited_linfo.
	 * The subprog can access its first jited_linfo by
	 * using the linfo_idx.
	 */
	void **jited_linfo;
	u32 func_info_cnt;
	u32 nr_linfo;
	/* subprog can use linfo_idx to access its first linfo and
	 * jited_linfo.
	 * main prog always has linfo_idx == 0
	 */
	u32 linfo_idx;
	struct bpf_prog_stats __percpu *stats;
	union {
		struct work_struct work;
		struct rcu_head	rcu;
	};
};

#endif

#define DUMP_bpf_prog_aux(a)						\
do {									\
	pr_err("%p: id=%u offload_requested=%u\n",			\
	a, (a)->id, (a)->offload_requested);				\
	pr_err("prog=%p name=%s\n", (a)->prog, (a)->name);		\
} while (0);

#if 0

struct sock_filter {	/* Filter block */
	__u16	code;   /* Actual filter code */
	__u8	jt;	/* Jump true */
	__u8	jf;	/* Jump false */
	__u32	k;      /* Generic multiuse field */
};

#endif

#define DUMP_sock_filter(a)				\
do {							\
	pr_err("%p: code=0x%x jt=%d jf=%d k=%u\n",	\
	a, (a)->code, (a)->jt, (a)->jf, (a)->k);	\
} while (0);

#if 0
struct bpf_insn {
	__u8	code;		/* opcode */
	__u8	dst_reg:4;	/* dest register */
	__u8	src_reg:4;	/* source register */
	__s16	off;		/* signed offset */
	__s32	imm;		/* signed immediate constant */
};
#endif

#define DUMP_bpf_insn(a)							\
do {										\
	pr_err("%p: code=0x%x dst_reg=0x%x src_reg=0x%x off=0x%x imm=0x%x\n",	\
	a, (a)->code, (a)->dst_reg, (a)->src_reg, (a)->off, (a)->imm);		\
} while (0);

#if 0
struct bpf_prog {
        u16                     pages;          /* Number of allocated pages */
        u16                     jited:1,        /* Is our filter JIT'ed? */
                                jit_requested:1,/* archs need to JIT the prog */
                                gpl_compatible:1, /* Is filter GPL compatible? */
                                cb_access:1,    /* Is control block accessed? */
                                dst_needed:1,   /* Do we need dst entry? */
                                blinded:1,      /* Was blinded */
                                is_func:1,      /* program is a bpf function */
                                kprobe_override:1, /* Do we override a kprobe? */
                                has_callchain_buf:1, /* callchain buffer allocated? */
                                enforce_expected_attach_type:1; /* Enforce expected_attach_type checking at attach time */
        enum bpf_prog_type      type;           /* Type of BPF program */
        enum bpf_attach_type    expected_attach_type; /* For some prog types */
        u32                     len;            /* Number of filter blocks */
        u32                     jited_len;      /* Size of jited insns in bytes */
        u8                      tag[BPF_TAG_SIZE];
        struct bpf_prog_aux     *aux;           /* Auxiliary fields */
        struct sock_fprog_kern  *orig_prog;     /* Original BPF program */
        unsigned int            (*bpf_func)(const void *ctx,
                                            const struct bpf_insn *insn);
        /* Instructions for interpreter */
        union {
                struct sock_filter      insns[0];
                struct bpf_insn         insnsi[0];
        };
};
#endif

#define DUMP_bpf_prog(a)							\
do {										\
	u32 iter = 0, *ptr;							\
	struct bpf_insn	*ins;							\
	pr_err("%p: Pages=%d jited=%d jit_requested=%d gpl_compatible=%d"	\
		 " cb_accesd=%d dst_needed=%d blinded=%d is_func=%d\n",		\
	a, (a)->pages, (a)->jited, (a)->jit_requested, (a)->gpl_compatible,	\
	(a)->cb_access, (a)->dst_needed, (a)->blinded, (a)->is_func);		\
	pr_err("kprobe_override=%d has_callchain_buf=%d"			\
	" enforce_expected_attach_type=%d\n",					\
	(a)->kprobe_override, (a)->has_callchain_buf,				\
	(a)->enforce_expected_attach_type);					\
	pr_err("type=%u expected_attach_type=%u len=%u jited_len=%u\n",		\
	(a)->type, (a)->expected_attach_type, (a)->len, (a)->jited_len);	\
	pr_err("Jited ins\n");							\
	pr_err("\n Jitted program \n");						\
	ptr = (u32 *)((a)->bpf_func);						\
	for (iter = 0; iter < (a)->jited_len / 4; iter++) {			\
		pr_err("%02d: 0x%08x\n", iter, htonl(*ptr++));				\
	}									\
	pr_err("\n BPF program \n");						\
	ins = (a)->insnsi;							\
	for (iter = 0; iter < (a)->len; iter++, ins++)	 {			\
		pr_err("%d :",  iter);						\
		DUMP_bpf_insn(ins);						\
	}									\
} while(0);

#if 0
struct netdev_bpf {
	enum bpf_netdev_command command;
	union {
		/* XDP_SETUP_PROG */
		struct {
			u32 flags;
			struct bpf_prog *prog;
			struct netlink_ext_ack *extack;
		};
		/* XDP_QUERY_PROG, XDP_QUERY_PROG_HW */
		struct {
			u32 prog_id;
			/* flags with which program was installed */
			u32 prog_flags;
		};
		/* BPF_OFFLOAD_MAP_ALLOC, BPF_OFFLOAD_MAP_FREE */
		struct {
			struct bpf_offloaded_map *offmap;
		};
		/* XDP_SETUP_XSK_UMEM */
		struct {
			struct xdp_umem *umem;
			u16 queue_id;
		} xsk;
	};
};
#endif

#define DUMP_netdev_bpf(a)								\
do {											\
		pr_err("%p: command %u, flags=0x%x prog=%p id=%d id_flags=0x%x", a,	\
		(a)->command, (a)->flags, (a)->prog, (a)->prog_id, (a)->prog_flags);	\
while(0);
#endif  /* G_H */
