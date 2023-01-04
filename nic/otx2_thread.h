#ifndef OTX2_THREAD_H_
#define OTX2_THREAD_H_

typedef int (*func_ptr_t)(u8 *pkt);
struct tinfo {
	struct task_struct *t;
	func_ptr_t func;
	struct list_head list;
	char tname[40];
	void *mem;
	int sz;
	bool ended;
};

int otx2_thread_init (void);
void otx2_thread_cleanup(void);
int otx2_thread_start_prog(struct tinfo *tinfo, int jited_len);
struct tinfo *otx2_thread_get_free_tinfo(void);

#endif /* OTX2_THREAD_H_ */
