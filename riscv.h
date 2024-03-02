#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#define XLEN 32
typedef uint32_t xlenbits;

typedef xlenbits regtype;

typedef uint32_t inst_t;

#define ALIGN 8

#define MASK(n) ((1 << (n)) - 1)
#define get_bit(reg, b) ((reg) & 1 << (b))
#define get_bit2(reg, b) (((reg) >> b) & 0x3)
#define set_bit(reg, b) ((*(reg)) |= 1 << (b))
#define clear_bit(reg, b) ((*(reg)) &=~ (1 << (b)))
#define clear_bit2(reg, b) ((*(reg)) &=~ (0x3 << (b)))

static inline void copy_bit(xlenbits *reg, int b, bool val)
{
	if (val) {
		set_bit(reg, b);
	} else {
		clear_bit(reg, b);
	}
}

static inline void copy_bit2(xlenbits *reg, int b, int val)
{
	copy_bit(reg, b, val & 0x01);
	copy_bit(reg, b + 1, val & 0x02);
}

enum trap_type { TRAP_NONE, INTERRUPT, EXCEPTION };

enum interrupt_type { INTR_MACHINE_TIMER = 7 };

enum exception_type {
	EXC_NONE = -1,
	EXC_INST_ADDR_MISALIGNED = 0,
	EXC_INST_ACCESS_FAULT = 1,
	EXC_ILLEGAL_INST = 2,
	EXC_BREAKPOINT = 3,
	EXC_LOAD_ADDR_MISALIGNED = 4,
	EXC_LOAD_ACCESS_FAULT = 5,
	EXC_STORE_ADDR_MISALIGNED = 6,
	EXC_STORE_ACCESS_FAULT = 7,
	EXC_ECALL_FROM_U_MODE = 8,
	EXC_ECALL_FROM_S_MODE = 9,
	EXC_ECALL_FROM_M_MODE = 11,
};

typedef struct {
	xlenbits low, high;
} dword_t;

static inline void dword_inc(dword_t *val, xlenbits delta)
{
	xlenbits new = val->low + delta;
	if (new < val->low) {
		val->high++;
	}
	val->low = new;
}

static inline bool dword_cmp(dword_t a, dword_t b)
{
	return (a.high > b.high || (a.high == b.high && a.low > b.low));
}

static inline bool dword_is_zero(dword_t a)
{
	return a.low == 0 && a.high == 0;
}

enum priv { PRIV_USER = 0x00, PRIV_SUPERVISOR = 0x01, PRIV_MACHINE = 0x03 };

enum reg_name {
	R_zero = 0,
	R_ra = 1,
	R_sp = 2,
	R_gp = 3,
	R_tp = 4,
	R_t0 = 5,
	R_t1 = 6,
	R_t2 = 7,
	R_s0 = 8,
	R_fp = 8,
	R_s1 = 9,
	R_a0 = 10,
	R_a1 = 11,
	R_a2 = 12,
	R_a3 = 13,
	R_a4 = 14,
	R_a5 = 15,
	R_a6 = 16,
	R_a7 = 17,
	R_s2 = 18,
	R_s3 = 19,
	R_s4 = 20,
	R_s5 = 21,
	R_s6 = 22,
	R_s7 = 23,
	R_s8 = 24,
	R_s9 = 25,
	R_s10 = 26,
	R_s11 = 27,
	R_t3 = 28,
	R_t4 = 29,
	R_t5 = 30,
	R_t6 = 31,
};

struct inst {
	union {
		struct {
			xlenbits opcode:7;
			xlenbits rd:5;
			xlenbits funct3:3;
		} v;

		struct {
			xlenbits opcode:7;
			xlenbits rd:5;
			xlenbits funct3:3;
			xlenbits rs1:5;
			xlenbits imm:12;
		} I;

		struct {
			xlenbits opcode:7;
			xlenbits imm_11:1;
			xlenbits imm_1_4:4;
			xlenbits funct3:3;
			xlenbits rs1:5;
			xlenbits rs2:5;
			xlenbits imm_5_10:6;
			xlenbits imm_12:1;
		} B;

		struct {
			xlenbits opcode:7;
			xlenbits rd:5;
			xlenbits imm:20;
		} U;
		struct {
			xlenbits opcode:7;
			xlenbits rd:5;
			xlenbits imm_12_19:8;
			xlenbits imm_11:1;
			xlenbits imm_1_10:10;
			xlenbits imm_20:1;
		} J;
		struct {
			xlenbits opcode:7;
			xlenbits rd:5;
			xlenbits funct3:3;
			xlenbits rs1:5;
			xlenbits rs2:5;
			xlenbits funct7:7;
		} priv_R;
		struct {
			xlenbits opcode:7;
			xlenbits rd:5;
			xlenbits funct3:3;
			xlenbits rs1:5;
			xlenbits imm:12;
		} priv_I;
		struct {
			xlenbits opcode:7;
			xlenbits rd:5;
			xlenbits funct3:3;
			xlenbits rs1_uimm:5;
			xlenbits csr:12;
		} Zicsr;
	};
} __attribute__((packed));

static inline xlenbits sign_ext(xlenbits imm, int size) {
	return get_bit(imm, size-1) ? imm | ((1 << (XLEN - size)) - 1) << size : imm;
}

typedef union{
	struct {
		xlenbits UIE:1; // 0
		xlenbits SIE:1; // 1
		xlenbits :1;    // 2
		xlenbits MIE:1; // 3

		xlenbits UPIE:1; //4
		xlenbits SPIE:1; //5
		xlenbits :1;     // 6
		xlenbits MPIE:1; //7

		xlenbits SPP:1;  //8
		xlenbits VS:2;   //9-10
		xlenbits MPP:2;  //11-12
		xlenbits FS:2;   //13-14
		xlenbits XS:2;   //15-16
		xlenbits MPRV:1; //17
		xlenbits SUM:1;  //18
		xlenbits MXR:1;  //19
		xlenbits TVM:1;  //20
		xlenbits TW:1;   //21
		xlenbits TSR:1;  //22
		xlenbits :XLEN - 1 - 23; //
		xlenbits SD:1;   // XLEN - 1
	} __attribute__((packed));
	xlenbits bits;
} mstatus_t;

struct rvcore_rv32ima {
	regtype regs[32];

	xlenbits pc;
	
	dword_t cycle;
	dword_t timer, timermatch;

	mstatus_t mstatus;
	regtype mscratch;
	regtype mtvec;
	regtype mie;
	regtype mip;

	regtype mepc;
	regtype mtval;
	regtype mcause;

	enum priv priv;
	bool wfi;
	xlenbits reservation;

	// not used by os, information only
	regtype mvendorid;
	regtype misa;
	
} __attribute__((aligned(ALIGN)));

static inline void write_rd(struct rvcore_rv32ima *core, int rd, xlenbits val)
{
	if (rd) {
		assert(rd < XLEN);
		core->regs[rd] = val;
	}
		
}

struct system {
    struct rvcore_rv32ima *core;

	xlenbits ram_base;
	xlenbits ram_size;
    uint8_t *image;

    xlenbits (*read_csr)(struct system *sys, struct inst);
    void (*write_csr)(struct system *sys, struct inst, xlenbits val);
};

static inline xlenbits sys_ram_end(struct system *sys) {
	return sys->ram_base + sys->ram_size;
}

void sys_alloc_memory(struct system *sys, xlenbits base, xlenbits size);
void dump_sys(struct system *sys);

static inline bool check_interrupt(const struct rvcore_rv32ima *core, enum interrupt_type bit)
{
	return core->mstatus.MIE &&
	       get_bit(core->mip, bit) && get_bit(core->mie, bit);
}

void handle_trap(struct rvcore_rv32ima *core, xlenbits mcause, xlenbits mtval);
static inline void handle_interrupt(struct rvcore_rv32ima *core, enum interrupt_type bit)
{
	handle_trap(core, 1 << (XLEN - 1) | bit, 0);
}


xlenbits proc_inst_Zicsr(struct rvcore_rv32ima *core, struct inst inst, struct system *sys);
void proc_inst_wfi(struct rvcore_rv32ima *core, struct inst inst);
void proc_inst_mret(struct rvcore_rv32ima *core, struct inst inst);

