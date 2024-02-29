#include <stdint.h>
#include <stdbool.h>

typedef uint32_t word_t;
typedef uint32_t inst_t;

#define ALIGN 8

#define MASK(n) ((1 << (n)) - 1)
#define get_bit(reg, b) ((reg) & 1 << (b))
#define get_bit2(reg, b) (((reg) << b) & 0x03)
#define set_bit(reg, b) ((*(reg)) |= 1 << (b))
#define clear_bit(reg, b) ((*(reg)) &=~ 1 << (b))

static inline void copy_bit(word_t *reg, int b, bool val)
{
	if (val) {
		set_bit(reg, b);
	} else {
		clear_bit(reg, b);
	}
}

static inline void copy_bit2(word_t *reg, int b, int val)
{
	copy_bit(reg, b, val & 0x01);
	copy_bit(reg, b, val & 0x02);
}

enum mstatus { MSTATUS_MIE = 3, MSTATUS_MPIE = 7, MSTATUS_MPP = 11 };

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
	word_t low, high;
} dword_t;

static inline void dword_inc(dword_t *val, word_t delta)
{
	word_t new = val->low + delta;
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
			word_t opcode:7;
			word_t rd:5;
			word_t funct3:3;
		} v;
		struct {
			word_t opcode:7;
			word_t rd:5;
			word_t funct3:3;
			word_t rs1:5;
			word_t rs2:5;
			word_t funct7:7;
		} priv_R;
		struct {
			word_t opcode:7;
			word_t rd:5;
			word_t funct3:3;
			word_t rs1:5;
			word_t imm:12;
		} priv_I;
		struct {
			word_t opcode:7;
			word_t rd:5;
			word_t funct3:3;
			word_t rs1_uimm:5;
			word_t csr:12;
		} Zicsr;
	};
} __attribute__((packed));

struct rvcore_rv32ima {
	uint32_t regs[32];

	uint32_t pc;
	uint32_t mstatus;
	dword_t cycle;

	dword_t timer, timermatch;

	uint32_t mscratch;
	uint32_t mtvec;
	uint32_t mie;
	uint32_t mip;

	uint32_t mepc;
	uint32_t mtval;
	uint32_t mcause;

	enum priv priv;
	bool wfi;
	word_t reservation;


	// not used by os, information only
	word_t mvendorid;
	word_t misa;
	
} __attribute__((aligned(ALIGN)));

struct system {
    struct rvcore_rv32ima *core;

	word_t ram_base;
	word_t ram_size;
    uint8_t *image;

    word_t (*read_csr)(struct system *sys, struct inst);
    void (*write_csr)(struct system *sys, struct inst, word_t val);
};

static inline word_t sys_ram_end(struct system *sys) {
	return sys->ram_base + sys->ram_size;
}

void sys_alloc_memory(struct system *sys, word_t base, word_t size);
void dump_sys(struct system *sys);

word_t proc_inst_Zicsr(struct rvcore_rv32ima *core, struct inst inst, struct system *sys);
void proc_inst_wfi(struct rvcore_rv32ima *core, struct inst inst);
