#ifndef _RISCV_H
#define _RISCV_H

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stddef.h>

#define XLEN 32
typedef uint32_t xlenbits;
typedef int32_t s_xlenbits;

typedef uint32_t bits32;
typedef union {
	uint64_t v;
	struct {
		bits32 low;
		bits32 high;
	};
} bits64;

typedef xlenbits regtype;

#define ALIGN 8

#define MASK(n) ((1 << (n)) - 1)
#define get_bit(reg, b) ((reg) & 1 << (b))
#define get_bit2(reg, b) (((reg) >> b) & 0x3)
#define set_bit(reg, b) ((*(reg)) |= 1 << (b))
#define clear_bit(reg, b) ((*(reg)) &= ~(1 << (b)))
#define clear_bit2(reg, b) ((*(reg)) &= ~(0x3 << (b)))

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

enum Privilege {User = 0, Supervisor = 1, Machine = 3};

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

typedef union {
	bits32 bits;

	struct {
		bits32 opcode : 7;
		bits32 rd : 5;
		bits32 funct3 : 3;
	};

	struct {
		bits32 opcode: 7;
		bits32 rd: 5;
		bits32 funct3: 3;
		bits32 rs1: 5;
		bits32 rs2: 5;
		bits32 funct7:7;
	} R;

	struct {
		bits32 opcode : 7;
		bits32 rd : 5;
		bits32 funct3 : 3;
		bits32 rs1 : 5;
		bits32 imm : 12;
	} I;

	struct {
		bits32 opcode : 7;
		bits32 imm_0_4 : 5;
		bits32 funct3 : 3;
		bits32 rs1 : 5;
		bits32 rs2 : 5;
		bits32 imm_5_11 : 7;
	} S;

	struct {
		bits32 opcode : 7;
		bits32 imm_11 : 1;
		bits32 imm_1_4 : 4;
		bits32 funct3 : 3;
		bits32 rs1 : 5;
		bits32 rs2 : 5;
		bits32 imm_5_10 : 6;
		bits32 imm_12 : 1;
	} B;

	struct {
		bits32 opcode : 7;
		bits32 rd : 5;
		xlenbits imm : 20;
	} U;
	struct {
		bits32 opcode : 7;
		bits32 rd : 5;
		bits32 imm_12_19 : 8;
		bits32 imm_11 : 1;
		bits32 imm_1_10 : 10;
		bits32 imm_20 : 1;
	} J;

	struct {
		bits32 opcode : 7;
		bits32 rd : 5;
		bits32 funct3 : 3;
		bits32 rs1_uimm : 5;
		bits32 csr : 12;
	} Zicsr;
} ast_t;

static inline xlenbits sign_ext(xlenbits imm, int size)
{
	return get_bit(imm, size - 1) ?
		       imm | ((1 << (XLEN - size)) - 1) << size :
		       imm;
}

typedef union {
	xlenbits bits;
	struct {
		xlenbits UIE : 1; // 0
		xlenbits SIE : 1; // 1
		xlenbits : 1; // 2
		xlenbits MIE : 1; // 3

		xlenbits UPIE : 1; //4
		xlenbits SPIE : 1; //5
		xlenbits : 1; // 6
		xlenbits MPIE : 1; //7

		xlenbits SPP : 1; //8
		xlenbits VS : 2; //9-10
		xlenbits MPP : 2; //11-12
		xlenbits FS : 2; //13-14
		xlenbits XS : 2; //15-16
		xlenbits MPRV : 1; //17
		xlenbits SUM : 1; //18
		xlenbits MXR : 1; //19
		xlenbits TVM : 1; //20
		xlenbits TW : 1; //21
		xlenbits TSR : 1; //22
		xlenbits : XLEN - 1 - 23; //
		xlenbits SD : 1; // XLEN - 1
	};
} mstatus_t;

typedef union {
	xlenbits bits;
	struct {
		xlenbits mode : 2; // 0-1
		xlenbits base : XLEN - 2; // 2-xlen-1
	};
} mtvec_t;

enum InterruptType {
	I_U_Software = 0,
	I_S_Software = 1,
	I_M_Software = 3,
	I_U_Timer = 4,
	I_S_Timer = 5,
	I_M_Timer = 7,
	I_U_External = 8,
	I_S_External = 9,
	I_M_External = 11,
};

enum ExceptionType {
	E_Fetch_Addr_Align = 0,
	E_Fetch_Access_Fault,
	E_Illegal_Instr,
	E_Breakpoint,
	E_Load_Addr_Align,
	E_Load_Access_Fault,
	E_SAMO_Addr_Align,
	E_SAMO_Access_Fault,
	E_U_EnvCall,
	E_S_EnvCall,
	E_Reserved_10,
	E_M_EnvCall,
	E_Fetch_Page_Fault,
	E_Load_Page_Fault,
	E_Reserved_14,
	E_SAMO_Page_Fault,

	/* extensions */
	// E_Extension,
};

typedef union {
	xlenbits bits;
	struct {
		xlenbits USI : 1; //0
		xlenbits SSI : 1; //1
		xlenbits : 1; //2
		xlenbits MSI : 1; //3

		xlenbits UTI : 1; //4
		xlenbits STI : 1; //5
		xlenbits : 1; //6
		xlenbits MTI : 1; //7

		xlenbits UEI : 1; //8
		xlenbits SEI : 1; //9
		xlenbits : 1; //10
		xlenbits MEI : 1; //11
	};
} interrupts_t;

typedef union {
	xlenbits bits;
	struct {
		xlenbits cause : XLEN - 1;
		xlenbits is_interrupt : 1;
	};
} mcause_t;

typedef union {
	xlenbits bits;
	struct {
		xlenbits A:1; //0
		xlenbits B:1; //1
		xlenbits C:1; //2
		xlenbits D:1; //3
		xlenbits E:1; //4
		xlenbits F:1; //5
		xlenbits G:1; //6
		xlenbits H:1; //7
		xlenbits I:1; //8
		xlenbits J:1; //9
		xlenbits K:1; //10
		xlenbits L:1; //11
		xlenbits M:1; //12
		xlenbits N:1; //13
		xlenbits O:1; //14
		xlenbits P:1; //15
		xlenbits Q:1; //16
		xlenbits R:1; //17
		xlenbits S:1; //18
		xlenbits T:1; //19
		xlenbits U:1; //20
		xlenbits V:1; //21
		xlenbits W:1; //22
		xlenbits X:1; //23
		xlenbits Y:1; //24
		xlenbits Z:1; //25
		xlenbits :XLEN - 26 - 2;
		xlenbits MXL:2; //XLEN-2 .. XLEN-1
	};
} misa_t;

struct rvcore_rv32ima {
	regtype regs[32];

	xlenbits pc;
	xlenbits next_pc;

	mstatus_t mstatus;
	mtvec_t mtvec;
	interrupts_t mie;
	interrupts_t mip;

	xlenbits mepc;
	xlenbits mtval;
	xlenbits mscratch;

	mcause_t mcause;

	enum Privilege cur_privilege;
	
	// for time
	bits64 mcycle;
	bits64 mtime;

	// not used by os, information only
	bits32 mvendorid;
	misa_t misa;

} __attribute__((aligned(ALIGN)));

static inline void tick_pc(struct rvcore_rv32ima *core)
{
	core->pc = core->next_pc;
}

static inline void wX(struct rvcore_rv32ima *core, int rd, regtype val)
{
	if (rd) {
		assert(rd < XLEN);
		core->regs[rd] = val;
	}
}
static inline regtype rX(struct rvcore_rv32ima *core, int rs)
{
	return rs ? core->regs[rs] : 0;
}
struct dram {
	xlenbits base;
	size_t size;
	uint8_t *image;
};

static inline xlenbits dram_end(struct dram *dram)
{
	return dram->base + dram->size;
}

void dram_alloc(struct dram *dram, xlenbits base, size_t size);

static inline void dram_sw(struct dram *dram, xlenbits vaddr, uint32_t val)
{
	xlenbits paddr = vaddr - dram->base;
	assert(paddr < dram->size);
	*(uint32_t*)(dram->image + paddr) = val;
}
static inline void dram_sh(struct dram *dram, xlenbits vaddr, uint16_t val)
{
	xlenbits paddr = vaddr - dram->base;
	assert(paddr < dram->size);
	*(uint16_t*)(dram->image + paddr) = val;
}
static inline void dram_sb(struct dram *dram, xlenbits vaddr, uint8_t val)
{
	xlenbits paddr = vaddr - dram->base;
	assert(paddr < dram->size);
	*(uint8_t*)(dram->image + paddr) = val;
}
static inline uint32_t dram_lw(struct dram *dram, xlenbits vaddr)
{
	xlenbits paddr = vaddr - dram->base;
	assert(paddr < dram->size);
	return *(uint32_t*)(dram->image + paddr);
}
static inline uint16_t dram_lhu(struct dram *dram, xlenbits vaddr)
{
	xlenbits paddr = vaddr - dram->base;
	assert(paddr < dram->size);
	return *(uint16_t*)(dram->image + paddr);
}
static inline uint16_t dram_lbu(struct dram *dram, xlenbits vaddr)
{
	xlenbits paddr = vaddr - dram->base;
	assert(paddr < dram->size);
	return *(uint8_t*)(dram->image + paddr);
}
static inline int16_t dram_lh(struct dram *dram, xlenbits vaddr)
{
	xlenbits paddr = vaddr - dram->base;
	assert(paddr < dram->size);
	return *(int16_t*)(dram->image + paddr);
}
static inline int16_t dram_lb(struct dram *dram, xlenbits vaddr)
{
	xlenbits paddr = vaddr - dram->base;
	assert(paddr < dram->size);
	return *(int8_t*)(dram->image + paddr);
}

static inline bool dram_is_in(struct dram *dram, xlenbits vaddr)
{
	return vaddr >= dram->base && vaddr < dram->base + dram->size;
}

static inline xlenbits dram_virt_to_phys(struct dram *dram, xlenbits vaddr)
{
	return vaddr - dram->base;
}

struct platform {
	struct rvcore_rv32ima *core;

	bool wfi;
	xlenbits reservation;
	bits64 mtimecmp;

	struct dram *dram;

	xlenbits (*read_csr)(struct platform *plat, ast_t inst);
	void (*write_csr)(struct platform *plat, ast_t inst, xlenbits val);
	xlenbits (*load)(struct platform *plat, xlenbits addr);
	int (*store)(struct platform *plat, xlenbits addr, xlenbits val);
};


void dump_plat(struct platform *plat);

static inline bool check_interrupt(const struct rvcore_rv32ima *core,
				   enum InterruptType intr)
{
	return core->mstatus.MIE && get_bit(core->mip.bits, intr) &&
	       get_bit(core->mie.bits, intr);
}

void handle_trap(struct rvcore_rv32ima *core, mcause_t mcause, xlenbits mtval);
static inline void handle_interrupt(struct rvcore_rv32ima *core,
				    enum InterruptType intr)
{
	mcause_t mcause = { .is_interrupt = true, .cause = intr };
	handle_trap(core, mcause, 0);
}
static inline void handle_exception(struct rvcore_rv32ima *core,
				    enum ExceptionType exc, xlenbits mtval)
{
	mcause_t mcause = { .is_interrupt = false, .cause = exc};
	handle_trap(core, mcause, mtval);
}

int execute_Zicsr(ast_t inst, struct rvcore_rv32ima *core, struct platform *plat);
int execute_wfi(ast_t inst, struct rvcore_rv32ima *core, struct platform *plat);
int execute_mret(ast_t inst, struct rvcore_rv32ima *core, struct platform *plat);
int execute_store(ast_t inst, struct rvcore_rv32ima *core, struct platform *plat);
int execute_mext(ast_t inst, struct rvcore_rv32ima *core, struct platform *plat);
int execute_aext(ast_t inst, struct rvcore_rv32ima *core, struct platform *plat);

int step_rv32ima(struct platform *plat, uint64_t elapsed_us, int inst_batch);
#endif
