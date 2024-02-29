// Copyright 2022 Charles Lohr, you may use this file or any portions herein under any of the BSD, MIT, or CC0 licenses.
// https://github.com/cnlohr/mini-rv32ima.git
// Refactored by Daley Deng

#ifndef _RISCV_H
#define _RISCV_H

#include <stdint.h>
#include <stdbool.h>

#include <stdio.h>
#include <stdlib.h>

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

struct system {
	word_t ram_base;
	word_t ram_size;
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


#ifndef MINIRV32_POSTEXEC
#define MINIRV32_POSTEXEC(...) ;
#endif

#ifndef MINIRV32_HANDLE_MEM_STORE_CONTROL
#define MINIRV32_HANDLE_MEM_STORE_CONTROL(...) ;
#endif

#ifndef MINIRV32_HANDLE_MEM_LOAD_CONTROL
#define MINIRV32_HANDLE_MEM_LOAD_CONTROL(...) ;
#endif

#ifndef MINIRV32_OTHERCSR_WRITE
#define MINIRV32_OTHERCSR_WRITE(...) ;
#endif

#ifndef MINIRV32_OTHERCSR_READ
#define MINIRV32_OTHERCSR_READ(...) ;
#endif

#ifndef MINIRV32_CUSTOM_MEMORY_BUS
#define MINIRV32_STORE4(ofs, val) *(uint32_t *)(image + ofs) = val
#define MINIRV32_STORE2(ofs, val) *(uint16_t *)(image + ofs) = val
#define MINIRV32_STORE1(ofs, val) *(uint8_t *)(image + ofs) = val
#define MINIRV32_LOAD4(ofs) *(uint32_t *)(image + ofs)
#define MINIRV32_LOAD2(ofs) *(uint16_t *)(image + ofs)
#define MINIRV32_LOAD1(ofs) *(uint8_t *)(image + ofs)
#define MINIRV32_LOAD2_SIGNED(ofs) *(int16_t *)(image + ofs)
#define MINIRV32_LOAD1_SIGNED(ofs) *(int8_t *)(image + ofs)
#endif

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

struct MiniRV32IMAState {
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
	
} __attribute__((aligned(ALIGN)));

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

int32_t MiniRV32IMAStep(struct system *sys, struct MiniRV32IMAState *state, uint8_t *image,
			uint32_t vProcAddress, uint32_t elapsedUs, int count);

#ifndef MINIRV32_CUSTOM_INTERNALS
#define CSR(x) state->x
#define SETCSR(x, val)          \
	{                       \
		state->x = val; \
	}
#define REG(x) state->regs[x]
#define REGSET(x, val)                \
	{                             \
		state->regs[x] = val; \
	}
#endif

int32_t MiniRV32IMAStep(struct system *sys, struct MiniRV32IMAState *state,
					  uint8_t *image, uint32_t vProcAddress,
					  uint32_t elapsedUs, int count)
{
	dword_inc(&state->timer, elapsedUs);

	// Handle Timer interrupt.
	if (!dword_is_zero(state->timermatch) && dword_cmp(state->timer, state->timermatch)) {
		state->wfi = false;
		CSR(mip) |=
			1
			<< 7; //MTIP of MIP // https://stackoverflow.com/a/61916199/2926815  Fire interrupt.
	} else {
		CSR(mip) &= ~(1 << 7);
	}

	if (state->wfi)
		return 1;

	uint32_t trap = 0;
	uint32_t rval = 0;
	uint32_t pc = CSR(pc);

	if ((CSR(mip) & (1 << 7)) && (CSR(mie) & (1 << 7) /*mtie*/) &&
	    (CSR(mstatus) & 0x8 /*mie*/)) {
		// Timer interrupt.
		trap = 0x80000007;
		pc -= 4;
	} else // No timer interrupt?  Execute a bunch of instructions.
		for (int icount = 0; icount < count; icount++) {
			word_t ir = 0;
			rval = 0;
			dword_inc(&state->cycle, 1);

			word_t ofs_pc = pc - sys->ram_base;

			if (ofs_pc >= sys->ram_size) {
				trap = 1 +
				       1; // Handle access violation on instruction read.
				break;
			} else if (ofs_pc & 3) {
				trap = 1 + 0; //Handle PC-misaligned access
				break;
			} else {
				ir = MINIRV32_LOAD4(ofs_pc);
				struct inst inst = *((struct inst*) &ir);
				int i_rd = inst.v.rd;

				switch (inst.v.opcode) {
				case 0x37: // LUI (0b0110111)
					rval = (ir & 0xfffff000);
					break;
				case 0x17: // AUIPC (0b0010111)
					rval = pc + (ir & 0xfffff000);
					break;
				case 0x6F: // JAL (0b1101111)
				{
					int32_t reladdy =
						((ir & 0x80000000) >> 11) |
						((ir & 0x7fe00000) >> 20) |
						((ir & 0x00100000) >> 9) |
						((ir & 0x000ff000));
					if (reladdy & 0x00100000)
						reladdy |=
							0xffe00000; // Sign extension.
					rval = pc + 4;
					pc = pc + reladdy - 4;
					break;
				}
				case 0x67: // JALR (0b1100111)
				{
					uint32_t imm = ir >> 20;
					int32_t imm_se = imm |
							 ((imm & 0x800) ?
								  0xfffff000 :
								  0);
					rval = pc + 4;
					pc = ((REG((ir >> 15) & 0x1f) +
					       imm_se) &
					      ~1) -
					     4;
					break;
				}
				case 0x63: // Branch (0b1100011)
				{
					uint32_t immm4 =
						((ir & 0xf00) >> 7) |
						((ir & 0x7e000000) >> 20) |
						((ir & 0x80) << 4) |
						((ir >> 31) << 12);
					if (immm4 & 0x1000)
						immm4 |= 0xffffe000;
					int32_t rs1 = REG((ir >> 15) & 0x1f);
					int32_t rs2 = REG((ir >> 20) & 0x1f);
					immm4 = pc + immm4 - 4;
					i_rd = 0;
					switch ((ir >> 12) & 0x7) {
					// BEQ, BNE, BLT, BGE, BLTU, BGEU
					case 0:
						if (rs1 == rs2)
							pc = immm4;
						break;
					case 1:
						if (rs1 != rs2)
							pc = immm4;
						break;
					case 4:
						if (rs1 < rs2)
							pc = immm4;
						break;
					case 5:
						if (rs1 >= rs2)
							pc = immm4;
						break; //BGE
					case 6:
						if ((uint32_t)rs1 <
						    (uint32_t)rs2)
							pc = immm4;
						break; //BLTU
					case 7:
						if ((uint32_t)rs1 >=
						    (uint32_t)rs2)
							pc = immm4;
						break; //BGEU
					default:
						trap = (2 + 1);
					}
					break;
				}
				case 0x03: // Load (0b0000011)
				{
					uint32_t rs1 = REG((ir >> 15) & 0x1f);
					uint32_t imm = ir >> 20;
					int32_t imm_se = imm |
							 ((imm & 0x800) ?
								  0xfffff000 :
								  0);
					uint32_t rsval = rs1 + imm_se;

					rsval -= sys->ram_base;
					if (rsval >= sys->ram_size - 3) {
						rsval +=
							sys->ram_base;
						if (rsval >= 0x10000000 &&
						    rsval < 0x12000000) // UART, CLNT
						{
							if (rsval ==
							    0x1100bffc) // https://chromitem-soc.readthedocs.io/en/latest/clint.html
								rval = state->timer.high;
							else if (rsval ==
								 0x1100bff8)
								 rval = state->timer.low;
							else
								MINIRV32_HANDLE_MEM_LOAD_CONTROL(
									rsval,
									rval);
						} else {
							trap = (5 + 1);
							rval = rsval;
						}
					} else {
						switch ((ir >> 12) & 0x7) {
						//LB, LH, LW, LBU, LHU
						case 0:
							rval = MINIRV32_LOAD1_SIGNED(
								rsval);
							break;
						case 1:
							rval = MINIRV32_LOAD2_SIGNED(
								rsval);
							break;
						case 2:
							rval = MINIRV32_LOAD4(
								rsval);
							break;
						case 4:
							rval = MINIRV32_LOAD1(
								rsval);
							break;
						case 5:
							rval = MINIRV32_LOAD2(
								rsval);
							break;
						default:
							trap = (2 + 1);
						}
					}
					break;
				}
				case 0x23: // Store 0b0100011
				{
					uint32_t rs1 = REG((ir >> 15) & 0x1f);
					uint32_t rs2 = REG((ir >> 20) & 0x1f);
					uint32_t addy =
						((ir >> 7) & 0x1f) |
						((ir & 0xfe000000) >> 20);
					if (addy & 0x800)
						addy |= 0xfffff000;
					addy += rs1 - sys->ram_base;
					i_rd = 0;

					if (addy >= sys->ram_size - 3) {
						addy += sys->ram_base;
						if (addy >= 0x10000000 &&
						    addy < 0x12000000) {
							// Should be stuff like SYSCON, 8250, CLNT
							if (addy ==
							    0x11004004) //CLNT
								state->timermatch.high =
									rs2;
							else if (addy ==
								 0x11004000) //CLNT
								state->timermatch.low =
									rs2;
							else if (addy ==
								 0x11100000) //SYSCON (reboot, poweroff, etc.)
							{
								SETCSR(pc,
								       pc + 4);
								return rs2; // NOTE: PC will be PC of Syscon.
							} else
								MINIRV32_HANDLE_MEM_STORE_CONTROL(
									addy,
									rs2);
						} else {
							trap = (7 +
								1); // Store access fault.
							rval = addy;
						}
					} else {
						switch ((ir >> 12) & 0x7) {
						//SB, SH, SW
						case 0:
							MINIRV32_STORE1(addy,
									rs2);
							break;
						case 1:
							MINIRV32_STORE2(addy,
									rs2);
							break;
						case 2:
							MINIRV32_STORE4(addy,
									rs2);
							break;
						default:
							trap = (2 + 1);
						}
					}
					break;
				}
				case 0x13: // Op-immediate 0b0010011
				case 0x33: // Op           0b0110011
				{
					uint32_t imm = ir >> 20;
					imm = imm |
					      ((imm & 0x800) ? 0xfffff000 : 0);
					uint32_t rs1 = REG((ir >> 15) & 0x1f);
					uint32_t is_reg = !!(ir & 0x20);
					uint32_t rs2 =
						is_reg ? REG(imm & 0x1f) : imm;

					if (is_reg && (ir & 0x02000000)) {
						switch ((ir >> 12) &
							7) //0x02000000 = RV32M
						{
						case 0:
							rval = rs1 * rs2;
							break; // MUL
#ifndef CUSTOM_MULH // If compiling on a system that doesn't natively, or via libgcc support 64-bit math.
						case 1:
							rval = ((int64_t)((
									int32_t)rs1) *
								(int64_t)((
									int32_t)rs2)) >>
							       32;
							break; // MULH
						case 2:
							rval = ((int64_t)((
									int32_t)rs1) *
								(uint64_t)rs2) >>
							       32;
							break; // MULHSU
						case 3:
							rval = ((uint64_t)rs1 *
								(uint64_t)rs2) >>
							       32;
							break; // MULHU
#else
							CUSTOM_MULH
#endif
						case 4:
							if (rs2 == 0)
								rval = -1;
							else
								rval = ((int32_t)rs1 ==
										INT32_MIN &&
									(int32_t)rs2 ==
										-1) ?
									       rs1 :
									       ((int32_t)
											rs1 /
										(int32_t)
											rs2);
							break; // DIV
						case 5:
							if (rs2 == 0)
								rval = 0xffffffff;
							else
								rval = rs1 /
								       rs2;
							break; // DIVU
						case 6:
							if (rs2 == 0)
								rval = rs1;
							else
								rval = ((int32_t)rs1 ==
										INT32_MIN &&
									(int32_t)rs2 ==
										-1) ?
									       0 :
									       ((uint32_t)((int32_t)
												   rs1 %
											   (int32_t)
												   rs2));
							break; // REM
						case 7:
							if (rs2 == 0)
								rval = rs1;
							else
								rval = rs1 %
								       rs2;
							break; // REMU
						}
					} else {
						switch ((ir >> 12) &
							7) // These could be either op-immediate or op commands.  Be careful.
						{
						case 0:
							rval = (is_reg &&
								(ir &
								 0x40000000)) ?
								       (rs1 -
									rs2) :
								       (rs1 +
									rs2);
							break;
						case 1:
							rval = rs1
							       << (rs2 & 0x1F);
							break;
						case 2:
							rval = (int32_t)rs1 <
							       (int32_t)rs2;
							break;
						case 3:
							rval = rs1 < rs2;
							break;
						case 4:
							rval = rs1 ^ rs2;
							break;
						case 5:
							rval = (ir &
								0x40000000) ?
								       (((int32_t)
										 rs1) >>
									(rs2 &
									 0x1F)) :
								       (rs1 >>
									(rs2 &
									 0x1F));
							break;
						case 6:
							rval = rs1 | rs2;
							break;
						case 7:
							rval = rs1 & rs2;
							break;
						}
					}
					break;
				}
				case 0x0f: // 0b0001111
					i_rd = 0; // fencetype = (ir >> 12) & 0b111; We ignore fences in this impl.
					break;
				case 0x73: // Zifencei+Zicsr  (0b1110011)
				{
					if ((inst.v.funct3 & MASK(2))) // It's a Zicsr function.
					{
						int rs1imm = (ir >> 15) & 0x1f;
						uint32_t rs1 = REG(rs1imm);
						uint32_t writeval = rs1;

						// https://raw.githubusercontent.com/riscv/virtual-memory/main/specs/663-Svpbmt.pdf
						// Generally, support for Zicsr
						switch (inst.Zicsr.csr) {
						case 0x340:
							rval = CSR(mscratch);
							break;
						case 0x305:
							rval = CSR(mtvec);
							break;
						case 0x304:
							rval = CSR(mie);
							break;
						case 0xC00:
							rval = state->cycle.low;
							break;
						case 0xC80:
							rval = state->cycle.high;
							break;
						case 0x344:
							rval = CSR(mip);
							break;
						case 0x341:
							rval = CSR(mepc);
							break;
						case 0x300:
							rval = CSR(mstatus);
							break; //mstatus
						case 0x342:
							rval = CSR(mcause);
							break;
						case 0x343:
							rval = CSR(mtval);
							break;
						case 0xf11:
							rval = 0xff0ff0ff;
							break; //mvendorid
						case 0x301:
							rval = 0x40401101;
							break; //misa (XLEN=32, IMA+X)
						//case 0x3B0: rval = 0; break; //pmpaddr0
						//case 0x3a0: rval = 0; break; //pmpcfg0
						//case 0xf12: rval = 0x00000000; break; //marchid
						//case 0xf13: rval = 0x00000000; break; //mimpid
						//case 0xf14: rval = 0x00000000; break; //mhartid
						default:
							MINIRV32_OTHERCSR_READ(
								inst.Zicsr.csr, rval);
							break;
						}

						switch (inst.Zicsr.funct3) {
						case 1:
							writeval = rs1;
							break; //CSRRW
						case 2:
							writeval = rval | rs1;
							break; //CSRRS
						case 3:
							writeval = rval & ~rs1;
							break; //CSRRC
						case 5:
							writeval = rs1imm;
							break; //CSRRWI
						case 6:
							writeval = rval |
								   rs1imm;
							break; //CSRRSI
						case 7:
							writeval = rval &
								   ~rs1imm;
							break; //CSRRCI
						}

						switch (inst.Zicsr.csr) {
						case 0x340:
							SETCSR(mscratch,
							       writeval);
							break;
						case 0x305:
							SETCSR(mtvec, writeval);
							break;
						case 0x304:
							SETCSR(mie, writeval);
							break;
						case 0x344:
							SETCSR(mip, writeval);
							break;
						case 0x341:
							SETCSR(mepc, writeval);
							break;
						case 0x300:
							SETCSR(mstatus,
							       writeval);
							break; //mstatus
						case 0x342:
							SETCSR(mcause,
							       writeval);
							break;
						case 0x343:
							SETCSR(mtval, writeval);
							break;
						//case 0x3a0: break; //pmpcfg0
						//case 0x3B0: break; //pmpaddr0
						//case 0xf11: break; //mvendorid
						//case 0xf12: break; //marchid
						//case 0xf13: break; //mimpid
						//case 0xf14: break; //mhartid
						//case 0x301: break; //misa
						default:
							MINIRV32_OTHERCSR_WRITE(
								inst.Zicsr.csr,
								writeval);
							break;
						}
					} else if (inst.v.funct3 == 0x0) // "SYSTEM" 0b000
					{
						i_rd = 0;
						int csrno = inst.priv_I.imm;
						if (csrno ==
						    0x105) //WFI (Wait for interrupts)
						{
							CSR(mstatus) |=
								8; //Enable interrupts
							state->wfi = true;
							SETCSR(pc, pc + 4);
							return 1;
						} else if (((csrno & 0xff) ==
							    0x02)) // MRET
						{
							//https://raw.githubusercontent.com/riscv/virtual-memory/main/specs/663-Svpbmt.pdf
							//Table 7.6. MRET then in mstatus/mstatush sets MPV=0, MPP=0, MIE=MPIE, and MPIE=1. La
							// Should also update mstatus to reflect correct mode.
							uint32_t startmstatus =
								CSR(mstatus);
							SETCSR(mstatus,
							       ((startmstatus &
								 0x80) >>
								4) |
								       (state->priv
									<< 11) |
								       0x80);

							state->priv = ((startmstatus >>
									11) &
								       3);

							pc = CSR(mepc) - 4;
						} else {
							switch (csrno) {
							case 0:
								trap = (state->priv == PRIV_MACHINE) ?
									       (11 +
										1) :
									       (8 +
										1);
								break; // ECALL; 8 = "Environment call from U-mode"; 11 = "Environment call from M-mode"
							case 1:
								trap = (3 + 1);
								break; // EBREAK 3 = "Breakpoint"
							default:
								trap = (2 + 1);
								break; // Illegal opcode.
							}
						}
					} else
						trap = (2 +
							1); // Note micrrop 0b100 == undefined.
					break;
				}
				case 0x2f: // RV32A (0b00101111)
				{
					uint32_t rs1 = REG((ir >> 15) & 0x1f);
					uint32_t rs2 = REG((ir >> 20) & 0x1f);
					uint32_t irmid = (ir >> 27) & 0x1f;

					rs1 -= sys->ram_base;

					// We don't implement load/store from UART or CLNT with RV32A here.

					if (rs1 >= sys->ram_size - 3) {
						trap = (7 +
							1); //Store/AMO access fault
						rval = rs1 +
						       sys->ram_base;
					} else {
						rval = MINIRV32_LOAD4(rs1);

						// Referenced a little bit of https://github.com/franzflasch/riscv_em/blob/master/src/core/core.c
						uint32_t dowrite = 1;
						switch (irmid) {
						case 2: //LR.W (0b00010)
							dowrite = 0;
							state->reservation = rs1;
							break;
						case 3: //SC.W (0b00011) (Make sure we have a slot, and, it's valid)
							rval = state->reservation != rs1;
							dowrite =
								!rval; // Only write if slot is valid.
							break;
						case 1:
							break; //AMOSWAP.W (0b00001)
						case 0:
							rs2 += rval;
							break; //AMOADD.W (0b00000)
						case 4:
							rs2 ^= rval;
							break; //AMOXOR.W (0b00100)
						case 12:
							rs2 &= rval;
							break; //AMOAND.W (0b01100)
						case 8:
							rs2 |= rval;
							break; //AMOOR.W (0b01000)
						case 16:
							rs2 = ((int32_t)rs2 <
							       (int32_t)rval) ?
								      rs2 :
								      rval;
							break; //AMOMIN.W (0b10000)
						case 20:
							rs2 = ((int32_t)rs2 >
							       (int32_t)rval) ?
								      rs2 :
								      rval;
							break; //AMOMAX.W (0b10100)
						case 24:
							rs2 = (rs2 < rval) ?
								      rs2 :
								      rval;
							break; //AMOMINU.W (0b11000)
						case 28:
							rs2 = (rs2 > rval) ?
								      rs2 :
								      rval;
							break; //AMOMAXU.W (0b11100)
						default:
							trap = (2 + 1);
							dowrite = 0;
							break; //Not supported.
						}
						if (dowrite)
							MINIRV32_STORE4(rs1,
									rs2);
					}
					break;
				}
				default:
					trap = (2 +
						1); // Fault: Invalid opcode.
				}

				// If there was a trap, do NOT allow register writeback.
				if (trap)
					break;

				if (i_rd) {
					REGSET(i_rd,
					       rval); // Write back register.
				}
			}

			MINIRV32_POSTEXEC(pc, ir, trap);

			pc += 4;
		}

	// Handle traps and interrupts.
	if (trap) {
		if (trap &
		    0x80000000) // If prefixed with 1 in MSB, it's an interrupt, not a trap.
		{
			SETCSR(mcause, trap);
			SETCSR(mtval, 0);
			pc += 4; // PC needs to point to where the PC will return to.
		} else {
			SETCSR(mcause, trap - 1);
			SETCSR(mtval, (trap > 5 && trap <= 8) ? rval : pc);
		}
		SETCSR(mepc,
		       pc); //TRICKY: The kernel advances mepc automatically.
		//CSR( mstatus ) & 8 = MIE, & 0x80 = MPIE
		// On an interrupt, the system moves current MIE into MPIE
		SETCSR(mstatus, ((CSR(mstatus) & 0x08) << 4) |
					(state->priv << 11));
		pc = (CSR(mtvec) - 4);

		// If trapping, always enter machine mode.
		state->priv = PRIV_MACHINE;

		trap = 0;
		pc += 4;
	}

	state->pc = pc;
	return 0;
}

#endif // _RISCV_H
