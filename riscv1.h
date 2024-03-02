// Copyright 2022 Charles Lohr, you may use this file or any portions herein under any of the BSD, MIT, or CC0 licenses.
// https://github.com/cnlohr/mini-rv32ima.git
// Refactored by Daley Deng

#ifndef _RISCV_H
#define _RISCV_H

#include <stdint.h>

#ifndef MINIRV32_HANDLE_MEM_STORE_CONTROL
#define MINIRV32_HANDLE_MEM_STORE_CONTROL(...) ;
#endif

#ifndef MINIRV32_HANDLE_MEM_LOAD_CONTROL
#define MINIRV32_HANDLE_MEM_LOAD_CONTROL(...) ;
#endif

#include "riscv.h"

int MiniRV32IMAStep(struct platform *sys, struct rvcore_rv32ima *state,
			uint8_t *image, uint32_t vProcAddress,
			uint32_t elapsedUs, int count);

#ifndef MINIRV32_CUSTOM_INTERNALS
#define CSR(x) core->x
#define SETCSR(x, val)         \
	{                      \
		core->x = val; \
	}
#define REG(x) core->regs[x]
#define REGSET(x, val)               \
	{                            \
		core->regs[x] = val; \
	}
#endif

int MiniRV32IMAStep(struct platform *plat, struct rvcore_rv32ima *core,
			uint8_t *image, uint32_t vProcAddress,
			uint32_t elapsedUs, int count)
{
	int err = 0;
	struct dram *dram = plat->dram;
	core->mtime.v += elapsedUs;
	// Handle Timer interrupt.
	if (plat->mtimecmp.v && core->mtime.v >= plat->mtimecmp.v) {
		plat->wfi = false;
		core->mip.MTI = true;
	} else if (core->mip.MTI) {
		core->mip.MTI = false;
	}

	if (plat->wfi)
		return 1;

	if (check_interrupt(core, I_M_Timer)) {
		handle_interrupt(core, I_M_Timer);
		return 0;
	}

	uint32_t rval = 0;

	for (int icount = 0; icount < count; icount++) {
		bool is_jump = false;
		bool rd_writed = false;
		xlenbits ir = 0;
		rval = 0;
		core->mcycle.v += 1;

		xlenbits ofs_pc = core->pc - plat->dram->base;

		if (ofs_pc >= plat->dram->size) {
			handle_exception(core, E_Fetch_Access_Fault, core->pc);
			return 0;
		}

		if (ofs_pc & 0x3) {
			handle_exception(core, E_Fetch_Addr_Align, core->pc);
			return 0;
		}

		ir = dram_lw(dram, ofs_pc);
		ast_t inst = { .bits = ir };
		int i_rd = inst.rd;

		switch (inst.opcode) {
		case 0x37: // LUI (0b0110111)
			wX(core, inst.U.rd, inst.U.imm << 12);
			rd_writed = true;
			break;

		case 0x17: // AUIPC (0b0010111)
			wX(core, inst.U.rd,
				 core->pc + (inst.U.imm << 12));
			rd_writed = true;
			break;

		case 0x6F: // JAL (0b1101111)
		{
			is_jump = true;
			xlenbits rel_addr =
				(inst.J.imm_1_10 << 1 | inst.J.imm_11 << 11 |
				 inst.J.imm_12_19 << 12 | inst.J.imm_20 << 20);
			rel_addr = sign_ext(rel_addr, 21);

			wX(core, inst.J.rd, core->pc + 4);
			core->pc += rel_addr;

			rd_writed = true;

			break;
		}

		case 0x67: // JALR (0b1100111)
		{
			is_jump = true;
			xlenbits imm_se = sign_ext(inst.I.imm, 12);
			// NOTICE, rs1 may override with rd, save rs1 first
			xlenbits rs1 = rX(core, inst.I.rs1);
			wX(core, inst.I.rd, core->pc + 4);
			core->pc = (rs1 + imm_se) & ~1;

			rd_writed = true;
			break;
		}

		case 0x63: // Branch (0b1100011)
		{
			xlenbits imm = sign_ext(
				(inst.B.imm_1_4 << 1 | inst.B.imm_5_10 << 5 |
				 inst.B.imm_11 << 11 | inst.B.imm_12 << 12),
				13);

			int32_t rs1 = rX(core, inst.B.rs1);
			int32_t rs2 = rX(core, inst.B.rs2);

			switch (inst.B.funct3) {
			// BEQ, BNE, BLT, BGE, BLTU, BGEU
			case 0:
				is_jump = rs1 == rs2; // beq
				break;
			case 1:
				is_jump = rs1 != rs2; // bne
				break;
			case 4:
				is_jump = rs1 < rs2; // blt
				break;
			case 5:
				is_jump = rs1 >= rs2; // bge
				break;
			case 6:
				is_jump = (uint32_t)rs1 < (uint32_t)rs2; // bltu
				break;
			case 7:
				is_jump = (uint32_t)rs1 >=
					  (uint32_t)rs2; // bgeu
				break;
			default:
				handle_exception(core, E_Illegal_Instr,
						 core->pc);
				return 0;
			}

			if (is_jump)
				core->pc += imm;

			rd_writed = true;
			break;
		}
		case 0x03: // Load (0b0000011)
		{
			uint32_t rs1 = REG((ir >> 15) & 0x1f);
			uint32_t imm = ir >> 20;
			int32_t imm_se = imm | ((imm & 0x800) ? 0xfffff000 : 0);
			uint32_t rsval = rs1 + imm_se;

			rsval -= plat->dram->base;
			if (rsval >= plat->dram->size - 3) {
				rsval += plat->dram->base;
				if (rsval >= 0x10000000 &&
				    rsval < 0x12000000) // UART, CLNT
				{
					if (rsval ==
					    0x1100bffc) // https://chromitem-soc.readthedocs.io/en/latest/clint.html
						rval = core->mtime.high;
					else if (rsval == 0x1100bff8)
						rval = core->mtime.low;
					else
						MINIRV32_HANDLE_MEM_LOAD_CONTROL(
							rsval, rval);
				} else {
					handle_exception(core, E_Load_Access_Fault, rsval);
					return 0;
				}
			} else {
				switch ((ir >> 12) & 0x7) {
				//LB, LH, LW, LBU, LHU
				case 0:
					rval = dram_lb(dram, rsval);
					break;
				case 1:
					rval = dram_lh(dram, rsval);
					break;
				case 2:
					rval = dram_lw(dram, rsval);
					break;
				case 4:
					rval = dram_lbu(dram, rsval);
					break;
				case 5:
					rval = dram_lhu(dram, rsval);
					break;
				default:
					handle_exception(core, E_Illegal_Instr, inst.bits);
					return 0;
				}
			}
			break;
		}
		case 0x23: // Store 0b0100011
		{
			rd_writed = true;

			uint32_t rs1 = REG((ir >> 15) & 0x1f);
			uint32_t rs2 = REG((ir >> 20) & 0x1f);
			uint32_t addy = ((ir >> 7) & 0x1f) |
					((ir & 0xfe000000) >> 20);
			if (addy & 0x800)
				addy |= 0xfffff000;
			addy += rs1 - plat->dram->base;
			i_rd = 0;

			if (addy >= plat->dram->size - 3) {
				addy += plat->dram->base;
				if (addy >= 0x10000000 && addy < 0x12000000) {
					// Should be stuff like SYSCON, 8250, CLNT
					if (addy == 0x11004004) //CLNT
						*((bits32 *)&plat->mtimecmp +
						  1) = rs2;
					else if (addy == 0x11004000) //CLNT
						*((bits32 *)&plat->mtimecmp) =
							rs2;
					else if (addy ==
						 0x11100000) //SYSCON (reboot, poweroff, etc.)
					{
						SETCSR(pc, core->pc + 4);
						return rs2; // NOTE: PC will be PC of Syscon.
					} else
						MINIRV32_HANDLE_MEM_STORE_CONTROL(
							addy, rs2);
				} else {
					handle_exception(core, E_SAMO_Access_Fault, addy);
					return 0;
				}
			} else {
				switch ((ir >> 12) & 0x7) {
				//SB, SH, SW
				case 0:
					dram_sb(dram, addy, rs2);
					break;
				case 1:
					dram_sh(dram, addy, rs2);
					break;
				case 2:
					dram_sw(dram, addy, rs2);
					break;
				default:
					handle_exception(core, E_Illegal_Instr, inst.bits);
					return 0;
				}
			}
			break;
		}
		case 0x13: // Op-immediate 0b0010011
		case 0x33: // Op           0b0110011
		{
			uint32_t imm = ir >> 20;
			imm = imm | ((imm & 0x800) ? 0xfffff000 : 0);
			uint32_t rs1 = REG((ir >> 15) & 0x1f);
			uint32_t is_reg = !!(ir & 0x20);
			uint32_t rs2 = is_reg ? REG(imm & 0x1f) : imm;

			if (is_reg && (ir & 0x02000000)) {
				switch ((ir >> 12) & 7) //0x02000000 = RV32M
				{
				case 0:
					rval = rs1 * rs2;
					break; // MUL
#ifndef CUSTOM_MULH // If compiling on a system that doesn't natively, or via libgcc support 64-bit math.
				case 1:
					rval = ((int64_t)((int32_t)rs1) *
						(int64_t)((int32_t)rs2)) >>
					       32;
					break; // MULH
				case 2:
					rval = ((int64_t)((int32_t)rs1) *
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
							(int32_t)rs2 == -1) ?
							       rs1 :
							       ((int32_t)rs1 /
								(int32_t)rs2);
					break; // DIV
				case 5:
					if (rs2 == 0)
						rval = 0xffffffff;
					else
						rval = rs1 / rs2;
					break; // DIVU
				case 6:
					if (rs2 == 0)
						rval = rs1;
					else
						rval = ((int32_t)rs1 ==
								INT32_MIN &&
							(int32_t)rs2 == -1) ?
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
						rval = rs1 % rs2;
					break; // REMU
				}
			} else {
				switch ((ir >> 12) &
					7) // These could be either op-immediate or op commands.  Be careful.
				{
				case 0:
					rval = (is_reg && (ir & 0x40000000)) ?
						       (rs1 - rs2) :
						       (rs1 + rs2);
					break;
				case 1:
					rval = rs1 << (rs2 & 0x1F);
					break;
				case 2:
					rval = (int32_t)rs1 < (int32_t)rs2;
					break;
				case 3:
					rval = rs1 < rs2;
					break;
				case 4:
					rval = rs1 ^ rs2;
					break;
				case 5:
					rval = (ir & 0x40000000) ?
						       (((int32_t)rs1) >>
							(rs2 & 0x1F)) :
						       (rs1 >> (rs2 & 0x1F));
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
			if ((inst.funct3 & MASK(2))) // Zicsr function.
			{
				if ((err = execute_Zicsr(inst, core, plat)))
					return err;

				rd_writed = true;

			} else if (inst.funct3 == 0x0) // "SYSTEM" 0b000
			{
				int csrno = inst.priv_I.imm;
				if (csrno == 0x105) //WFI (Wait for interrupts)
				{
					if ((err = execute_wfi(inst, core, plat)))
						return err;
					
					core->pc = core->pc + 4;
					return 1;

				} else if (((csrno & 0xff) == 0x02)) // MRET
				{
					if ((err = execute_mret(inst, core, plat)))
						return err;

					core->pc = core->mepc - 4;

				} else {
					i_rd = 0;
					switch (csrno) {
					case 0:
						if (core->cur_privilege == Machine) {
							handle_exception(core, E_M_EnvCall, core->pc);
							return 0;
						} else {
							handle_exception(core, E_U_EnvCall, core->pc);
							return 0;			
						}
						break; // ECALL; 8 = "Environment call from U-mode"; 11 = "Environment call from M-mode"
					case 1:
						handle_exception(core, E_Breakpoint, core->pc);
						return 0;
					default:
						handle_exception(core, E_Illegal_Instr, inst.bits);
						return 0;
					}
				}
			} else {
				handle_exception(core, E_Illegal_Instr, inst.bits);
				return 0;
			}
				
			break;
		}
		case 0x2f: // RV32A (0b00101111)
		{
			uint32_t rs1 = REG((ir >> 15) & 0x1f);
			uint32_t rs2 = REG((ir >> 20) & 0x1f);
			uint32_t irmid = (ir >> 27) & 0x1f;

			rs1 -= plat->dram->base;

			// We don't implement load/store from UART or CLNT with RV32A here.

			if (rs1 >= plat->dram->size - 3) {
				rval = rs1 + plat->dram->base;
				
				handle_exception(core, E_SAMO_Access_Fault, rval);
				return 0;
			} else {
				rval = dram_lw(dram, rs1);

				// Referenced a little bit of https://github.com/franzflasch/riscv_em/blob/master/src/core/core.c
				uint32_t dowrite = 1;
				switch (irmid) {
				case 2: //LR.W (0b00010)
					dowrite = 0;
					plat->reservation = rs1;
					break;
				case 3: //SC.W (0b00011) (Make sure we have a slot, and, it's valid)
					rval = plat->reservation != rs1;
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
					rs2 = ((int32_t)rs2 < (int32_t)rval) ?
						      rs2 :
						      rval;
					break; //AMOMIN.W (0b10000)
				case 20:
					rs2 = ((int32_t)rs2 > (int32_t)rval) ?
						      rs2 :
						      rval;
					break; //AMOMAX.W (0b10100)
				case 24:
					rs2 = (rs2 < rval) ? rs2 : rval;
					break; //AMOMINU.W (0b11000)
				case 28:
					rs2 = (rs2 > rval) ? rs2 : rval;
					break; //AMOMAXU.W (0b11100)
				default:
					handle_exception(core, E_Illegal_Instr, inst.bits);
					return 0;

					dowrite = 0;
					break; //Not supported.
				}
				if (dowrite)
					dram_sw(dram, rs1, rs2);
			}
			break;
		}
		default:
			handle_exception(core, E_Illegal_Instr, inst.bits);
			return 0;
		}

		if (!rd_writed)
			wX(core, i_rd, rval);

		if (!is_jump)
			core->pc += 4;
	}

	return 0;
}

#endif // _RISCV_H
