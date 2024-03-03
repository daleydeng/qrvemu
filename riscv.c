#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "riscv.h"

void dram_alloc(struct dram *dram, xlenbits base, size_t size)
{
	dram->base = base;
	dram->size = size;
	dram->image = calloc(size, 1);
	if (!dram->image) {
		fprintf(stderr, "Error: could not allocate dram.\n");
		exit(-4);
	}
}

void dump_plat(struct platform *plat)
{
	uint32_t pc = plat->core->pc;
	uint32_t pc_offset = pc - plat->dram->base;
	uint32_t ir = 0;

	printf("PC: %08x ", pc);
	if (pc_offset >= 0 && pc_offset < plat->dram->size - 3) {
		ir = *((uint32_t *)(&((uint8_t *)plat->dram->image)[pc_offset]));
		printf("[0x%08x] ", ir);
	} else
		printf("[xxxxxxxxxx] ");
	uint32_t *regs = plat->core->regs;
	printf("Z:%08x ra:%08x sp:%08x gp:%08x tp:%08x t0:%08x t1:%08x t2:%08x "
	       "s0:%08x s1:%08x a0:%08x a1:%08x a2:%08x a3:%08x a4:%08x a5:%08x ",
	       regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6],
	       regs[7], regs[8], regs[9], regs[10], regs[11], regs[12],
	       regs[13], regs[14], regs[15]);
	printf("a6:%08x a7:%08x s2:%08x s3:%08x s4:%08x s5:%08x s6:%08x s7:%08x "
	       "s8:%08x s9:%08x s10:%08x s11:%08x t3:%08x t4:%08x t5:%08x t6:%08x\n",
	       regs[16], regs[17], regs[18], regs[19], regs[20], regs[21],
	       regs[22], regs[23], regs[24], regs[25], regs[26], regs[27],
	       regs[28], regs[29], regs[30], regs[31]);
}

void handle_trap(struct rvcore_rv32ima *core, mcause_t mcause, xlenbits mtval)
{
	core->mcause = mcause;
	core->mtval = mtval;
	core->mepc = core->pc;
	core->next_pc = core->mtvec.bits;

	core->mstatus.MPIE = core->mstatus.MIE;
	core->mstatus.MIE = false;
	core->mstatus.MPP = core->cur_privilege;

	core->cur_privilege = Machine;

	tick_pc(core);
}

#define READ_CSR(no, name)         \
	case no:                   \
		rval = core->name; \
		break;
#define WRITE_CSR(no, name)             \
	case no:                        \
		core->name = write_val; \
		break;

int execute_Zicsr(ast_t inst, struct rvcore_rv32ima *core,
		  struct platform *plat)
{
	xlenbits rval = 0;
	int i_rs1 = inst.Zicsr.rs1_uimm;
	xlenbits uimm = inst.Zicsr.rs1_uimm;
	xlenbits rs1 = core->regs[i_rs1];
	xlenbits write_val = rs1;

	// https://raw.githubusercontent.com/riscv/virtual-memory/main/specs/663-Svpbmt.pdf
	// Generally, support for Zicsr
	switch (inst.Zicsr.csr) {
	case 0xC00:
		rval = (xlenbits)core->mcycle.v;
		break;
	case 0xC01:
		rval = (xlenbits)core->mtime.v;
		break;
	case 0xC80:
		rval = core->mcycle.high;
		break;
	case 0xC81:
		rval = core->mtime.high;
		break;

		READ_CSR(0xf11, mvendorid)
		READ_CSR(0x300, mstatus.bits)
		READ_CSR(0x301, misa.bits)
		READ_CSR(0x304, mie.bits)
		READ_CSR(0x305, mtvec.bits)

		READ_CSR(0x340, mscratch)
		READ_CSR(0x341, mepc)
		READ_CSR(0x342, mcause.bits)
		READ_CSR(0x343, mtval)
		READ_CSR(0x344, mip.bits)

	//case 0x3B0: rval = 0; break; //pmpaddr0
	//case 0x3a0: rval = 0; break; //pmpcfg0
	//case 0xf12: rval = 0x00000000; break; //marchid
	//case 0xf13: rval = 0x00000000; break; //mimpid
	//case 0xf14: rval = 0x00000000; break; //mhartid
	default:
		if (plat->read_csr)
			rval = plat->read_csr(plat, inst);
		break;
	}

	switch (inst.Zicsr.funct3) {
	case 1:
		write_val = rs1;
		break; //CSRRW
	case 2:
		write_val = rval | rs1;
		break; //CSRRS
	case 3:
		write_val = rval & ~rs1;
		break; //CSRRC
	case 5:
		write_val = uimm;
		break; //CSRRWI
	case 6:
		write_val = rval | uimm;
		break; //CSRRSI
	case 7:
		write_val = rval & ~uimm;
		break; //CSRRCI
	}

	switch (inst.Zicsr.csr) {
		WRITE_CSR(0x300, mstatus.bits)
		WRITE_CSR(0x304, mie.bits)
		WRITE_CSR(0x305, mtvec.bits)
		WRITE_CSR(0x340, mscratch)
		WRITE_CSR(0x341, mepc)
		WRITE_CSR(0x342, mcause.bits)
		WRITE_CSR(0x343, mtval)
		WRITE_CSR(0x344, mip.bits)

	default:
		if (plat->write_csr)
			plat->write_csr(plat, inst, write_val);
		break;
	}

	wX(core, inst.Zicsr.rd, rval);
	return 0;
}

int execute_wfi(ast_t inst, struct rvcore_rv32ima *core, struct platform *plat)
{
	assert(inst.priv_I.imm == 0x105);
	core->mstatus.MIE = true;
	plat->wfi = true;
	return 0;
}

int execute_mret(ast_t inst, struct rvcore_rv32ima *core, struct platform *plat)
{
	assert(inst.priv_I.imm == 0x302); // 0b0011 0000 0010
	// refer Volume II: RISC-V Privileged Architectures V20211203 manual 8.6.4 Trap Return
	// The MRET instruction is used to return from a trap taken into M-mode. MRET first determines
	// what the new privilege mode will be according to the values of MPP and MPV in mstatus or
	// mstatush, as encoded in Table 8.8. MRET then in mstatus/mstatush sets MPV=0, MPP=0,
	// MIE=MPIE, and MPIE=1. Lastly, MRET sets the privilege mode as previously determined, and
	// sets pc = mepc.

	core->cur_privilege = core->mstatus.MPP;
	;
	// clear_bit2(&core->mstatus, MSTATUS_MPP); ??? dont work here
	core->mstatus.MIE = core->mstatus.MPIE;
	core->mstatus.MPIE = true;
	core->next_pc = core->mepc;
	return 0;
}

// int execute_store(ast_t inst, struct rvcore_rv32ima *core, struct platform *plat)
// {
// 	struct dram *dram = plat->dram;
// 	regtype rs1 = rX(core, inst.S.rs1);
// 	regtype rs2 = rX(core, inst.S.rs2);
// 	xlenbits imm = sign_ext(inst.S.imm_0_4 | inst.S.imm_5_11 << 5, 12);

// 	xlenbits vaddr = rs1 + imm;

// 	if (dram_is_in(dram, vaddr)) {
// 		xlenbits paddr = dram_virt_to_phys(dram, vaddr);
// 		switch (inst.S.funct3) {
// 		//SB, SH, SW
// 		case 0:
// 			dram_sb(dram, paddr, rs2);
// 			break;
// 		case 1:
// 			dram_sh(dram, paddr, rs2);
// 			break;
// 		case 2:
// 			dram_sw(dram, paddr, rs2);
// 			break;
// 		default:
// 			trap = (2 + 1);
// 		}
// 		return 0;
// 	}

// 	xlenbits addr_off = rs1 + imm - dram->base;

// 	if (addy >= plat->dram->size - 3) {
// 		addy += plat->dram->base;
// 		if (addy >= 0x10000000 && addy < 0x12000000) {
// 			// Should be stuff like SYSCON, 8250, CLNT
// 			if (addy == 0x11004004) //CLNT
// 				*((bits32 *)&plat->mtimecmp +
// 					1) = rs2;
// 			else if (addy == 0x11004000) //CLNT
// 				*((bits32 *)&plat->mtimecmp) =
// 					rs2;
// 			else if (addy ==
// 					0x11100000) //SYSCON (reboot, poweroff, etc.)
// 			{
// 				SETCSR(pc, core->pc + 4);
// 				return rs2; // NOTE: PC will be PC of Syscon.
// 			} else
// 				MINIRV32_HANDLE_MEM_STORE_CONTROL(
// 					addy, rs2);
// 		} else {
// 			trap = (7 + 1); // Store access fault.
// 			rval = addy;
// 		}
// 	} else {

// 	}
// }

// void proc_inst_priv(struct plattem *plat, struct inst inst)
// {

// 	} else if (((csrno & 0xff) == 0x02)) // MRET
// 	{
// 		//https://raw.githubusercontent.com/riscv/virtual-memory/main/specs/663-Svpbmt.pdf
// 		//Table 7.6. MRET then in mstatus/mstatush sets MPV=0, MPP=0, MIE=MPIE, and MPIE=1. La
// 		// Should also update mstatus to reflect correct mode.
// 		uint32_t startmstatus =
// 			CSR(mstatus);
// 		SETCSR(mstatus,
// 				((startmstatus &
// 				0x80) >>
// 			4) |
// 					(core->priv
// 				<< 11) |
// 					0x80);

// 		core->priv =
// 			((startmstatus >>
// 				11) &
// 				3);

// 		pc = CSR(mepc) - 4;
// 	} else {
// 		switch (csrno) {
// 		case 0:
// 			trap = (core->priv ==
// 				PRIV_MACHINE) ?
// 						(11 +
// 					1) :
// 						(8 +
// 					1);
// 			break; // ECALL; 8 = "Environment call from U-mode"; 11 = "Environment call from M-mode"
// 		case 1:
// 			trap = (3 + 1);
// 			break; // EBREAK 3 = "Breakpoint"
// 		default:
// 			trap = (2 + 1);
// 			break; // Illegal opcode.
// 		}
// 	}
// }

int step_rv32ima(struct platform *plat, uint64_t elapsed_us, int inst_batch)
{
	int err = 0;
	struct rvcore_rv32ima *core = plat->core;
	struct dram *dram = plat->dram;
	core->mtime.v += elapsed_us;

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

	for (int icount = 0; icount < inst_batch; icount++) {
		core->mcycle.v += 1;
		xlenbits pc = core->pc;

		if (!dram_is_in(dram, pc)) {
			handle_exception(core, E_Fetch_Access_Fault, pc);
			return 0;
		}

		if (pc & 0x3) {
			handle_exception(core, E_Fetch_Addr_Align, pc);
			return 0;
		}

		xlenbits ir = dram_lw(dram, pc);
		ast_t inst = { .bits = ir };
		core->next_pc = pc + 4;

		switch (inst.opcode) {
		case 0x37: // LUI (0b0110111)
			wX(core, inst.U.rd, inst.U.imm << 12);
			break;

		case 0x17: // AUIPC (0b0010111)
			wX(core, inst.U.rd, pc + (inst.U.imm << 12));
			break;

		case 0x6F: // JAL (0b1101111)
		{
			xlenbits imm = sign_ext(
				(inst.J.imm_1_10 << 1 | inst.J.imm_11 << 11 |
				 inst.J.imm_12_19 << 12 | inst.J.imm_20 << 20),
				21);

			wX(core, inst.J.rd, pc + 4);
			core->next_pc = pc + imm;
			break;
		}

		case 0x67: // JALR (0b1100111)
		{
			xlenbits imm = sign_ext(inst.I.imm, 12);
			// NOTICE, rs1 may override with rd, save rs1 first
			xlenbits rs1 = rX(core, inst.I.rs1);
			wX(core, inst.I.rd, pc + 4);
			core->next_pc = (rs1 + imm) & ~1;
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

			bool jumped = false;
			switch (inst.B.funct3) {
			// BEQ, BNE, BLT, BGE, BLTU, BGEU
			case 0:
				jumped = rs1 == rs2; // beq
				break;
			case 1:
				jumped = rs1 != rs2; // bne
				break;
			case 4:
				jumped = rs1 < rs2; // blt
				break;
			case 5:
				jumped = rs1 >= rs2; // bge
				break;
			case 6:
				jumped = (uint32_t)rs1 < (uint32_t)rs2; // bltu
				break;
			case 7:
				jumped = (uint32_t)rs1 >= (uint32_t)rs2; // bgeu
				break;
			default:
				handle_exception(core, E_Illegal_Instr, pc);
				return 0;
			}

			if (jumped)
				core->next_pc = pc + imm;

			break;
		}
		case 0x03: // Load (0b0000011) TODO
		{
			regtype rs1 = rX(core, inst.I.rs1);
			xlenbits imm = sign_ext(inst.I.imm, 12);
			xlenbits vaddr = rs1 + imm;
			xlenbits rval = 0;

			if (dram_is_in(dram, vaddr)) {
				switch ((ir >> 12) & 0x7) {
				//LB, LH, LW, LBU, LHU
				case 0:
					rval = dram_lb(dram, vaddr);
					break;
				case 1:
					rval = dram_lh(dram, vaddr);
					break;
				case 2:
					rval = dram_lw(dram, vaddr);
					break;
				case 4:
					rval = dram_lbu(dram, vaddr);
					break;
				case 5:
					rval = dram_lhu(dram, vaddr);
					break;
				default:
					handle_exception(core, E_Illegal_Instr,
							 inst.bits);
					return 0;
				}
				wX(core, inst.I.rd, rval);
				break;
			}

			if (vaddr >= 0x10000000 &&
			    vaddr < 0x12000000) // UART, CLNT
			{
				// https://chromitem-soc.readthedocs.io/en/latest/clint.html
				if (vaddr == 0x1100bffc)
					rval = core->mtime.high;
				else if (vaddr == 0x1100bff8)
					rval = core->mtime.low;
				else {
					if (plat->load)
						rval = plat->load(plat, vaddr);
				}
			} else {
				handle_exception(core, E_Load_Access_Fault,
						 vaddr);
				return 0;
			}
			wX(core, inst.I.rd, rval);
			break;
		}
		case 0x23: // Store 0b0100011 TODO
		{
			regtype rs1 = rX(core, inst.S.rs1);
			regtype rs2 = rX(core, inst.S.rs2);
			uint32_t addy = ((ir >> 7) & 0x1f) |
					((ir & 0xfe000000) >> 20);
			if (addy & 0x800)
				addy |= 0xfffff000;
			addy += rs1 - dram->base;
			xlenbits vaddr = addy + dram->base;

			if (addy >= dram->size - 3) {
				addy += dram->base;
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
						tick_pc(core);
						return rs2; // NOTE: PC will be PC of Syscon.

					} else {
						if (plat->store) {
							if ((err = plat->store(
								     plat, addy,
								     rs2)))
								return err;
						}
					}
				} else {
					handle_exception(core,
							 E_SAMO_Access_Fault,
							 addy);
					return 0;
				}
			} else {
				switch ((ir >> 12) & 0x7) {
				//SB, SH, SW
				case 0:
					dram_sb(dram, vaddr, rs2);
					break;
				case 1:
					dram_sh(dram, vaddr, rs2);
					break;
				case 2:
					dram_sw(dram, vaddr, rs2);
					break;
				default:
					handle_exception(core, E_Illegal_Instr,
							 inst.bits);
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
			regtype rs1 = rX(core, inst.R.rs1);
			uint32_t is_reg = !!(ir & 0x20);
			regtype rs2 = is_reg ? rX(core, inst.R.rs2) : imm;
			xlenbits rval = 0;

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
			wX(core, inst.R.rd, rval);
			break;
		}
		case 0x0f: // 0b0001111 fence
			break;
		case 0x73: // Zifencei+Zicsr  (0b1110011)
		{
			if ((inst.funct3 & MASK(2))) // Zicsr function.
			{
				if ((err = execute_Zicsr(inst, core, plat)))
					return err;

			} else if (inst.funct3 == 0x0) // "SYSTEM" 0b000
			{
				int csrno = inst.priv_I.imm;
				if (csrno == 0x105) //WFI (Wait for interrupts)
				{
					if ((err = execute_wfi(inst, core,
							       plat)))
						return err;

					tick_pc(core);
					return 1;

				} else if (((csrno & 0xff) == 0x02)) // MRET
				{
					if ((err = execute_mret(inst, core,
								plat)))
						return err;

				} else {
					switch (csrno) {
					case 0:
						if (core->cur_privilege ==
						    Machine) {
							handle_exception(
								core,
								E_M_EnvCall,
								pc);
							return 0;
						} else {
							handle_exception(
								core,
								E_U_EnvCall,
								pc);
							return 0;
						}
					case 1:
						handle_exception(
							core, E_Breakpoint, pc);
						return 0;
					default:
						handle_exception(
							core, E_Illegal_Instr,
							inst.bits);
						return 0;
					}
				}
			} else {
				handle_exception(core, E_Illegal_Instr,
						 inst.bits);
				return 0;
			}

			break;
		}
		case 0x2f: // RV32A (0b00101111)
		{
			regtype rs1 = rX(core, inst.R.rs1);
			regtype rs2 = rX(core, inst.R.rs2);
			uint32_t irmid = (ir >> 27) & 0x1f;
			xlenbits rval = 0;

			rs1 -= dram->base;
			xlenbits vaddr = rs1 + dram->base;

			// We don't implement load/store from UART or CLNT with RV32A here.
			if (rs1 >= dram->size - 3) {
				handle_exception(core, E_SAMO_Access_Fault,
						 rs1 + dram->base);
				return 0;
			}

			rval = dram_lw(dram, vaddr);

			// Referenced a little bit of https://github.com/franzflasch/riscv_em/blob/master/src/core/core.c
			uint32_t write_mem = 1;
			switch (irmid) {
			case 2: //LR.W (0b00010)
				write_mem = 0;
				plat->reservation = rs1;
				break;
			case 3: //SC.W (0b00011) (Make sure we have a slot, and, it's valid)
				rval = plat->reservation != rs1;
				write_mem =
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
				rs2 = ((int32_t)rs2 < (int32_t)rval) ? rs2 :
								       rval;
				break; //AMOMIN.W (0b10000)
			case 20:
				rs2 = ((int32_t)rs2 > (int32_t)rval) ? rs2 :
								       rval;
				break; //AMOMAX.W (0b10100)
			case 24:
				rs2 = (rs2 < rval) ? rs2 : rval;
				break; //AMOMINU.W (0b11000)
			case 28:
				rs2 = (rs2 > rval) ? rs2 : rval;
				break; //AMOMAXU.W (0b11100)
			default:
				handle_exception(core, E_Illegal_Instr,
						 inst.bits);
				return 0;
			}

			if (write_mem)
				dram_sw(dram, vaddr, rs2);

			wX(core, inst.R.rd, rval);
			break;
		}
		default:
			handle_exception(core, E_Illegal_Instr, inst.bits);
			return 0;
		}

		tick_pc(core);
	}

	return 0;
}