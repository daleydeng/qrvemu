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

#define READ_CSR(no, name)       \
	case no:                 \
		rd = core->name; \
		break;
#define WRITE_CSR(no, name)             \
	case no:                        \
		core->name = write_val; \
		break;

enum ExeResult execute_Zicsr(ast_t inst, struct rvcore_rv32ima *core,
		  struct platform *plat)
{
	xlenbits rd = 0;
	int i_rs1 = inst.Zicsr.rs1_uimm;
	xlenbits uimm = inst.Zicsr.rs1_uimm;
	xlenbits rs1 = core->regs[i_rs1];
	xlenbits write_val = rs1;

	// https://raw.githubusercontent.com/riscv/virtual-memory/main/specs/663-Svpbmt.pdf
	// Generally, support for Zicsr
	switch (inst.Zicsr.csr) {
	case 0xC00:
		rd = (xlenbits)core->mcycle.v;
		break;
	case 0xC01:
		rd = (xlenbits)core->mtime.v;
		break;
	case 0xC80:
		rd = core->mcycle.high;
		break;
	case 0xC81:
		rd = core->mtime.high;
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

	//case 0x3B0: rd = 0; break; //pmpaddr0
	//case 0x3a0: rd = 0; break; //pmpcfg0
	//case 0xf12: rd = 0x00000000; break; //marchid
	//case 0xf13: rd = 0x00000000; break; //mimpid
	//case 0xf14: rd = 0x00000000; break; //mhartid
	default:
		if (plat->read_csr)
			rd = plat->read_csr(plat, inst);
		break;
	}

	switch (inst.Zicsr.funct3) {
	case 1:
		write_val = rs1;
		break; //CSRRW
	case 2:
		write_val = rd | rs1;
		break; //CSRRS
	case 3:
		write_val = rd & ~rs1;
		break; //CSRRC
	case 5:
		write_val = uimm;
		break; //CSRRWI
	case 6:
		write_val = rd | uimm;
		break; //CSRRSI
	case 7:
		write_val = rd & ~uimm;
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

	wX(core, inst.Zicsr.rd, rd);
	return EXE_OK;
}

enum ExeResult execute_wfi(ast_t inst, struct rvcore_rv32ima *core, struct platform *plat)
{
	assert(inst.I.imm == 0x105);
	core->mstatus.MIE = true;
	plat->wfi = true;
	return EXE_OK;
}

enum ExeResult execute_mret(ast_t inst, struct rvcore_rv32ima *core, struct platform *plat)
{
	assert(inst.I.imm == 0x302); // 0b0011 0000 0010
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
	return EXE_OK;
}

enum ExeResult execute_mext(ast_t inst, struct rvcore_rv32ima *core, struct platform *plat) // adapt to XLEN
{
	regtype rs1 = rX(core, inst.R.rs1);
	regtype rs2 = rX(core, inst.R.rs2);
	regtype rd = 0;

	switch (inst.R.funct3) //0x02000000 = RV32M
	{
	case 0: // mul
		rd = rs1 * rs2;
		break;
	case 1: // mulh
		rd = ((int64_t)((int32_t)rs1) * (int64_t)((int32_t)rs2)) >> 32;
		break; // MULH
	case 2: // mulhsu
		rd = ((int64_t)((int32_t)rs1) * (uint64_t)rs2) >> 32;
		break;
	case 3: // mulhu
		rd = ((uint64_t)rs1 * (uint64_t)rs2) >> 32;
		break;
	case 4: // div
		if (rs2 == 0)
			rd = -1;
		else
			rd = ((int32_t)rs1 == INT32_MIN && (int32_t)rs2 == -1) ?
				     rs1 :
				     ((int32_t)rs1 / (int32_t)rs2);
		break;
	case 5: // divu
		if (rs2 == 0)
			rd = 0xffffffff;
		else
			rd = rs1 / rs2;
		break;
	case 6: // rem
		if (rs2 == 0)
			rd = rs1;
		else
			rd = ((int32_t)rs1 == INT32_MIN && (int32_t)rs2 == -1) ?
				     0 :
				     ((uint32_t)((int32_t)rs1 % (int32_t)rs2));
		break;
	case 7: // remu
		if (rs2 == 0)
			rd = rs1;
		else
			rd = rs1 % rs2;
		break;
	}
	wX(core, inst.R.rd, rd);
	return EXE_OK;
}

enum ExeResult execute_aext(ast_t inst, struct rvcore_rv32ima *core, struct platform *plat)
{

	return EXE_OK;
}

enum ExeResult step_rv32ima(struct platform *plat, uint64_t elapsed_us, int inst_batch)
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
		return EXE_WFI;

	if (check_interrupt(core, I_M_Timer)) {
		handle_interrupt(core, I_M_Timer);
		return EXE_INTR;
	}

	for (int icount = 0; icount < inst_batch; icount++) {
		core->mcycle.v += 1;
		xlenbits pc = core->pc;

		if (!dram_is_in(dram, pc)) {
			handle_exception(core, E_Fetch_Access_Fault, pc);
			return EXE_EXC;
		}

		if (pc & 0x3) {
			handle_exception(core, E_Fetch_Addr_Align, pc);
			return EXE_EXC;
		}

		xlenbits ir = dram_lw(dram, pc);
		ast_t inst = { .bits = ir };
		core->next_pc = pc + 4;

		switch (inst.opcode) {
		case 0x37: // LUI (0b0110111)
		{
			xlenbits imm = inst.U.imm
				       << 12; // 32bit no sign_ext needed
			wX(core, inst.U.rd, imm);
			break;
		}
		case 0x17: // AUIPC (0b0010111)
		{
			xlenbits imm = inst.U.imm
				       << 12; // 32bit no sign_ext needed
			wX(core, inst.U.rd, pc + imm);
			break;
		}
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
				return EXE_EXC;
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
			xlenbits rd = 0;

			if (dram_is_in(dram, vaddr)) {
				switch (inst.I.funct3) {
				//LB, LH, LW, LBU, LHU
				case 0:
					rd = dram_lb(dram, vaddr);
					break;
				case 1:
					rd = dram_lh(dram, vaddr);
					break;
				case 2:
					rd = dram_lw(dram, vaddr);
					break;
				case 4:
					rd = dram_lbu(dram, vaddr);
					break;
				case 5:
					rd = dram_lhu(dram, vaddr);
					break;
				default:
					handle_exception(core, E_Illegal_Instr,
							 inst.bits);
					return EXE_EXC;
				}
				wX(core, inst.I.rd, rd);
				break;
			}

			if (vaddr >= 0x10000000 &&
			    vaddr < 0x12000000) // UART, CLNT
			{
				// https://chromitem-soc.readthedocs.io/en/latest/clint.html
				if (vaddr == 0x1100bffc)
					rd = core->mtime.high;
				else if (vaddr == 0x1100bff8)
					rd = core->mtime.low;
				else {
					if (plat->load)
						rd = plat->load(plat, vaddr);
				}
			} else {
				handle_exception(core, E_Load_Access_Fault,
						 vaddr);
				return EXE_EXC;
			}
			wX(core, inst.I.rd, rd);
			break;
		}
		case 0x23: // Store 0b0100011 TODO
		{
			regtype rs1 = rX(core, inst.S.rs1);
			regtype rs2 = rX(core, inst.S.rs2);
			xlenbits imm = sign_ext(
				inst.S.imm_0_4 | inst.S.imm_5_11 << 5, 12);
			xlenbits vaddr = rs1 + imm;

			if (dram_is_in(dram, vaddr)) {
				switch (inst.S.funct3) {
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
					return EXE_EXC;
				}
				break;
			}

			if (vaddr >= 0x10000000 && vaddr < 0x12000000) {
				// Should be stuff like SYSCON, 8250, CLNT
				if (vaddr == 0x11004004) //CLNT
					*((bits32 *)&plat->mtimecmp + 1) = rs2;
				else if (vaddr == 0x11004000) //CLNT
					*((bits32 *)&plat->mtimecmp) = rs2;
				else if (vaddr ==
					 0x11100000) //SYSCON (reboot, poweroff, etc.)
				{
					tick_pc(core);
					return rs2; // NOTE: PC will be PC of Syscon.

				} else {
					if (plat->store) {
						if ((err = plat->store(
							     plat, vaddr, rs2)))
							return err;
					}
				}
			} else {
				handle_exception(core, E_SAMO_Access_Fault,
						 vaddr);
				return EXE_EXC;
			}
			break;
		}
		case 0x13: // Op-immediate 0b0010011
		{
			xlenbits imm = sign_ext(inst.I.imm, 12);
			xlenbits imm_5_11 = imm >> 5;
			xlenbits shamt = XLEN == 32 ? imm & MASK(5) : imm;
			regtype rs1 = rX(core, inst.R.rs1);
			xlenbits rd = 0;

			switch (inst.I.funct3) {
			case 0: // addi
				rd = rs1 + imm;
				break;
			case 2: // slti
				rd = (s_xlenbits)rs1 < (s_xlenbits)imm;
				break;
			case 3: // sltiu
				rd = rs1 < imm;
				break;
			case 7: // andi
				rd = rs1 & imm;
				break;
			case 6: // ori
				rd = rs1 | imm;
				break;
			case 4: // xori
				rd = rs1 ^ imm;
				break;

			case 1: // slli
				if (XLEN == 32)
					assert(imm_5_11 == 0);
				rd = rs1 << shamt;
				break;

			case 5:
				if (imm_5_11 == 0) { // srli
					rd = rs1 >> shamt;
				} else if (imm_5_11 == 0x20) { // srai
					rd = ((s_xlenbits)rs1) >> shamt;
				}
				break;
			}
			wX(core, inst.R.rd, rd);
			break;
		}
		case 0x33: // Op           0b0110011
		{
			regtype rs1 = rX(core, inst.R.rs1);
			regtype rs2 = rX(core, inst.R.rs2);
			int shamt = XLEN == 32 ? rs2 & MASK(5) : rs2;

			xlenbits rd = 0;
			if (inst.R.funct7 == 0 || inst.R.funct7 == 0x20) {
				switch (inst.R.funct3) {
				case 0: // add/sub
					rd = (inst.R.funct7 == 0x20) ?
						     (rs1 - rs2) :
						     (rs1 + rs2);
					break;
				case 1: // sll
					rd = rs1 << shamt;
					break;
				case 2: // slt
					rd = (s_xlenbits)rs1 < (s_xlenbits)rs2;
					break;
				case 3: // sltu
					rd = rs1 < rs2;
					break;
				case 4: // xor
					rd = rs1 ^ rs2;
					break;
				case 5: // srl/sra
					rd = (inst.R.funct7 == 0x20) ?
						     (((int32_t)rs1) >> shamt) :
						     (rs1 >> shamt);
					break;
				case 6:
					rd = rs1 | rs2;
					break;
				case 7:
					rd = rs1 & rs2;
					break;
				}
				wX(core, inst.R.rd, rd);

			} else if (inst.R.funct7 == 1) {
				if ((err = execute_mext(inst, core, plat)))
					return err;
			} else {
				handle_exception(core, E_Illegal_Instr,
						 inst.bits);
				return EXE_EXC;
			}
			break;
		}
		case 0x0f: // 0b0001111 fence
			break;
		case 0x73: // Zifencei+Zicsr  (0b1110011)
		{
			if ((inst.funct3 & MASK(2))) { // Zicsr function.
				if ((err = execute_Zicsr(inst, core, plat)))
					return err;
				break;
			}

			if (inst.I.funct3 == 0 && inst.I.imm == 0) {// ecall
				enum ExceptionType exc = core->cur_privilege == Machine ? E_M_EnvCall : E_U_EnvCall;
				handle_exception(core, exc, pc);
				return EXE_EXC;
			}

			if (inst.I.funct3 == 0 && inst.I.imm == 1) {// ebreak
				handle_exception(core, E_Breakpoint, pc);
				return EXE_EXC;
			}

			if (inst.funct3 == 0 && inst.I.imm == 0x105) { // wfi
				if ((err = execute_wfi(inst, core, plat)))
					return err;

				tick_pc(core);
				return EXE_WFI;
			}

			if (inst.funct3 == 0 && inst.I.imm == 0x302) // MRET
			{
				if ((err = execute_mret(inst, core, plat)))
					return err;
				break;
			}

			handle_exception(core, E_Illegal_Instr, inst.bits);
			return EXE_EXC;
		}
		case 0x2f: // RV32A (0b00101111)
		{
			regtype rs1 = rX(core, inst.R.rs1);
			regtype rs2 = rX(core, inst.R.rs2);
			uint32_t irmid = (ir >> 27) & 0x1f;
			xlenbits rd = 0;

			rs1 -= dram->base;
			xlenbits vaddr = rs1 + dram->base;

			// We don't implement load/store from UART or CLNT with RV32A here.
			if (rs1 >= dram->size - 3) {
				handle_exception(core, E_SAMO_Access_Fault,
						 rs1 + dram->base);
				return EXE_EXC;
			}

			rd = dram_lw(dram, vaddr);

			// Referenced a little bit of https://github.com/franzflasch/riscv_em/blob/master/src/core/core.c
			uint32_t write_mem = 1;
			switch (irmid) {
			case 2: //LR.W (0b00010)
				write_mem = 0;
				plat->reservation = rs1;
				break;
			case 3: //SC.W (0b00011) (Make sure we have a slot, and, it's valid)
				rd = plat->reservation != rs1;
				write_mem = !rd; // Only write if slot is valid.
				break;
			case 1:
				break; //AMOSWAP.W (0b00001)
			case 0:
				rs2 += rd;
				break; //AMOADD.W (0b00000)
			case 4:
				rs2 ^= rd;
				break; //AMOXOR.W (0b00100)
			case 12:
				rs2 &= rd;
				break; //AMOAND.W (0b01100)
			case 8:
				rs2 |= rd;
				break; //AMOOR.W (0b01000)
			case 16:
				rs2 = ((int32_t)rs2 < (int32_t)rd) ? rs2 : rd;
				break; //AMOMIN.W (0b10000)
			case 20:
				rs2 = ((int32_t)rs2 > (int32_t)rd) ? rs2 : rd;
				break; //AMOMAX.W (0b10100)
			case 24:
				rs2 = (rs2 < rd) ? rs2 : rd;
				break; //AMOMINU.W (0b11000)
			case 28:
				rs2 = (rs2 > rd) ? rs2 : rd;
				break; //AMOMAXU.W (0b11100)
			default:
				handle_exception(core, E_Illegal_Instr,
						 inst.bits);
				return EXE_EXC;
			}

			if (write_mem)
				dram_sw(dram, vaddr, rs2);

			wX(core, inst.R.rd, rd);
			break;
		}
		default:
			handle_exception(core, E_Illegal_Instr, inst.bits);
			return EXE_EXC;
		}

		tick_pc(core);
	}

	return EXE_OK;
}