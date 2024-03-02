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

#define READ_CSR(no, name) \
	case no: rval = core->name; break;
#define WRITE_CSR(no, name) \
	case no: core->name = write_val; break;

int execute_Zicsr(ast_t inst, struct rvcore_rv32ima *core, struct platform *plat) 
{
	xlenbits rval = 0;
	int i_rs1 = inst.Zicsr.rs1_uimm;
	xlenbits uimm = inst.Zicsr.rs1_uimm;
	xlenbits rs1 = core->regs[i_rs1];
	xlenbits write_val = rs1;

	// https://raw.githubusercontent.com/riscv/virtual-memory/main/specs/663-Svpbmt.pdf
	// Generally, support for Zicsr
	switch (inst.Zicsr.csr) {
		case 0xC00: rval = (xlenbits) core->mcycle.v; break;
		case 0xC01: rval = (xlenbits) core->mtime.v; break;
		case 0xC80: rval = core->mcycle.high; break;
		case 0xC81: rval = core->mtime.high;break;

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
		write_val = rval &~ rs1;
		break; //CSRRC
	case 5:
		write_val = uimm;
		break; //CSRRWI
	case 6:
		write_val = rval | uimm;
		break; //CSRRSI
	case 7:
		write_val = rval &~ uimm;
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

	core->cur_privilege = core->mstatus.MPP;;
	// clear_bit2(&core->mstatus, MSTATUS_MPP); ??? dont work here
	core->mstatus.MIE = core->mstatus.MPIE;
	core->mstatus.MPIE = true;
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
