#include <stdlib.h>
#include <stdio.h>
#include "riscv.h"

void sys_alloc_memory(struct system *sys, word_t base, word_t size)
{
    sys->ram_base = base;
    sys->ram_size = size;
    sys->image = calloc(size, 1);
    if (!sys->image) {
		fprintf(stderr, "Error: could not allocate system image.\n");
		exit(-4);
	}

}

#define READ_CSR(no, name) \
	case no: rval = sys->core->name; break;
#define WRITE_CSR(no, name) \
	case no: sys->core->name = write_val; break;

word_t handle_Zicsr(struct system *sys, struct inst inst) 
{
	word_t rval = 0;
	int i_rs1 = inst.Zicsr.rs1_uimm;
	word_t uimm = inst.Zicsr.rs1_uimm;
	word_t rs1 = sys->core->regs[i_rs1];
	word_t write_val = rs1;

	// https://raw.githubusercontent.com/riscv/virtual-memory/main/specs/663-Svpbmt.pdf
	// Generally, support for Zicsr
	switch (inst.Zicsr.csr) {
	READ_CSR(0xC00, cycle.low)
	READ_CSR(0xC80, cycle.low)

	READ_CSR(0xf11, mvendorid)
	READ_CSR(0x300, mstatus)
	READ_CSR(0x301, misa)
	READ_CSR(0x304, mie)
	READ_CSR(0x305, mtvec)

	READ_CSR(0x340, mscratch)
	READ_CSR(0x341, mepc)
	READ_CSR(0x342, mcause)
	READ_CSR(0x343, mtval)
	READ_CSR(0x344, mip)

	//case 0x3B0: rval = 0; break; //pmpaddr0
	//case 0x3a0: rval = 0; break; //pmpcfg0
	//case 0xf12: rval = 0x00000000; break; //marchid
	//case 0xf13: rval = 0x00000000; break; //mimpid
	//case 0xf14: rval = 0x00000000; break; //mhartid
	default:
		if (sys->read_csr)
			rval = sys->read_csr(sys, inst);
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
	WRITE_CSR(0x300, mstatus)
	WRITE_CSR(0x304, mie)
	WRITE_CSR(0x305, mtvec)
	WRITE_CSR(0x340, mscratch)
	WRITE_CSR(0x341, mepc)
	WRITE_CSR(0x342, mcause)
	WRITE_CSR(0x343, mtval)
	WRITE_CSR(0x344, mip)

	default:
		if (sys->write_csr)
			sys->write_csr(sys, inst, write_val);
		break;
	}

	return rval;
}


void dump_sys(struct system *sys)
{
	uint32_t pc = sys->core->pc;
	uint32_t pc_offset = pc - sys->ram_base;
	uint32_t ir = 0;

	printf("PC: %08x ", pc);
	if (pc_offset >= 0 && pc_offset < sys->ram_size - 3) {
		ir = *((uint32_t *)(&((uint8_t *)sys->image)[pc_offset]));
		printf("[0x%08x] ", ir);
	} else
		printf("[xxxxxxxxxx] ");
	uint32_t *regs = sys->core->regs;
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