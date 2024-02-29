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

#ifndef MINIRV32_OTHERCSR_WRITE
#define MINIRV32_OTHERCSR_WRITE(...) ;
#endif

#ifndef MINIRV32_OTHERCSR_READ
#define MINIRV32_OTHERCSR_READ(...) ;
#endif

#define read_csr(no, name) \
	case no: rval = core->name; break;
#define write_csr(no, name) \
	case no: core->name = write_val; break;

void handle_Zicsr(struct rvcore_rv32ima *core, struct inst inst, uint8_t *image) 
{
	word_t rval = 0;
	int i_rs1 = inst.Zicsr.rs1_uimm;
	word_t uimm = inst.Zicsr.rs1_uimm;
	word_t rs1 = core->regs[i_rs1];
	word_t write_val = rs1;

	// https://raw.githubusercontent.com/riscv/virtual-memory/main/specs/663-Svpbmt.pdf
	// Generally, support for Zicsr
	switch (inst.Zicsr.csr) {
	read_csr(0xC00, cycle.low)
	read_csr(0xC80, cycle.low)

	read_csr(0xf11, mvendorid)
	read_csr(0x300, mstatus)
	read_csr(0x301, misa)
	read_csr(0x304, mie)
	read_csr(0x305, mtvec)

	read_csr(0x340, mscratch)
	read_csr(0x341, mepc)
	read_csr(0x342, mcause)
	read_csr(0x343, mtval)
	read_csr(0x344, mip)

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
	write_csr(0x300, mstatus)
	write_csr(0x304, mie)
	write_csr(0x305, mtvec)
	write_csr(0x340, mscratch)
	write_csr(0x341, mepc)
	write_csr(0x342, mcause)
	write_csr(0x343, mtval)
	write_csr(0x344, mip)

	default:
		MINIRV32_OTHERCSR_WRITE(
			inst.Zicsr.csr,
			write_val);
		break;
	}
}