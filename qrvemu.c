#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int fail_on_all_faults = 0;

static int64_t SimpleReadNumberInt(const char *number, int64_t defaultNumber);
static uint64_t GetTimeMicroseconds();
static void ResetKeyboardInput();
static void CaptureKeyboardInput();
static uint32_t HandleException(uint32_t ir, uint32_t retval);
static uint32_t HandleControlStore(uint32_t addy, uint32_t val);
static uint32_t HandleControlLoad(uint32_t addy);
static void MiniSleep();
static int IsKBHit();
static int ReadKBByte();

// This is the functionality we want to override in the emulator.
//  think of this as the way the emulator's processor is connected to the
//  outside world.
#define MINIRV32_POSTEXEC(pc, ir, retval)                             \
	{                                                             \
		if (retval > 0) {                                     \
			if (fail_on_all_faults) {                     \
				printf("FAULT\n");                    \
				return 3;                             \
			} else                                        \
				retval = HandleException(ir, retval); \
		}                                                     \
	}
#define MINIRV32_HANDLE_MEM_STORE_CONTROL(addy, val) \
	if (HandleControlStore(addy, val))           \
		return val;
#define MINIRV32_HANDLE_MEM_LOAD_CONTROL(addy, rval) \
	rval = HandleControlLoad(addy);

#include "riscv1.h"
#include "utils.h"

static xlenbits read_other_csr(struct system *sys, ast_t inst);
static void write_other_csr(struct system *sys, ast_t inst, xlenbits val);

size_t RAM_BASE = 0x80000000;
size_t RAM_SIZE = 64 * 1024 * 1024;

struct system *sys = NULL;

int main(int argc, char **argv)
{
	const char *kernel_command_line = 0;
	int i;
	long long instct = -1;
	int show_help = 0;
	int time_divisor = 1;
	int fixed_update = 0;
	int do_sleep = 1;
	int single_step = 0;
	const char *image_file_name = 0;
	const char *dtb_file_name = 0;
	for (i = 1; i < argc; i++) {
		const char *param = argv[i];
		int param_continue = 0; // Can combine parameters, like -lpt x
		do {
			if (param[0] == '-' || param_continue) {
				switch (param[1]) {
				case 'm':
					if (++i < argc)
						RAM_SIZE = SimpleReadNumberInt(
							argv[i], RAM_SIZE);
					break;
				case 'c':
					if (++i < argc)
						instct = SimpleReadNumberInt(
							argv[i], -1);
					break;
				case 'k':
					if (++i < argc)
						kernel_command_line = argv[i];
					break;
				case 'f':
					image_file_name =
						(++i < argc) ? argv[i] : 0;
					break;
				case 'b':
					dtb_file_name = (++i < argc) ? argv[i] :
								       0;
					break;
				case 'l':
					param_continue = 1;
					fixed_update = 1;
					break;
				case 'p':
					param_continue = 1;
					do_sleep = 0;
					break;
				case 's':
					param_continue = 1;
					single_step = 1;
					break;
				case 'd':
					param_continue = 1;
					fail_on_all_faults = 1;
					break;
				case 't':
					if (++i < argc)
						time_divisor =
							SimpleReadNumberInt(
								argv[i], 1);
					break;
				default:
					if (param_continue)
						param_continue = 0;
					else
						show_help = 1;
					break;
				}
			} else {
				show_help = 1;
				break;
			}
			param++;
		} while (param_continue);
	}
	if (show_help || image_file_name == 0 || time_divisor <= 0) {
		fprintf(stderr,
			"./mini-rv32imaf [parameters]\n\t-m [ram amount]\n\t-f [running "
			"image]\n\t-k [kernel command line]\n\t-b [dtb file, or "
			"'disable']\n\t-c instruction count\n\t-s single step with full "
			"processor state\n\t-t time divion base\n\t-l lock time base to "
			"instruction count\n\t-p disable sleep when wfi\n\t-d fail out "
			"immediately on all faults\n");
		return 1;
	}


	sys = calloc(1, sizeof(struct system));
	assert(sys);
	sys_alloc_memory(sys, RAM_BASE, RAM_SIZE);
	sys->read_csr = read_other_csr;
	sys->write_csr = write_other_csr;

	long flen = 0;
	size_t dtb_len = 0;

restart:
	if ((flen = load_file(sys->image, sys->ram_size, image_file_name, false)) < 0)
		return flen;

	if (!dtb_file_name) {
		fprintf(stderr,
			"Error: Could not open dtb \"%s\"\n",
			dtb_file_name);
		return -9;
	}

	if ((dtb_len = load_file(sys->image, sys->ram_size, dtb_file_name, true)) < 0)
	    return dtb_len;

	if( kernel_command_line )
		strncpy( (char*)(sys_ram_end(sys) - dtb_len + 0xc0 ), kernel_command_line, 54 );

	CaptureKeyboardInput();

	struct rvcore_rv32ima *core = calloc(1, sizeof(struct rvcore_rv32ima));
	core->pc = RAM_BASE;
	core->regs[R_a0] = 0x00; // hart ID
	core->regs[R_a1] = RAM_BASE + RAM_SIZE - dtb_len;
	core->priv = PRIV_MACHINE; // Machine-mode.

	sys->core = core;

	// Image is loaded.
	uint64_t rt;
	uint64_t lastTime =
		(fixed_update) ? 0 : (GetTimeMicroseconds() / time_divisor);
	int instrs_per_flip = single_step ? 1 : 1024;
	for (rt = 0; rt < instct + 1 || instct < 0; rt += instrs_per_flip) {
		uint64_t *this_ccount = ((uint64_t *)&core->cycle.low);
		uint32_t elapsedUs = 0;
		if (fixed_update)
			elapsedUs = *this_ccount / time_divisor - lastTime;
		else
			elapsedUs =
				GetTimeMicroseconds() / time_divisor - lastTime;
		lastTime += elapsedUs;

		if (single_step)
			dump_sys(sys);

		int ret = MiniRV32IMAStep(
			sys,
			core, sys->image, 0, elapsedUs,
			instrs_per_flip); // Execute upto 1024 cycles before breaking out.
		switch (ret) {
		case 0:
			break;
		case 1:
			if (do_sleep)
				MiniSleep();
			*this_ccount += instrs_per_flip;
			break;
		case 3:
			instct = 0;
			break;
		case 0x7777:
			goto restart; // syscon code for restart
		case 0x5555:
			printf("POWEROFF@0x%08x%08x\n", core->cycle.high,
			       core->cycle.low);
			return 0; // syscon code for power-off
		default:
			printf("Unknown failure\n");
			break;
		}
	}

	dump_sys(sys);
}

//////////////////////////////////////////////////////////////////////////
// Platform-specific functionality
//////////////////////////////////////////////////////////////////////////

#include <signal.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <termios.h>
#include <unistd.h>

static void CtrlC()
{
	dump_sys(sys);
	exit(0);
}

// Override keyboard, so we can capture all keyboard input for the VM.
static void CaptureKeyboardInput()
{
	// Hook exit, because we want to re-enable keyboard.
	atexit(ResetKeyboardInput);
	signal(SIGINT, CtrlC);

	struct termios term;
	tcgetattr(0, &term);
	term.c_lflag &= ~(ICANON | ECHO); // Disable echo as well
	tcsetattr(0, TCSANOW, &term);
}

static void ResetKeyboardInput()
{
	// Re-enable echo, etc. on keyboard.
	struct termios term;
	tcgetattr(0, &term);
	term.c_lflag |= ICANON | ECHO;
	tcsetattr(0, TCSANOW, &term);
}

static void MiniSleep()
{
	usleep(500);
}

static uint64_t GetTimeMicroseconds()
{
	struct timeval tv;
	gettimeofday(&tv, 0);
	return tv.tv_usec + ((uint64_t)(tv.tv_sec)) * 1000000LL;
}

static int is_eofd;

static int ReadKBByte()
{
	if (is_eofd)
		return 0xffffffff;
	char rxchar = 0;
	int rread = read(fileno(stdin), (char *)&rxchar, 1);

	if (rread > 0) // Tricky: getchar can't be used with arrow keys.
		return rxchar;
	else
		return -1;
}

static int IsKBHit()
{
	if (is_eofd)
		return -1;
	int byteswaiting;
	ioctl(0, FIONREAD, &byteswaiting);
	if (!byteswaiting && write(fileno(stdin), 0, 0) != 0) {
		is_eofd = 1;
		return -1;
	} // Is end-of-file for
	return !!byteswaiting;
}

//////////////////////////////////////////////////////////////////////////
// Rest of functions functionality
//////////////////////////////////////////////////////////////////////////

static uint32_t HandleException(uint32_t ir, uint32_t code)
{
	// Weird opcode emitted by duktape on exit.
	if (code == 3) {
		// Could handle other opcodes here.
	}
	return code;
}

static uint32_t HandleControlStore(uint32_t addy, uint32_t val)
{
	if (addy == 0x10000000) // UART 8250 / 16550 Data Buffer
	{
		printf("%c", val);
		fflush(stdout);
	}
	return 0;
}

static uint32_t HandleControlLoad(uint32_t addy)
{
	// Emulating a 8250 / 16550 UART
	if (addy == 0x10000005)
		return 0x60 | IsKBHit();
	else if (addy == 0x10000000 && IsKBHit())
		return ReadKBByte();
	return 0;
}

static void write_other_csr(struct system *sys, ast_t inst, xlenbits val)
{
	xlenbits ptrstart, ptrend;

	switch (inst.Zicsr.csr) {
	case 0x136:
		printf("%d", val);
		fflush(stdout);
		break;

	case 0x137:
		printf("%08x", val);
		fflush(stdout);
		break;

	case 0x138:
		// Print "string"
		ptrstart = val - sys->ram_base;
		ptrend = ptrstart;
		if (ptrstart >= sys->ram_size)
			printf("DEBUG PASSED INVALID PTR (%08x)\n", val);
		while (ptrend < sys->ram_size) {
			if (sys->image[ptrend] == 0)
				break;
			ptrend++;
		}

		if (ptrend != ptrstart)
			fwrite(sys->image + ptrstart, ptrend - ptrstart, 1, stdout);
		break;

	case 0x139:
		putchar(val);
		fflush(stdout);
		break;
	}
}

static xlenbits read_other_csr(struct system *sys, ast_t inst)
{
	if (inst.Zicsr.csr == 0x140) {
		if (!IsKBHit())
			return -1;
		return ReadKBByte();
	}
	return 0;
}

static int64_t SimpleReadNumberInt(const char *number, int64_t defaultNumber)
{
	if (!number || !number[0])
		return defaultNumber;
	int radix = 10;
	if (number[0] == '0') {
		char nc = number[1];
		number += 2;
		if (nc == 0)
			return 0;
		else if (nc == 'x')
			radix = 16;
		else if (nc == 'b')
			radix = 2;
		else {
			number--;
			radix = 8;
		}
	}
	char *endptr;
	uint64_t ret = strtoll(number, &endptr, radix);
	if (endptr == number) {
		return defaultNumber;
	} else {
		return ret;
	}
}