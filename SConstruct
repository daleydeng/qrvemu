import os.path as osp

env = Environment(CFLAGS=['-O0', '-g', '-Wall'])

env.Program("qrvemu", ["qrvemu.c", 'riscv.c', "riscv.h", 'utils.c'])

env.Command('q64mb.dtb', 'q64mb.dts', 'dtc -I dts -O dtb -o ${TARGET} ${SOURCE} -a 8')
env.Command('rvemu.dtb', 'rvemu.dts', 'dtc -I dts -O dtb -o ${TARGET} ${SOURCE} -a 8')

env.Command('run_q', ['q64mb.dtb', 'qrvemu'], './qrvemu -f kernel.img -b ${SOURCE}')
env.Command('run_r', ['rvemu.dtb', 'qrvemu'], './qrvemu -f kernel.img -b ${SOURCE}')

env.Command('debug_q', ['q64mb.dtb', 'qrvemu'], 'gdb --args ./qrvemu -f kernel.img -b ${SOURCE}')


env.Default('qrvemu', 'q64mb.dtb', 'rvemu.dtb', 'baremetal.bin', 'baremetal.debug.txt')


CROSS = osp.expanduser("~/riscv/toolchain/riscv32-elf-llvm/bin/riscv32-unknown-elf-")
dir = 'examples/baremetal/'
env = Environment()
# env.Command("baremetal.elf", [ f"{dir}baremetal.c", f"{dir}baremetal.S", f"{dir}/flatfile.lds",], 
#             f"{CROSS}gcc -o $TARGET ${{SOURCES[:-1]}} -fno-stack-protector -static-libgcc -fdata-sections -ffunction-sections\
#                 -g -Os -march=rv32ima_zicsr -mabi=ilp32 -static -T ${{SOURCES[-1]}} -nostdlib -Wl,--gc-sections")

env.Command("baremetal.elf", [ f"{dir}baremetal.c", f"{dir}baremetal.S", f"{dir}/flatfile.lds",], 
            f"{CROSS}gcc -o $TARGET ${{SOURCES[:-1]}} -fno-stack-protector \
                -g -Os -march=rv32ima_zicsr -mabi=ilp32 -nostdlib -T ${{SOURCES[-1]}}")

env.Command('baremetal.bin', 'baremetal.elf', 'llvm-objcopy -O binary $SOURCE $TARGET')
env.Command('baremetal.debug.txt', 'baremetal.elf', 'llvm-objdump -tS $SOURCE > $TARGET')

env.Command('run_bare', ['qrvemu', 'baremetal.bin'], './$SOURCE -f ${SOURCES[1]}')