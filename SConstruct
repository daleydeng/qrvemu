env = Environment(CFLAGS=['-O0', '-g', '-Wall'])

env.Program("qrvemu", ["qrvemu.c", 'riscv.c', "riscv.h", 'utils.c'])

env.Command('q64mb.dtb', 'q64mb.dts', 'dtc -I dts -O dtb -o ${TARGET} ${SOURCE} -a 8')
env.Command('rvemu.dtb', 'rvemu.dts', 'dtc -I dts -O dtb -o ${TARGET} ${SOURCE} -a 8')

env.Command('run_q', ['q64mb.dtb', 'qrvemu'], './qrvemu -f kernel.img -b ${SOURCE}')
env.Command('run_r', ['rvemu.dtb', 'qrvemu'], './qrvemu -f kernel.img -b ${SOURCE}')

env.Default('qrvemu', 'q64mb.dtb', 'rvemu.dtb')