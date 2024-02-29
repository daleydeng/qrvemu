env = Environment(CFLAGS=['-Og', '-g', '-Wall'])

env.Program("qrvemu", ["qrvemu.c", 'riscv.c', "riscv.h", 'utils.c'])


env.Command('q64mb.dtb', 'q64mb.dts', 'dtc -I dts -O dtb -o ${TARGET} ${SOURCE} -a 8')

env.Command('run', ['qrvemu','q64mb.dtb'], './qrvemu -f kernel.img -b q64mb.dtb')

env.Default('qrvemu')