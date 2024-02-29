env = Environment(CFLAGS=['-Og', '-g', '-Wall'])

env.Program("qrvemu", ["qrvemu.c", 'riscv.c', "riscv.h"])


env.Command('q64mb.dtb', 'q64mb.dts', 'dtc -I dts -O dtb -o ${TARGET} ${SOURCE} -S 1536')

# env.Program("bintoh.c")
# env.Command('q64mb.h', ['q64mb.dtb', 'bintoh'], './bintoh q64mb_dtb < ${SOURCE} > ${TARGET}')

env.Command('run', ['qrvemu','q64mb.dtb'], './qrvemu -f kernel.img -b q64mb.dtb')