    .text
    .global _start
    .balign 4096
_start:
    .skip 0xFF8              // pad so the next instruction sits at page offset 0xFF8
    adrp x0, mydata
    ldr  x2, [x3]
    ldr  x1, [x0, :lo12:mydata]
    ret

    .data
    .balign 8
mydata:
    .quad 0
