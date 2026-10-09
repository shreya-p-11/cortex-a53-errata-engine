    .text
    .global _start
    .balign 4096
_start:
    ldr x1, [x2]
    madd x3, x4, x5, x6
    ret
    .data
    .balign 8
mydata:
    .quad 0
