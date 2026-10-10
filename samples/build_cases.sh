set -e
mkdir -p samples/build

body_only() { sed '1,/Disassembly of section/d'; }

make_case() {  # name, skip bytes, expected detector verdict, assembly body, [rule]
  name=$1; skip=$2; expected=$3; body=$4; rule=${5:-843419}
  cat > samples/build/$name.S <<EOF
    .text
    .global _start
    .balign 4096
_start:
    .skip $skip
$body
    ret
    .data
    .balign 8
mydata:
    .quad 0
EOF
  aarch64-linux-gnu-as samples/build/$name.S -o samples/build/$name.o
  aarch64-linux-gnu-ld -Ttext=0x400000 samples/build/$name.o -o samples/build/$name.elf
  aarch64-linux-gnu-ld -Ttext=0x400000 --fix-cortex-a53-843419 samples/build/$name.o -o samples/build/${name}_fixed.elf
  if diff -q <(aarch64-linux-gnu-objdump -d samples/build/$name.elf | body_only) \
             <(aarch64-linux-gnu-objdump -d samples/build/${name}_fixed.elf | body_only) >/dev/null; then
    linker="unchanged"
  else
    linker="CHANGED"
  fi
  got=$(python -m scanner.cli --elf samples/build/$name.elf --rule $rule 2>&1 | awk '/Verdict:/ {print $3}')
  if [ "$got" = "$expected" ]; then ok="OK"; else ok="MISMATCH"; fi
  printf "%-14s %-11s %-11s %-9s %s\n" "$name" "$expected" "$got" "$linker" "$ok"
}

printf "%-14s %-11s %-11s %-9s %s\n" CASE EXPECTED DETECTOR LINKER-FIX RESULT
make_case seq1_basic   0xFF8 VULNERABLE $'    adrp x0, mydata\n    ldr x2, [x3]\n    ldr x1, [x0, :lo12:mydata]'
make_case seq1_gap     0xFF8 VULNERABLE $'    adrp x0, mydata\n    ldr x2, [x3]\n    mov x4, x5\n    ldr x1, [x0, :lo12:mydata]'
make_case seq1_at_ffc  0xFFC VULNERABLE $'    adrp x0, mydata\n    ldr x2, [x3]\n    ldr x1, [x0, :lo12:mydata]'
make_case safe_offset  0xFF0 CLEAN      $'    adrp x0, mydata\n    ldr x2, [x3]\n    ldr x1, [x0, :lo12:mydata]'
make_case too_far      0xFF8 CLEAN      $'    adrp x0, mydata\n    ldr x2, [x3]\n    mov x4, x5\n    mov x6, x7\n    ldr x1, [x0, :lo12:mydata]'
make_case writes_rn    0xFF8 CLEAN      $'    adrp x0, mydata\n    ldr x0, [x3]\n    ldr x1, [x0, #8]'
make_case not_unsigned 0xFF8 CLEAN      $'    adrp x0, mydata\n    ldr x2, [x3]\n    ldur x1, [x0, #1]'
make_case seq2_basic   0x10  VULNERABLE $'    adrp x0, mydata\n    mov x0, #5\n    nop\n    ldr x1, [x0, #8]'
make_case e835769_basic 0 VULNERABLE $'    ldr x1, [x2]\n    madd x3, x4, x5, x6' 835769
make_case e835769_clean 0 CLEAN      $'    ldr x1, [x2]\n    mul x3, x4, x5' 835769
make_case e819472_vuln   0 VULNERABLE $'    dc cvac, x0\n    dc cvau, x1' 819472
make_case e819472_clean  0 CLEAN      $'    dc civac, x0\n    dc civac, x1' 819472
# --- Newly fixed errata test cases ---

# 824069: Cache line might not be marked clean after a CleanShared snoop
make_case e824069_vuln   0 VULNERABLE $'    dc cvac, x0\n    dc cvau, x1' 824069
make_case e824069_clean  0 CLEAN      $'    dc civac, x0\n    dc civac, x1' 824069

# 826319: System might deadlock if a write cannot complete
make_case e826319_vuln   0 VULNERABLE $'    dc cvac, x0\n    dc cvau, x1\n    dc csw, x2' 826319
make_case e826319_clean  0 CLEAN      $'    dc civac, x0\n    dc civac, x1\n    dc cisw, x2' 826319

# 855872: Load-Exclusive followed by Store-Exclusive
make_case e855872_vuln   0 VULNERABLE $'    str x0, [x1]\n    ldxr x2, [x3]' 855872
make_case e855872_clean  0 CLEAN      $'    str x0, [x1]\n    dmb sy\n    ldxr x2, [x3]' 855872