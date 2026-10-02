import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from scanner.loader import load_code_sections

def main():
    path = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for sec in load_code_sections(path, allow_relocatable=True):
        print(f"Section {sec['name']} @ 0x{sec['addr']:x}, {len(sec['data'])} bytes")
        for i, ins in enumerate(md.disasm(sec["data"], sec["addr"])):
            if i >= limit:
                break
            print(f"  0x{ins.address:x}: {ins.mnemonic} {ins.op_str}")

if __name__ == "__main__":
    main()