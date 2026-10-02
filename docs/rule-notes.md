# Erratum 843419 - rule notes (source: Arm Cortex-A53 SDEN, ARM-EPM-048406 v21)

Category A. Affects r0p0, r0p1, r0p2, r0p3, r0p4 (all revisions). AArch64 only.
Effect: the final load/store may access an incorrect address (same permission checks apply).

## Sequence 1
1. ADRP writing Rn, located at address with low 12 bits 0xFF8 or 0xFFC.
2. Load/store: single-register load/store (int or vector), STP/STNP, or ST1.
   Must not write Rn. May read Rn. Load must cross a 64-bit boundary; store must cross a 128-bit boundary.
3. Optionally one instruction: not a branch, does not write Rn, may read Rn.
4. Load/store from the "unsigned immediate" class, base register Rn.

## Sequence 2 (no address condition stated)
1. ADRP writing Rn.
2. Instruction writing Rn: not a branch, not ADRP, does not read Rn.
3. Another instruction: not a branch, does not write Rn, may read Rn.
4. Load/store (unsigned immediate class), base register Rn.

## Workarounds (from Arm)
- Seq 1: keep loads/stores that use the ADRP result immediately after the ADRP, or insert NOPs so more than two instructions separate the ADRP and the final load/store.
- Seq 2: remove the ADRP or put a NOP right after it.

## Known limits of this scanner
- Boundary-crossing depends on runtime addresses, so findings are "potentially vulnerable".
- Capstone stops at undecodable bytes; data inside code sections needs mapping-symbol filtering (Phase 3).
- Not yet confirmed whether GNU ld --fix-cortex-a53-843419 also covers sequence 2.

## Validation against GNU ld (binutils 2.46, --fix-cortex-a53-843419)
- Detector and linker agree on all sequence-1 positives (basic, gap, ADRP at 0xFFC) and negatives (safe offset, too far, non-unsigned-immediate final access).
- writes_rn (instruction 2 overwrites Rn): linker patched it, detector reports CLEAN. Arm's text says instruction 2 must not write Rn, so the detector follows the Arm text. The linker appears more conservative.
- seq2_basic (sequence 2, no page-offset condition): detector reports VULNERABLE, linker left the binary unchanged in this test.

## Mitigation shape 2 (observed, far_target, GNU ld)
- Data out of ADR range (~2 MB away): the ADRP stays (retargeted to a new page), the final load/store at 0x401000 is replaced by a branch to a linker-generated stub.
- The stub (symbol e843419@...) contains the original load and a branch back to the instruction after it.
- Phase 4 signature: final load/store replaced by 'b' into a symbol named e843419@* (GNU ld naming; other linkers may differ).
