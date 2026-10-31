// Generated V7 conditional early-copy handoff candidate. Canonical tag os1handoff-v7.
// Preserve original SVclear copy; on SVset force the existing native copy only
// for rawON requested-code crossings0..4<->5. Parser/adapter remain unchanged.
// Explicit ASTATX/Y copies use a byte-bound named-alias post-pass.
// Persistent wire PP00/01/02 at stages5/8; PP80 current V5 union otherwise.
// Tail30dd74..30dd8c retains nativeON/seed counters and lastON across OFF/expiry.
// Variables moved to30dc10,size180; records/table/bank unchanged.
// oneshot5.asm -- the ONESHOT port: a type-5 render loop that drives the
// Digitakt II's own voice render, transplanted into the DN2 at apply time.
//
// Our own code, assembled with selache's `selas` (GPL-3.0, used as a tool and
// never linked in). Run offline in digikit's SHARC executor inside the DN2 1.11
// image; the earlier prototype did not complete its hardware test. The render it calls is NOT in this file or
// this repository: `dnfw.transplant` copies it from the user's own DT2 1.16 OS
// file into sw 0x185000 when the transplant is applied.
//
// The loop has Milestone 3's shape (machine5.asm): scan the 16 track records and
// act on every track whose machine type is 5. For such a track t it
//
//   1. on a note trigger (the byte engine +0x138fc + t, raised by the frame
//      unpack), builds a DT2-shaped voice record at 0x30e000 + 0x1d8 t from six
//      machine-page parameters of the frame (slots 25, 26, 28, 31, 32, 33:
//      TUNE, PLAY, SAMP, STRT, LEN, LOOP), resolving SAMP through the sample bank
//      directory (magic 'OSB1') baked into section 7;
//   2. calls the render with R4 = the record, R8 = the track buffer, R12 = the
//      block size, as the DT2's own dispatch calls it (DT2 0x1c6afd).
//
// Without a trigger the record carries on as the last block left it (a one-shot
// ends by clearing its own ACTIVE; the render then writes silence). Without the
// directory magic the loop renders nothing.
//
// The record arithmetic is `dnfw.oneshot.params.record_fields`, which the gate
// compares with what this loop writes, word for word:
//   S = min(scale(STRT, len), len - 141)
//   E = max(min(S + scale(LEN, len), len), S + 141)
//   P = scale(LOOP, len); P > E - 141 or OFF -> S
//   PLAY: 0 REV, 1 REV.L, 2 FWD.L, 3 FWD; step = steps[TUNE + 128 * reverse]
//   phase = reverse ? E - 1 : S
//
// PLACEMENT IS FIXED at PM sw 0x185800. Absolute targets are written for that
// address from selas's own symbol table (a labelled reassembly); the gate
// decodes the spliced code and checks every target lands on our labels.
//
// DM (byte addresses; spans the DN2 boot stream never loads, checked by the gate):
//   0x30dc10  save area, 32 words: R0-R15, I0-I5, I12, M0-M4
//   0x30dc90  tracks left            0x30dc94  this track's index
//   0x30dc98  this track's record    0x30dc9c  this track's frame slot
//   0x30dca0  -> machine type word   0x30dca4  -> track buffer pointer
//   0x30dca8  this track's buffer    0x30dcb0  six coarse parameters
//   0x30dcd0/c4/c8 entry/trigger/render-return counters (zero-filled at boot)
//   0x30dcdc per-block flags: type5, bank, pointer, active, donor called
//   reply words 1..4 at both 0x2c49d0 and 0x2c59d0: stage, entries, triggers, returns
//   diagnostic os1poly-v4 stage: canonical 0x4f53FFVS; V=voice index, S=stage
//   1 entry(index0), 2 trigger, 3 predonor, 4 returned, 6 next entered,
//   7 cursors advanced(completed voice), 5 scan complete, 8 restored/pre-resume.
//   FF is cumulative block flags only at stages5/8; V=15 there. No caller-return proof.
//   0x30e000  16 records of 0x1d8 bytes (a zero-fill block at boot)
//   0x310000  256 steps, 2 words each (ours: 0.5 * 2^((c - 64) / 12), Q31)
//   0x310800  the sample bank: 'OSB1', count, (pointer, length, rate) ...
//
// selas compresses `R0 = R0 + R1` to the 16-bit parcel 0xc001, which digikit's
// decoder reads as a 32-bit Type 2b (docs/for-digikit-sharc-runner-dn2.md 10),
// and `R5 = R5 + R6` to 0xc056 the same way; os_next. writes `R5 = R6 + R5`,
// which selas emits in 48 bits and both toolchains read alike.
//
// Only forms the firmware itself uses, as machine5.asm: absolute JUMP/CJUMP,
// Type 14a absolute loads and stores, Type 15b I+displacement, 16a immediate
// stores, and no MODIFY and no DM(Mb, Ia) read (docs/for-digikit-sharc-runner-dn2.md 4, 19).

.SECTION/PM seg_pmco;

.GLOBAL os_type5.;
os_type5.:
      DM(0x30dc10) = R0;
      DM(0x30dc14) = R1;
      DM(0x30dc18) = R2;
      DM(0x30dc1c) = R3;
      DM(0x30dc20) = R4;
      DM(0x30dc24) = R5;
      DM(0x30dc28) = R6;
      DM(0x30dc2c) = R7;
      DM(0x30dc30) = R8;
      DM(0x30dc34) = R9;
      DM(0x30dc38) = R10;
      DM(0x30dc3c) = R11;
      DM(0x30dc40) = R12;
      DM(0x30dc44) = R13;
      DM(0x30dc48) = R14;
      DM(0x30dc4c) = R15;
      DM(0x30dc50) = I0;
      DM(0x30dc54) = I1;
      DM(0x30dc58) = I2;
      DM(0x30dc5c) = I3;
      DM(0x30dc60) = I4;
      DM(0x30dc64) = I5;
      DM(0x30dc68) = I12;
      DM(0x30dc6c) = M0;
      DM(0x30dc70) = M1;
      DM(0x30dc74) = M2;
      DM(0x30dc78) = M3;
      DM(0x30dc7c) = M4;
      // Save I6/I7 too. The transplanted render ends in RFRAME, which sets
      // I6/I7 from the frame CJUMP built; on a never-triggered (word-0 = 0)
      // record it leaves the caller's I7 pointing at a word we did not own, and
      // the DN2 block loop carries I7 into the next block. Restored at the exit.
      R0 = I6;
      DM(0x30dc80) = R0;
      R0 = I7;
      DM(0x30dc84) = R0;

      R0 = 0;
      DM(0x30dcdc) = R0;
      R0 = DM(0x30dcd0);
      R1 = 1;
      R0 = R1 + R0;
      DM(0x30dcd0) = R0;
      R0 = DM(0x30dcd0);
      R1 = LSHIFT R0 BY 16;
      R0 = LSHIFT R0 BY -16;
      R0 = R0 OR R1;
      DM(0x2c49d8) = R0;
      DM(0x2c59d8) = R0;

.GLOBAL os_diag_expiry_check.;
os_diag_expiry_check.:
      R0 = DM(0x30dd30);
      R0 = PASS R0;
      IF EQ JUMP 0x185897; // -> os_diag_expiry_done_1.
      R0 = DM(0x30dcd0);
      R1 = DM(0x30dd28);
      R0 = R0 - R1;
      R1 = 1024;
      COMPU(R0, R1);
      IF LT JUMP 0x185897; // -> os_diag_expiry_done_1.
      R0 = 0;
      DM(0x30dd30) = R0;

.GLOBAL os_diag_expiry_done_1.;
os_diag_expiry_done_1.:
      R0 = 0;
      DM(0x30dd04) = R0;
      R0 = 117440512;
      DM(0x30dd0c) = R0;
      R0 = 0;
      DM(0x30dcf0) = R0;
      R0 = 0;
      DM(0x30dd00) = R0;
      R0 = 16;
      DM(0x30dc90) = R0;
      R0 = 0;
      DM(0x30dc94) = R0;

.GLOBAL os_diag_publish_s1_2.;
os_diag_publish_s1_2.:
      R0 = DM(0x30dc90);
      R1 = 16;
      COMPU(R0, R1);
      R0 = 0x30e000;
      DM(0x30dc98) = R0;
      R0 = 0x25c566;                    // the frame copy 0x25c48c + slot 218
      DM(0x30dc9c) = R0;
      R0 = 0x25566c;                    // &track[0].machine (0x2554b8 + 0x1b4)
      DM(0x30dca0) = R0;
      R0 = 0x254a60;                    // &track_buffer[0]
      DM(0x30dca4) = R0;

.GLOBAL os_loop.;
os_loop.:
      R0 = 0;
      DM(0x30dd04) = R0;
      R0 = 117440512;
      DM(0x30dd0c) = R0;

.GLOBAL os_diag_legacy_s9_compare.;
os_diag_legacy_s9_compare.:
      R0 = DM(0x30dc90);
      R1 = 16;
      COMPU(R0, R1);
      I4 = DM(0x30dca0);
      R2 = DM(0, I4);
      DM(0x30dce0) = R2;
      I4 = DM(0x30dca4);
      R3 = DM(0, I4);
      DM(0x30dce4) = R3;
      DM(0x30dca8) = R3;

.GLOBAL os_diag_legacy_s10_compare.;
os_diag_legacy_s10_compare.:
      R0 = DM(0x30dc90);
      R1 = 16;
      COMPU(R0, R1);

.GLOBAL os_diag_snapshot_fields.;
os_diag_snapshot_fields.:
      R0 = DM(0x30dc94);
      R1 = 3;
      R2 = R0 AND R1;
      R3 = R0 - R2;
      R4 = 0x254b94;
      R4 = R4 + R3;
      I4 = R4;
      R5 = DM(0, I4);
      R2 = LSHIFT R2 BY 3;
      R3 = 0;
      R2 = R3 - R2;
      R5 = LSHIFT R5 BY R2;
      R1 = 0xff;
      R5 = R5 AND R1;
      DM(0x30dce8) = R5;
      R0 = DM(0x30dc94);
      R1 = 3;
      R2 = R0 AND R1;
      R3 = R0 - R2;
      R4 = 0x254bb4;
      R4 = R4 + R3;
      I4 = R4;
      R5 = DM(0, I4);
      R2 = LSHIFT R2 BY 3;
      R3 = 0;
      R2 = R3 - R2;
      R5 = LSHIFT R5 BY R2;
      R1 = 0xff;
      R5 = R5 AND R1;
      DM(0x30dcec) = R5;
      R0 = 0;
      DM(0x30dd44) = R0;
      R0 = DM(0x30dc94);
      R1 = 3;
      R2 = R0 AND R1;
      R3 = R0 - R2;
      R4 = 0x30dd34;
      R4 = R4 + R3;
      I4 = R4;
      R6 = DM(0, I4);
      R2 = LSHIFT R2 BY 3;
      R3 = 0;
      R3 = R3 - R2;
      R5 = LSHIFT R6 BY R3;
      R1 = 0xff;
      R5 = R5 AND R1;
      R0 = DM(0x30dcec);
      R0 = PASS R0;
      IF EQ JUMP 0x185972; // -> os_diag_off_same_5.
      COMP(R0, R5);
      IF EQ JUMP 0x185972; // -> os_diag_off_same_5.
      R0 = 1;
      DM(0x30dd44) = R0;

.GLOBAL os_diag_off_same_5.;
os_diag_off_same_5.:
      R1 = 0xff;
      R1 = LSHIFT R1 BY R2;
      R7 = 0xffffffff;
      R1 = R1 XOR R7;
      R6 = R6 AND R1;
      R0 = DM(0x30dcec);
      R0 = LSHIFT R0 BY R2;
      R6 = R6 OR R0;
      DM(0, I4) = R6;
      R0 = DM(0x30dc98);
      I4 = R0;
      R0 = DM(0, I4);
      DM(0x30dcf0) = R0;
      R0 = DM(0x30dc98);
      R1 = 0x1b8;
      R0 = R0 + R1;
      I4 = R0;
      R0 = DM(0, I4);
      DM(0x30dcf4) = R0;
      R0 = 0;
      DM(0x30dcf8) = R0;
      R0 = DM(0x310800);
      R1 = 0x3142534f;
      COMP(R0, R1);
      IF NE JUMP 0x1859ad; // -> os_diag_bank_snapshot_done_6.
      R0 = 1;
      DM(0x30dcf8) = R0;

.GLOBAL os_diag_bank_snapshot_done_6.;
os_diag_bank_snapshot_done_6.:
      R0 = DM(0x30dc94);
      R1 = LSHIFT R0 BY 1;
      R1 = R0 + R1;
      R0 = LSHIFT R0 BY 3;
      R0 = R1 + R0;
      R0 = LSHIFT R0 BY 2;
      R1 = 0x2547a0;
      R0 = R0 + R1;
      I4 = R0;
      R0 = DM(7, I4);
      DM(0x30dcfc) = R0;
      R0 = DM(10, I4);
      DM(0x30dd00) = R0;
      R0 = 1;
      DM(0x30dd04) = R0;
      CALL 0x186041; // -> os_diag_status_helper.

.GLOBAL os_diag_publish_s13_7.;
os_diag_publish_s13_7.:
      R0 = DM(0x30dcf0);
      DM(0x30dd6c) = R0;
      R0 = DM(0x30dd00);
      DM(0x30dd70) = R0;
      R0 = 872275;
      DM(0x30dd60) = R0;
      R0 = DM(0x30dc94);
      DM(0x30dd68) = R0;
      CALL 0x1860d0; // -> os_diag_publish_helper.

.GLOBAL os_diag_native_on_observe.;
os_diag_native_on_observe.:
      R0 = DM(0x30dce8);
      R0 = PASS R0;
      IF EQ JUMP 0x185a23; // -> os_diag_native_on_done.
      R0 = DM(0x30dd74);
      R1 = 1;
      R0 = R1 + R0;
      DM(0x30dd74) = R0;
      R0 = DM(0x30dc94);
      DM(0x30dd80) = R0;
      R0 = DM(0x30dcd0);
      DM(0x30dd84) = R0;
      R0 = DM(0x30dcf0);
      DM(0x30dd88) = R0;
      R0 = DM(0x30dce0);
      DM(0x30dd8c) = R0;
      R0 = DM(0x30dd0c);
      R1 = 0x3fffffff;
      R0 = R0 AND R1;
      DM(0x30dd7c) = R0;

.GLOBAL os_diag_native_on_done.;
os_diag_native_on_done.:
      R2 = DM(0x30dce0);
      R3 = DM(0x30dce4);
      R1 = 5;
      COMP(R2, R1);
      IF NE JUMP 0x185f2e;             // -> os_invalidate.
      R0 = DM(0x30dcdc);
      R1 = 1;
      R0 = R0 OR R1;
      DM(0x30dcdc) = R0;               // any native DSP type-5 slot seen
      R1 = DM(0x310800);                // the bank's magic
      R2 = 0x3142534f;
      COMP(R1, R2);
      IF NE JUMP 0x185fb3; // -> os_diag_bank_bad.
      R0 = DM(0x30dcdc);
      R1 = 2;
      R0 = R0 OR R1;
      DM(0x30dcdc) = R0;               // OSB1 magic valid for a type-5 slot


.GLOBAL os_diag_native_event_decision.;
os_diag_native_event_decision.:
      R0 = DM(0x30dce8);
      R0 = PASS R0;
      IF NE JUMP 0x185a8d; // -> os_diag_no_off_latch_8.
      R0 = DM(0x30dd44);
      R0 = PASS R0;
      IF EQ JUMP 0x185a8d; // -> os_diag_no_off_latch_8.

.GLOBAL os_diag_latch_k2_9.;
os_diag_latch_k2_9.:
      R0 = DM(0x30dd0c);
      DM(0x30dd10) = R0;
      R0 = DM(0x30dcf0);
      DM(0x30dd14) = R0;
      R0 = DM(0x30dcfc);
      DM(0x30dd18) = R0;
      R0 = DM(0x30dd00);
      DM(0x30dd1c) = R0;
      R0 = DM(0x30dc90);
      DM(0x30dd20) = R0;
      R0 = DM(0x30dc94);
      DM(0x30dd24) = R0;
      R0 = DM(0x30dcd0);
      DM(0x30dd28) = R0;
      R0 = 2;
      DM(0x30dd2c) = R0;
      R0 = 1;
      DM(0x30dd30) = R0;

.GLOBAL os_diag_no_off_latch_8.;
os_diag_no_off_latch_8.:
      R7 = DM(0x30dce8);
      R7 = PASS R7;
      IF EQ JUMP 0x185cb0; // -> os_render.
      R0 = DM(0x30dcd4);
      R1 = 1;
      R0 = R1 + R0;
      DM(0x30dcd4) = R0;

.GLOBAL os_diag_on_accepted.;
os_diag_on_accepted.:
      R0 = DM(0x30dd7c);
      R1 = 0x40000000;
      R0 = R0 OR R1;
      DM(0x30dd7c) = R0;

.GLOBAL os_diag_publish_s2_10.;
os_diag_publish_s2_10.:
      R0 = DM(0x30dcf0);
      DM(0x30dd6c) = R0;
      R0 = DM(0x30dd00);
      DM(0x30dd70) = R0;
      R0 = 151379;
      DM(0x30dd60) = R0;
      R0 = DM(0x30dc94);
      DM(0x30dd68) = R0;
      CALL 0x1860d0; // -> os_diag_publish_helper.
      // the DT2 records' values from the frame slot: slot s at byte 2 * (s - 25).
      // Live instrument frames carry the native sound words (September 30
      // correction in dnfw.waverider.frame). TUNE/PLAY use frame >> 8,
      // SAMP is whole, and STRT/LEN/LOOP keep 0x7800 = the sample's end.
      // Fine TUNE and machine-page CFADE/LEV are not implemented here.
      R8 = DM(0x30dc9c);
      R9 = 0xfffffffc;
      R10 = 2;
      R11 = 0;
      R12 = 0xffff;
      R13 = 0xff;
      R0 = R8;
      // TUNE, slot 25: +0
      R1 = R0 AND R9;
      I4 = R1;
      R2 = DM(0, I4);
      R3 = R0 AND R10;
      R3 = LSHIFT R3 BY 3;
      R3 = R11 - R3;
      R2 = LSHIFT R2 BY R3;
      R2 = LSHIFT R2 BY -8;
      R2 = R2 AND R13;
      R1 = 127;
      R2 = MIN(R2, R1);                // step table stays within 0..127
      DM(0x30dcb0) = R2;
      R0 = R0 + R10;
      // PLAY, slot 26: +2
      R1 = R0 AND R9;
      I4 = R1;
      R2 = DM(0, I4);
      R3 = R0 AND R10;
      R3 = LSHIFT R3 BY 3;
      R3 = R11 - R3;
      R2 = LSHIFT R2 BY R3;
      R2 = LSHIFT R2 BY -8;
      R2 = R2 AND R13;
      R1 = 3;
      R2 = MIN(R2, R1);                // four supported play modes
      DM(0x30dcb4) = R2;
      R0 = R0 + R10;
      R0 = R0 + R10;
      // SAMP, slot 28: +6
      R1 = R0 AND R9;
      I4 = R1;
      R2 = DM(0, I4);
      R3 = R0 AND R10;
      R3 = LSHIFT R3 BY 3;
      R3 = R11 - R3;
      R2 = LSHIFT R2 BY R3;
      R2 = R2 AND R12;
      DM(0x30dcb8) = R2;
      R0 = R0 + R10;
      R0 = R0 + R10;
      R0 = R0 + R10;
      // STRT, slot 31: +12
      R1 = R0 AND R9;
      I4 = R1;
      R2 = DM(0, I4);
      R3 = R0 AND R10;
      R3 = LSHIFT R3 BY 3;
      R3 = R11 - R3;
      R2 = LSHIFT R2 BY R3;
      R2 = R2 AND R12;
      R1 = 0x7800;
      R2 = MIN(R2, R1);                // bounded frame endpoint before multiplication
      DM(0x30dcbc) = R2;
      R0 = R0 + R10;
      // LEN, slot 32: +14
      R1 = R0 AND R9;
      I4 = R1;
      R2 = DM(0, I4);
      R3 = R0 AND R10;
      R3 = LSHIFT R3 BY 3;
      R3 = R11 - R3;
      R2 = LSHIFT R2 BY R3;
      R2 = R2 AND R12;
      R1 = 0x7800;
      R2 = MIN(R2, R1);                // bounded frame endpoint before multiplication
      DM(0x30dcc0) = R2;
      R0 = R0 + R10;
      // LOOP, slot 33: +16
      R1 = R0 AND R9;
      I4 = R1;
      R2 = DM(0, I4);
      R3 = R0 AND R10;
      R3 = LSHIFT R3 BY 3;
      R3 = R11 - R3;
      R2 = LSHIFT R2 BY R3;
      R2 = R2 AND R12;
      R1 = 0x7800;
      R2 = MIN(R2, R1);                // bounded frame endpoint before multiplication
      DM(0x30dcc4) = R2;

      // SAMP through the directory; a slot past the count plays slot 0
      R1 = DM(0x30dcb8);
      R2 = DM(0x310804);
      COMPU(R1, R2);
      IF GE R1 = R1 - R1;
      R2 = 12;
      R1 = R1 * R2 (SSI);
      R2 = 0x310808;
      R1 = R1 + R2;
      I4 = R1;
      R13 = DM(0, I4);                  // pointer
      R14 = DM(1, I4);                  // len

      // S = min(f * len / 30720, len - 141), f the native STRT word
      R0 = DM(0x30dcbc);
      R0 = R0 * R14 (SSI);
      R0 = LSHIFT R0 BY -10;
      R2 = 2185;                        // 65536 / 30, so (x >> 10) * 2185 >> 16 = x / 30720
      R0 = R0 * R2 (SSI);
      R0 = LSHIFT R0 BY -16;
      R1 = 141;                       // donor renderer enforces this minimum span
      R2 = R14 - R1;
      R0 = MIN(R0, R2);                 // R0 = S
      // L = f * len / 30720, f the native LEN frame word
      R3 = DM(0x30dcc0);
      R4 = R3 * R14 (SSI);
      R4 = LSHIFT R4 BY -10;
      R2 = 2185;
      R4 = R4 * R2 (SSI);
      R4 = LSHIFT R4 BY -16;
      // E = max(min(S + L, len), S + 141)
      R4 = R0 + R4;
      R4 = MIN(R4, R14);
      R5 = R0 + R1;
      R4 = MAX(R4, R5);                 // R4 = E
      R1 = 1;
      // P: LOOP 0 is OFF; else (native word - 1) * len / 30720
      R7 = DM(0x30dcc4);
      R6 = R7 - R1;
      R6 = MAX(R6, R11);
      R6 = R6 * R14 (SSI);
      R6 = LSHIFT R6 BY -10;
      R2 = 2185;
      R6 = R6 * R2 (SSI);
      R6 = LSHIFT R6 BY -16;
      R2 = 141;
      R2 = R4 - R2;
      COMP(R6, R2);
      IF GT R6 = PASS R0;
      R7 = PASS R7;
      IF EQ R6 = PASS R0;               // R6 = P
      // PLAY, the DT2's order: 0 REV, 1 REV.L, 2 FWD.L, 3 FWD
      R7 = DM(0x30dcb4);
      R9 = LSHIFT R7 BY -1;
      R9 = R9 AND R1;                   // 0 0 1 1: forward
      R8 = R1 - R9;                     // reverse
      R10 = R7 AND R1;                  // 0 1 0 1
      R9 = R9 XOR R10;                  // loop: 0 1 1 0
      // step = steps[TUNE + 128 * reverse], two words
      R10 = LSHIFT R8 BY 7;
      R11 = DM(0x30dcb0);
      R10 = R10 + R11;
      R10 = LSHIFT R10 BY 3;
      R11 = 0x310000;
      R10 = R10 + R11;
      I4 = R10;
      R10 = DM(0, I4);                  // step lo
      R11 = DM(1, I4);                  // step hi
      // phase = reverse ? E - 1 : S
      R12 = R4 - R1;
      R8 = PASS R8;
      IF EQ R12 = PASS R0;

      // the record
      R15 = DM(0x30dc98);
      I4 = R15;
      DM(0, I4) = R13;                  // +0x000 sample pointer
      R2 = 0x17c;
      R2 = R15 + R2;
      I4 = R2;
      R3 = 0;
      DM(0, I4) = R3;                   // +0x17c declick one-shots
      DM(1, I4) = R3;                   // +0x180 previous sample
      DM(3, I4) = R14;                  // +0x188 length
      DM(4, I4) = R3;                   // +0x18c
      R2 = LSHIFT R6 BY 31;
      DM(5, I4) = R2;                   // +0x190 loop start
      R2 = LSHIFT R6 BY -1;
      DM(6, I4) = R2;
      R2 = LSHIFT R0 BY 31;
      DM(7, I4) = R2;                   // +0x198 start
      R2 = LSHIFT R0 BY -1;
      DM(8, I4) = R2;
      R2 = LSHIFT R4 BY 31;
      DM(9, I4) = R2;                   // +0x1a0 end
      R2 = LSHIFT R4 BY -1;
      DM(10, I4) = R2;
      DM(11, I4) = R10;                 // +0x1a8 step
      DM(12, I4) = R11;
      R2 = LSHIFT R12 BY 31;
      DM(13, I4) = R2;                  // +0x1b0 phase
      R2 = LSHIFT R12 BY -1;
      DM(14, I4) = R2;
      R2 = LSHIFT R8 BY 24;
      R2 = R2 + R1;
      DM(15, I4) = R2;                  // +0x1b8 ACTIVE = 1, +0x1bb REVERSE
      DM(16, I4) = R9;                  // +0x1bc LOOP

.GLOBAL os_diag_seed_complete.;
os_diag_seed_complete.:
      R0 = DM(0x30dd78);
      R1 = 1;
      R0 = R1 + R0;
      DM(0x30dd78) = R0;
      R0 = DM(0x30dc98);
      I4 = R0;
      R0 = DM(0, I4);
      DM(0x30dcf0) = R0;
      R0 = DM(0x30dc98);
      R1 = 0x1b8;
      R0 = R0 + R1;
      I4 = R0;
      R0 = DM(0, I4);
      DM(0x30dcf4) = R0;
      CALL 0x186041; // -> os_diag_status_helper.

.GLOBAL os_diag_seed_retained_update.;
os_diag_seed_retained_update.:
      R0 = DM(0x30dcf0);
      DM(0x30dd88) = R0;
      R0 = DM(0x30dd0c);
      R1 = 0x3fffffff;
      R0 = R0 AND R1;
      R1 = 0xc0000000;
      R0 = R0 OR R1;
      DM(0x30dd7c) = R0;

.GLOBAL os_diag_latch_k1_11.;
os_diag_latch_k1_11.:
      R0 = DM(0x30dd0c);
      DM(0x30dd10) = R0;
      R0 = DM(0x30dcf0);
      DM(0x30dd14) = R0;
      R0 = DM(0x30dcfc);
      DM(0x30dd18) = R0;
      R0 = DM(0x30dd00);
      DM(0x30dd1c) = R0;
      R0 = DM(0x30dc90);
      DM(0x30dd20) = R0;
      R0 = DM(0x30dc94);
      DM(0x30dd24) = R0;
      R0 = DM(0x30dcd0);
      DM(0x30dd28) = R0;
      R0 = 1;
      DM(0x30dd2c) = R0;
      R0 = 1;
      DM(0x30dd30) = R0;

.GLOBAL os_diag_publish_s14_12.;
os_diag_publish_s14_12.:
      R0 = DM(0x30dc90);
      R1 = 16;
      COMPU(R0, R1);

.GLOBAL os_render.;
os_render.:
      R4 = DM(0x30dc98);
      R8 = DM(0x30dca8);
      // An idle voice (no sample pointer, or ACTIVE clear) is not handed to the
      // render: its own zero-fill arm for that case is the DT2's, and in the DN2's
      // per-block run it did not come back (the runner halted at PC 0 on the first
      // idle block -- #133's "setup table" blocker was this, not the table). The
      // adapter writes the block's 32 zeros itself.
      I4 = R4;
      R2 = DM(0, I4);                   // +0x000 sample pointer
      R3 = 0x1b8;
      R3 = R4 + R3;
      I4 = R3;
      R3 = DM(0, I4);                   // +0x1b8 ACTIVE (low byte)
      DM(0x30dcf4) = R3;
      DM(0x30dcf0) = R2;
      CALL 0x186041; // -> os_diag_status_helper.
      R1 = 0xff;
      R3 = R3 AND R1;
      R2 = PASS R2;
      IF EQ JUMP 0x185cdb;             // -> os_flags_no_pointer.
      R0 = DM(0x30dcdc);
      R1 = 4;
      R0 = R0 OR R1;
      DM(0x30dcdc) = R0;
.GLOBAL os_flags_no_pointer.;
os_flags_no_pointer.:
      R3 = PASS R3;
      IF EQ JUMP 0x185ce8;             // -> os_flags_no_active.
      R0 = DM(0x30dcdc);
      R1 = 8;
      R0 = R0 OR R1;
      DM(0x30dcdc) = R0;
.GLOBAL os_flags_no_active.;
os_flags_no_active.:
      R2 = PASS R2;
      IF EQ JUMP 0x186005; // -> os_diag_quiet_pointer.
      R3 = PASS R3;
      IF EQ JUMP 0x186023; // -> os_diag_quiet_active.
      R12 = DM(0x30dc34);               // the dispatch's R9: the block size
      // The transplanted render ends in a RETURN whose delay slot is RFRAME:
      // it needs both a PC-stack return and the frame link (I6 = I7, R2 = old
      // I6) that the donor's own frame-linked caller (0x1c6b00) sets up. CJUMP
      // does exactly both (digikit `_type_25a_direct`: call = True and the
      // cjump-frame), so the render is reached with CJUMP and the two software-
      // stack pushes, as machine5_dir reaches the reader.
      R0 = DM(0x30dcdc);
      R1 = 16;
      R0 = R0 OR R1;
      DM(0x30dcdc) = R0;               // donor call arm reached this block

.GLOBAL os_diag_publish_s3_13.;
os_diag_publish_s3_13.:
      R0 = DM(0x30dc90);
      R1 = 16;
      COMPU(R0, R1);
      CJUMP 0x185000 (DB);             // the transplanted render
      DM(I7, M7) = R2;
      DM(I7, M7) = 0x185d09;           // return address - 1: os_render_return. - 1

.GLOBAL os_render_return.;
os_render_return.:
      R0 = DM(0x30dcd8);
      R1 = 1;
      R0 = R1 + R0;
      DM(0x30dcd8) = R0;
      R0 = DM(0x30dc98);
      I4 = R0;
      R0 = DM(0, I4);
      DM(0x30dcf0) = R0;
      R0 = DM(0x30dc98);
      R1 = 0x1b8;
      R0 = R0 + R1;
      I4 = R0;
      R0 = DM(0, I4);
      DM(0x30dcf4) = R0;
      CALL 0x186041; // -> os_diag_status_helper.

.GLOBAL os_diag_publish_s4_14.;
os_diag_publish_s4_14.:
      R0 = DM(0x30dc90);
      R1 = 16;
      COMPU(R0, R1);

.GLOBAL os_next.;
os_next.:

.GLOBAL os_diag_publish_s6_15.;
os_diag_publish_s6_15.:
      R0 = DM(0x30dc90);
      R1 = 16;
      COMPU(R0, R1);
      R5 = DM(0x30dc94);
      R6 = 1;
      R5 = R6 + R5;
      DM(0x30dc94) = R5;
      R5 = DM(0x30dc98);
      R6 = 472;
      R5 = R6 + R5;
      DM(0x30dc98) = R5;
      R5 = DM(0x30dc9c);
      R6 = 146;
      R5 = R6 + R5;
      DM(0x30dc9c) = R5;
      R5 = DM(0x30dca0);
      R6 = 564;
      R5 = R6 + R5;
      DM(0x30dca0) = R5;
      R5 = DM(0x30dca4);
      R6 = 4;
      R5 = R6 + R5;
      DM(0x30dca4) = R5;

.GLOBAL os_diag_publish_s7_16.;
os_diag_publish_s7_16.:
      R0 = DM(0x30dc90);
      R1 = 16;
      COMPU(R0, R1);
      R5 = DM(0x30dc90);
      R6 = 1;
      R5 = R5 - R6;
      DM(0x30dc90) = R5;
      IF NE JUMP 0x185d8b; // -> os_diag_decrement_more.

.GLOBAL os_diag_legacy_s15_done_compare.;
os_diag_legacy_s15_done_compare.:
      R0 = DM(0x30dc90);
      R1 = 16;
      COMPU(R0, R1);
      JUMP 0x185d95; // -> os_diag_scan_complete.

.GLOBAL os_diag_decrement_more.;
os_diag_decrement_more.:

.GLOBAL os_diag_legacy_s15_more_compare.;
os_diag_legacy_s15_more_compare.:
      R0 = DM(0x30dc90);
      R1 = 16;
      COMPU(R0, R1);
      JUMP 0x1858d5; // -> os_loop.

.GLOBAL os_diag_scan_complete.;
os_diag_scan_complete.:
      R0 = DM(0x30dd30);
      R0 = PASS R0;
      IF EQ JUMP 0x185da3; // -> os_diag_legacy_completion_compare_done.
      R0 = DM(0x30dd20);
      R1 = 16;
      COMPU(R0, R1);

.GLOBAL os_diag_legacy_completion_compare_done.;
os_diag_legacy_completion_compare_done.:
      R0 = DM(0x30dcd0);
      R0 = LSHIFT R0 BY -10;
      R1 = 3;
      R0 = R0 AND R1;
      R1 = 1;
      R1 = R0 - R1;
      IF EQ JUMP 0x185dd9; // -> os_diag_persistent_page1.
      R1 = 2;
      R1 = R0 - R1;
      IF EQ JUMP 0x185dfa; // -> os_diag_persistent_page2.

.GLOBAL os_diag_persistent_page0.;
os_diag_persistent_page0.:
      R0 = DM(0x30dd74);
      DM(0x30dd60) = R0;
      R0 = DM(0x30dcd4);
      DM(0x30dd6c) = R0;
      R0 = DM(0x30dd78);
      DM(0x30dd70) = R0;
      R0 = 15;
      DM(0x30dd68) = R0;
      R0 = 0x0;
      DM(0x30dd64) = R0;
      JUMP 0x185e1b; // -> os_diag_persistent_payload_ready.

.GLOBAL os_diag_persistent_page1.;
os_diag_persistent_page1.:
      R0 = DM(0x30dcd8);
      DM(0x30dd60) = R0;
      R0 = DM(0x30dd7c);
      DM(0x30dd6c) = R0;
      R0 = DM(0x30dd84);
      DM(0x30dd70) = R0;
      R0 = DM(0x30dd80);
      DM(0x30dd68) = R0;
      R0 = 0x1000000;
      DM(0x30dd64) = R0;
      JUMP 0x185e1b; // -> os_diag_persistent_payload_ready.

.GLOBAL os_diag_persistent_page2.;
os_diag_persistent_page2.:
      R0 = DM(0x30dd8c);
      DM(0x30dd60) = R0;
      R0 = DM(0x30dd88);
      DM(0x30dd6c) = R0;
      R0 = DM(0x30dd84);
      DM(0x30dd70) = R0;
      R0 = DM(0x30dd80);
      DM(0x30dd68) = R0;
      R0 = 0x2000000;
      DM(0x30dd64) = R0;
      JUMP 0x185e1b; // -> os_diag_persistent_payload_ready.

.GLOBAL os_diag_persistent_payload_ready.;
os_diag_persistent_payload_ready.:
      R0 = DM(0x30dd60);
      R1 = LSHIFT R0 BY 16;
      R0 = LSHIFT R0 BY -16;
      R0 = R0 OR R1;
      DM(0x30dd4c) = R0;
      DM(0x2c49dc) = R0;
      DM(0x2c59dc) = R0;
      R0 = DM(0x30dd6c);
      R1 = LSHIFT R0 BY 16;
      R0 = LSHIFT R0 BY -16;
      R0 = R0 OR R1;
      DM(0x30dd50) = R0;
      DM(0x2c49e0) = R0;
      DM(0x2c59e0) = R0;
      R0 = DM(0x30dd70);
      R1 = LSHIFT R0 BY 16;
      R0 = LSHIFT R0 BY -16;
      R0 = R0 OR R1;
      DM(0x30dd54) = R0;
      DM(0x2c49e8) = R0;
      DM(0x2c59e8) = R0;
      R0 = DM(0x30dd68);
      R0 = LSHIFT R0 BY 20;
      R1 = DM(0x30dd64);
      R0 = R0 OR R1;
      R1 = 0x84f53;
      R1 = R0 OR R1;
      DM(0x30dd58) = R1;
      R1 = 0x54f53;
      R0 = R0 OR R1;
      DM(0x2c49d4) = R0;
      DM(0x2c59d4) = R0;
      R0 = DM(0x30dc10);
      R1 = DM(0x30dc14);
      R2 = DM(0x30dc18);
      R3 = DM(0x30dc1c);
      R4 = DM(0x30dc20);
      R5 = DM(0x30dc24);
      R6 = DM(0x30dc28);
      R7 = DM(0x30dc2c);
      R8 = DM(0x30dc30);
      R9 = DM(0x30dc34);
      R10 = DM(0x30dc38);
      R11 = DM(0x30dc3c);
      R12 = DM(0x30dc40);
      R13 = DM(0x30dc44);
      R14 = DM(0x30dc48);
      R15 = DM(0x30dc4c);
      I0 = DM(0x30dc50);
      I1 = DM(0x30dc54);
      I2 = DM(0x30dc58);
      I3 = DM(0x30dc5c);
      I4 = DM(0x30dc60);
      I5 = DM(0x30dc64);
      I12 = DM(0x30dc68);
      M0 = DM(0x30dc6c);
      M1 = DM(0x30dc70);
      M2 = DM(0x30dc74);
      M3 = DM(0x30dc78);
      M4 = DM(0x30dc7c);
      R0 = DM(0x30dc80);
      I6 = R0;                          // the dispatch's frame, whatever the render left
      R0 = DM(0x30dc84);
      I7 = R0;
      R0 = DM(0x30dc10);               // I6/I7 restoration used R0 as scratch

      // the two instructions the entry JUMP replaced (0x1c9448, 0x1c944a)
      I5 = DM(-24, I6);
      R10 = DM(-34, I6);

.GLOBAL os_diag_restored_publication.;
os_diag_restored_publication.:
      R0 = DM(0x30dd58);
      DM(0x2c49d4) = R0;
      DM(0x2c59d4) = R0;
      R0 = DM(0x30dc10);
      R1 = DM(0x30dc14);
      JUMP 0x1c944c;

      // os_quiet sits out of line: the instruction after the render's CJUMP and
      // its delay slots is where the render's RETURN comes back to (the PC stack),
      // so that must stay os_render_return.
.GLOBAL os_quiet.;
os_quiet.:
      I4 = R8;
      R3 = 0;
      DM(0, I4) = R3;
      DM(1, I4) = R3;
      DM(2, I4) = R3;
      DM(3, I4) = R3;
      DM(4, I4) = R3;
      DM(5, I4) = R3;
      DM(6, I4) = R3;
      DM(7, I4) = R3;
      DM(8, I4) = R3;
      DM(9, I4) = R3;
      DM(10, I4) = R3;
      DM(11, I4) = R3;
      DM(12, I4) = R3;
      DM(13, I4) = R3;
      DM(14, I4) = R3;
      DM(15, I4) = R3;
      DM(16, I4) = R3;
      DM(17, I4) = R3;
      DM(18, I4) = R3;
      DM(19, I4) = R3;
      DM(20, I4) = R3;
      DM(21, I4) = R3;
      DM(22, I4) = R3;
      DM(23, I4) = R3;
      DM(24, I4) = R3;
      DM(25, I4) = R3;
      DM(26, I4) = R3;
      DM(27, I4) = R3;
      DM(28, I4) = R3;
      DM(29, I4) = R3;
      DM(30, I4) = R3;
      DM(31, I4) = R3;
      JUMP 0x185d35;                   // -> os_next.

      // The DN2 allocator may reuse a voice slot for a stock machine and later
      // return it to type5 without a fresh trigger. An old loop must not resume
      // across that ownership change. Invalidate only our private pointer and
      // ACTIVE/REVERSE word; the next type5 trigger rebuilds the record. Stock
      // track buffers, release envelopes and the other private fields are kept.
.GLOBAL os_invalidate.;
os_invalidate.:

.GLOBAL os_diag_publish_s11_23.;
os_diag_publish_s11_23.:
      R0 = DM(0x30dc90);
      R1 = 16;
      COMPU(R0, R1);
      R0 = 0;
      DM(0x30dd48) = R0;
      R0 = DM(0x30dcf0);
      R1 = DM(0x30dcf4);
      R1 = LSHIFT R1 BY 24;
      R1 = LSHIFT R1 BY -24;
      R0 = R0 OR R1;
      R0 = PASS R0;
      IF EQ JUMP 0x185f50; // -> os_diag_invalidation_not_live_22.
      R0 = 1;
      DM(0x30dd48) = R0;

.GLOBAL os_diag_invalidation_not_live_22.;
os_diag_invalidation_not_live_22.:
      R4 = DM(0x30dc98);
      I4 = R4;
      R0 = 0;
      DM(0, I4) = R0;
      R1 = 0x1b8;
      R4 = R1 + R4;
      I4 = R4;
      DM(0, I4) = R0;
      R0 = 0;
      DM(0x30dcf0) = R0;
      R0 = 0;
      DM(0x30dcf4) = R0;
      CALL 0x186041; // -> os_diag_status_helper.
      R0 = DM(0x30dd48);
      R0 = PASS R0;
      IF EQ JUMP 0x185fa9; // -> os_diag_no_invalidation_latch_24.

.GLOBAL os_diag_latch_k3_25.;
os_diag_latch_k3_25.:
      R0 = DM(0x30dd0c);
      DM(0x30dd10) = R0;
      R0 = DM(0x30dcf0);
      DM(0x30dd14) = R0;
      R0 = DM(0x30dcfc);
      DM(0x30dd18) = R0;
      R0 = DM(0x30dd00);
      DM(0x30dd1c) = R0;
      R0 = DM(0x30dc90);
      DM(0x30dd20) = R0;
      R0 = DM(0x30dc94);
      DM(0x30dd24) = R0;
      R0 = DM(0x30dcd0);
      DM(0x30dd28) = R0;
      R0 = 3;
      DM(0x30dd2c) = R0;
      R0 = 1;
      DM(0x30dd30) = R0;

.GLOBAL os_diag_no_invalidation_latch_24.;
os_diag_no_invalidation_latch_24.:

.GLOBAL os_diag_publish_s12_26.;
os_diag_publish_s12_26.:
      R0 = DM(0x30dc90);
      R1 = 16;
      COMPU(R0, R1);
      JUMP 0x185d35; // -> os_next.

.GLOBAL os_diag_bank_bad.;
os_diag_bank_bad.:

.GLOBAL os_diag_latch_k4_27.;
os_diag_latch_k4_27.:
      R0 = DM(0x30dd0c);
      DM(0x30dd10) = R0;
      R0 = DM(0x30dcf0);
      DM(0x30dd14) = R0;
      R0 = DM(0x30dcfc);
      DM(0x30dd18) = R0;
      R0 = DM(0x30dd00);
      DM(0x30dd1c) = R0;
      R0 = DM(0x30dc90);
      DM(0x30dd20) = R0;
      R0 = DM(0x30dc94);
      DM(0x30dd24) = R0;
      R0 = DM(0x30dcd0);
      DM(0x30dd28) = R0;
      R0 = 4;
      DM(0x30dd2c) = R0;
      R0 = 1;
      DM(0x30dd30) = R0;

.GLOBAL os_diag_publish_s13_28.;
os_diag_publish_s13_28.:
      R0 = DM(0x30dcf0);
      DM(0x30dd6c) = R0;
      R0 = DM(0x30dd00);
      DM(0x30dd70) = R0;
      R0 = 872275;
      DM(0x30dd60) = R0;
      R0 = DM(0x30dc94);
      DM(0x30dd68) = R0;
      CALL 0x1860d0; // -> os_diag_publish_helper.
      JUMP 0x185d35; // -> os_next.

.GLOBAL os_diag_quiet_pointer.;
os_diag_quiet_pointer.:

.GLOBAL os_diag_publish_s13_29.;
os_diag_publish_s13_29.:
      R0 = DM(0x30dcf0);
      DM(0x30dd6c) = R0;
      R0 = DM(0x30dd00);
      DM(0x30dd70) = R0;
      R0 = 872275;
      DM(0x30dd60) = R0;
      R0 = DM(0x30dc94);
      DM(0x30dd68) = R0;
      CALL 0x1860d0; // -> os_diag_publish_helper.
      JUMP 0x185ee7; // -> os_quiet.

.GLOBAL os_diag_quiet_active.;
os_diag_quiet_active.:

.GLOBAL os_diag_publish_s13_30.;
os_diag_publish_s13_30.:
      R0 = DM(0x30dcf0);
      DM(0x30dd6c) = R0;
      R0 = DM(0x30dd00);
      DM(0x30dd70) = R0;
      R0 = 872275;
      DM(0x30dd60) = R0;
      R0 = DM(0x30dc94);
      DM(0x30dd68) = R0;
      CALL 0x1860d0; // -> os_diag_publish_helper.
      JUMP 0x185ee7; // -> os_quiet.

.GLOBAL os_diag_status_helper.;
os_diag_status_helper.:
      R0 = DM(0x30dce0);
      R1 = 5;
      COMPU(R0, R1);
      IF GT JUMP 0x18604e; // -> os_diag_type_unknown_31.
      JUMP 0x186050; // -> os_diag_type_done_32.

.GLOBAL os_diag_type_unknown_31.;
os_diag_type_unknown_31.:
      R0 = 7;

.GLOBAL os_diag_type_done_32.;
os_diag_type_done_32.:
      R0 = LSHIFT R0 BY 24;
      DM(0x30dd0c) = R0;
      R0 = DM(0x30dcf0);
      R0 = PASS R0;
      IF EQ JUMP 0x186067; // -> os_diag_status_skip_33.
      R0 = DM(0x30dd0c);
      R1 = 0x8000000;
      R0 = R0 OR R1;
      DM(0x30dd0c) = R0;

.GLOBAL os_diag_status_skip_33.;
os_diag_status_skip_33.:
      R0 = DM(0x30dd04);
      R0 = PASS R0;
      IF EQ JUMP 0x186078; // -> os_diag_status_skip_34.
      R0 = DM(0x30dd0c);
      R1 = 0x10000000;
      R0 = R0 OR R1;
      DM(0x30dd0c) = R0;

.GLOBAL os_diag_status_skip_34.;
os_diag_status_skip_34.:
      R0 = DM(0x30dcf8);
      R0 = PASS R0;
      IF EQ JUMP 0x186089; // -> os_diag_status_skip_35.
      R0 = DM(0x30dd0c);
      R1 = 0x20000000;
      R0 = R0 OR R1;
      DM(0x30dd0c) = R0;

.GLOBAL os_diag_status_skip_35.;
os_diag_status_skip_35.:
      R0 = DM(0x30dcf4);
      R0 = LSHIFT R0 BY -24;
      R1 = 0xff;
      R0 = R0 AND R1;
      R0 = PASS R0;
      IF EQ JUMP 0x1860a0; // -> os_diag_status_skip_36.
      R0 = DM(0x30dd0c);
      R1 = 0x40000000;
      R0 = R0 OR R1;
      DM(0x30dd0c) = R0;

.GLOBAL os_diag_status_skip_36.;
os_diag_status_skip_36.:
      R0 = DM(0x30dce8);
      R1 = 0xff;
      R0 = R0 AND R1;
      R0 = LSHIFT R0 BY 16;
      R1 = DM(0x30dd0c);
      R0 = R0 OR R1;
      DM(0x30dd0c) = R0;
      R0 = DM(0x30dcec);
      R1 = 0xff;
      R0 = R0 AND R1;
      R0 = LSHIFT R0 BY 8;
      R1 = DM(0x30dd0c);
      R0 = R0 OR R1;
      DM(0x30dd0c) = R0;
      R0 = DM(0x30dcf4);
      R1 = 0xff;
      R0 = R0 AND R1;
      R1 = DM(0x30dd0c);
      R0 = R0 OR R1;
      DM(0x30dd0c) = R0;
      RETURN;

.GLOBAL os_diag_publish_helper.;
os_diag_publish_helper.:
      R0 = DM(0x30dd0c);
      R1 = LSHIFT R0 BY 16;
      R0 = LSHIFT R0 BY -16;
      R0 = R0 OR R1;
      DM(0x2c49dc) = R0;
      DM(0x2c59dc) = R0;
      R0 = DM(0x30dd6c);
      R1 = LSHIFT R0 BY 16;
      R0 = LSHIFT R0 BY -16;
      R0 = R0 OR R1;
      DM(0x2c49e0) = R0;
      DM(0x2c59e0) = R0;
      R0 = DM(0x30dd70);
      R1 = LSHIFT R0 BY 16;
      R0 = LSHIFT R0 BY -16;
      R0 = R0 OR R1;
      DM(0x2c49e8) = R0;
      DM(0x2c59e8) = R0;

.GLOBAL os_diag_legacy_helper_compare.;
os_diag_legacy_helper_compare.:
      R0 = DM(0x30dc90);
      R1 = 16;
      COMPU(R0, R1);
      R0 = 0x80000000;
      R1 = DM(0x30dd68);
      R1 = LSHIFT R1 BY 20;
      R0 = R0 OR R1;
      R1 = DM(0x30dd60);
      R0 = R0 OR R1;
      DM(0x2c49d4) = R0;
      DM(0x2c59d4) = R0;
      RETURN;
.os_type5..end:
      .type os_type5.,STT_FUNC;

.GLOBAL os_handoff_early_guard.;
os_handoff_early_guard.:
      IF NOT SV JUMP 0x1c2875; // unchanged native early copy
      DM(0x30dc10) = R0;
      DM(0x30dc14) = R1;
      DM(0x30dc18) = R2;
      DM(0x30dc1c) = R3;
      DM(0x30dc20) = R4;
      DM(0x30dc24) = R5;
      DM(0x30dc60) = I4;
      DM(0x30dc64) = I5;
      DM(0x30dc88) = ASTATX;
      DM(0x30dc8c) = ASTATY;
      R5 = DM(-32, I6);
      R0 = 32;
      R0 = R5 + R0;
      I4 = R0;
      R4 = DM(0, I4);
      R4 = LSHIFT R4 BY -16;
      R1 = 0xffff;
      R4 = R4 AND R1;
      R0 = 0;

.GLOBAL os_handoff_guard_loop.;
os_handoff_guard_loop.:
      BTST R4 BY R0;
      IF SZ JUMP 0x18619f; // -> os_handoff_guard_next.
      R1 = 1;
      R1 = R0 AND R1;
      R2 = R0 - R1;
      R2 = LSHIFT R2 BY 1;
      R3 = 148;
      R3 = R5 + R3;
      R3 = R3 + R2;
      I4 = R3;
      R3 = 0x25c520;
      R2 = R3 + R2;
      I5 = R2;
      R2 = DM(0, I4);
      R3 = DM(0, I5);
      R1 = LSHIFT R1 BY 4;
      R1 = -R1;
      R2 = LSHIFT R2 BY R1;
      R3 = LSHIFT R3 BY R1;
      R1 = 0xffff;
      R2 = R2 AND R1;
      R3 = R3 AND R1;
      R1 = 6;
      R1 = R2 - R1;
      IF GE JUMP 0x18619f; // -> os_handoff_guard_next.
      R1 = 6;
      R1 = R3 - R1;
      IF GE JUMP 0x18619f; // -> os_handoff_guard_next.
      R1 = 5;
      R2 = R2 - R1;
      IF EQ JUMP 0x18619b; // -> os_handoff_guard_new5.
      R3 = R3 - R1;
      IF EQ JUMP 0x1861ad; // -> os_handoff_guard_copy.
      JUMP 0x18619f; // -> os_handoff_guard_next.

.GLOBAL os_handoff_guard_new5.;
os_handoff_guard_new5.:
      R3 = R3 - R1;
      IF NE JUMP 0x1861ad; // -> os_handoff_guard_copy.

.GLOBAL os_handoff_guard_next.;
os_handoff_guard_next.:
      R1 = 1;
      R0 = R1 + R0;
      R1 = 16;
      R1 = R0 - R1;
      IF NE JUMP 0x186152; // -> os_handoff_guard_loop.
      JUMP 0x1861ce; // -> os_handoff_guard_skip.

.GLOBAL os_handoff_guard_copy.;
os_handoff_guard_copy.:
      R0 = DM(0x30dc10);
      R1 = DM(0x30dc14);
      R2 = DM(0x30dc18);
      R3 = DM(0x30dc1c);
      R4 = DM(0x30dc20);
      R5 = DM(0x30dc24);
      I4 = DM(0x30dc60);
      I5 = DM(0x30dc64);
      ASTATY = DM(0x30dc8c);
      ASTATX = DM(0x30dc88);
      JUMP 0x1c2875; // original native copy continuation

.GLOBAL os_handoff_guard_skip.;
os_handoff_guard_skip.:
      R0 = DM(0x30dc10);
      R1 = DM(0x30dc14);
      R2 = DM(0x30dc18);
      R3 = DM(0x30dc1c);
      R4 = DM(0x30dc20);
      R5 = DM(0x30dc24);
      I4 = DM(0x30dc60);
      I5 = DM(0x30dc64);
      ASTATY = DM(0x30dc8c);
      ASTATX = DM(0x30dc88);
      JUMP 0x1c2888; // original native skip continuation
