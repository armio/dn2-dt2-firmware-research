/* M3b static format stub (rev 2, 2026-10-09): the donor helper's format
 * callee. ABI = the donor format (this @ sp+4, text @ sp+8, buffer @ sp+12):
 * write the resolved text pointer through this and return. The rev 1 build
 * repointed the helper at the DN2 native heap-format twin (format ->
 * builder -> allocator -> memcpy): on hardware that chain runs ~140 bytes
 * deep and allocates per value change INSIDE the per-frame GUI draw call,
 * and the stock GUI stack ran near its floor — the draw faulted with an
 * access error at the stack base (device EXCEPTION DS0059, fault address
 * 0x00180000). The donor's own caller disposes and refills a caller-owned
 * string; the drawer path has no such owner, so the heap lifecycle cannot
 * be transplanted there at all. This stub keeps the donor helper's shape
 * (gate -> lookup -> format-call) with the format's write-through contract
 * resolved statically: no heap, no deep calls, no dispose needed, the
 * baked names are stable for the life of the image.
 */
.text
.global m3b_static_format
m3b_static_format:
    movea.l 4(%sp),%a0        /* this (the char* slot) */
    move.l  8(%sp),%d1        /* text (the resolved name) */
    move.l  %d1,(%a0)         /* *(this) = text */
    rts