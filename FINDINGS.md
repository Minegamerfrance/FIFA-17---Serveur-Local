# FINDINGS

## ProtoSSL Verification Setup

Stalker proved too brittle (causing thread desync/buffer latencies when analyzing `FAIL_9` jump-table paths), but fuzzy backtraces highlighted several candidates for the actual `VerifyCert` caller or dispatchers:
- `0x61321de`
- `0x612f38f`
- `0x61261da`

In v64, we've fixed a `patchCount` error from v62 and implemented the superior `je -> jmp` patch at `0x612f39c`. This bypasses the accumulated error check in `edi` completely, rather than just clearing `eax` which might not be enough if `edi` was already non-zero.

We've retained the `strHost` sticky fix to handle CN resets.