# cyrius aarch64 backend doesn't support sub-8-byte struct field loads

**Filed:** 2026-05-07
**Reporter:** agnosys 1.1.9 (V1.1.8 multi-width struct field
migration shipped clean on x86_64 but broke aarch64 cross-build
in CI; reverted in 1.1.9).
**agnosys version observed:** 1.1.8 (reverted in 1.1.9)
**cyrius version active:** 5.9.25
**Severity:** MEDIUM — gates the V1.1.8 deliverable for any
project that cross-compiles to aarch64. Affects `i16`/`i8`
field loads via pointer-to-struct dot syntax (write side and
`i32` loads work fine).

**Local reproducer:** [`/tmp/cyrius-aarch64-sub-8-byte-struct-load/`](/tmp/cyrius-aarch64-sub-8-byte-struct-load/)
— self-contained, ~1 KB. Contains:

```
README.md            ← full diagnostic + suggested upstream fix shape
minimal_repro.cyr    ← struct with i16 + i32 fields; load both
                       on x86_64 (works) vs aarch64 (fails)
```

## Summary

cyrius's pointer-to-struct dot syntax (`var s: T = ptr; var v = s.f;`)
emits the correct width-aware load on x86_64 (v5.6.0+). The
aarch64 backend rejects the codegen path for any field smaller
than 4 bytes:

```
error:1610: sub-8-byte struct field load is x86-only for v5.6.0; aarch64 + cx pending
```

The error message itself documents that the aarch64 backend is
known-incomplete here; the work is "pending."

## Reproduction

```sh
cd /tmp/cyrius-aarch64-sub-8-byte-struct-load
cyrius build minimal_repro.cyr minimal_repro                   # x86_64: works
./minimal_repro                                                # prints "100\n7"
cyrius build --aarch64 minimal_repro.cyr minimal_repro_aarch64 # aarch64: FAILS
```

aarch64 output:

```
compile minimal_repro.cyr -> minimal_repro_aarch64 [aarch64] error:1610: sub-8-byte struct field load is x86-only for v5.6.0; aarch64 + cx pending
FAIL
```

## Scope

- **Stores work** on aarch64 (verified — agnosys's V1.1.8
  write-side changes built clean on aarch64). Only the load
  codegen is missing.
- **`i32` loads work** on aarch64. Only sub-32-bit (`i16`, `i8`)
  field loads break, despite the error message saying
  "sub-8-byte."
- The `cx` (cyrius-x bytecode) backend is also flagged as
  pending per the error message.

## Why this matters for agnosys

agnosys 1.1.8 migrated four kernel-ABI structs to typed `struct`
decls + pointer-to-struct dot syntax. Three of those have `i16`
fields (`sockaddr_nl.nl_family`, `sockaddr_nl.nl_pad`,
`nlmsghdr.nlmsg_type`, `nlmsghdr.nlmsg_flags`, `bpf_insn.code`).
Read-side dot syntax in `audit.cyr fn audit_recv_raw` loads
`hdr.nlmsg_type` (i16) — which broke the aarch64 CI cross-build:

```
compile fuzz/audit_nlmsg.fcyr -> build/audit_nlmsg-aarch64 [aarch64] FAIL
Error: Process completed with exit code 1.
```

agnosys's local audit (`scripts/audit.sh`) only x86_64-built;
the aarch64 cross-build was a CI-only gate. agnosys 1.1.9 (a)
reverts V1.1.8's source changes back to explicit `store16`/
`load32` calls and (b) extends the local audit to also
cross-build for aarch64 so this regression class is caught in
local audit, not just CI.

When the upstream aarch64 EFLLOAD_W path lands, the V1.1.8
migration re-opens.

## Suggested upstream investigation

1. The fix mirrors the existing x86_64 codegen for sub-8-byte
   field loads. From vidya `multi_width_types`:
   ```
   Width 1: movzx rax, byte [addr]
   Width 2: movzx eax, word [addr]
   Width 4: mov eax, [addr]
   Width 8: mov rax, [addr]
   ```
   The aarch64 equivalents are `ldrb w0, [x1]` (1 byte),
   `ldrh w0, [x1]` (2 byte), `ldr w0, [x1]` (4 byte),
   `ldr x0, [x1]` (8 byte). Width-4 and width-8 are presumably
   already wired in the aarch64 backend; widths 1 and 2 are
   what's missing.
2. Same shape needed for the `cx` bytecode backend.
3. Stores of sub-8-byte struct fields already work on aarch64
   (we verified during the 1.1.8 → 1.1.9 revert work — the
   write-side dot syntax built clean). So the asymmetry is
   load-only; whichever code change added store support didn't
   pair it with the load side.

## References

- `/tmp/cyrius-aarch64-sub-8-byte-struct-load/README.md` —
  full reproducer
- agnosys CHANGELOG `[1.1.8]` (reverted) — the V1.1.8 work that
  exposed this gap
- agnosys CHANGELOG `[1.1.9]` (revert + audit-gate enhancement)
  — documents the revert shape
- agnosys `scripts/audit.sh` — gate 4 extended in 1.1.9 to add
  `cyrius build --aarch64` and grep its build log for the
  `error:1610` pattern as a hard gate
- vidya `content/cyrius/language/features.cyml`
  `multi_width_types` — documents the width-correct codegen
  contract that the aarch64 backend doesn't yet honor for
  struct-field loads
