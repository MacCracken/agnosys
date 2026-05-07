# cyrius `match` exhaustiveness check fires inconsistently across fn names

**Status:** RESOLVED in cyrius 5.9.25 — verified by re-running
the sweep at `/tmp/cyrius-match-coverage-dce-gated/`: all 13
fn-name variations now fire the non-exhaustive warning (was a
roughly 50/50 mix of `1`/`0` on 5.9.21). The internal
hash-table indexing bug in the coverage check's bookkeeping
has been fixed. Side-observation also fixed: `cyrius --version`
no longer emits the trailing `\xb3` byte (output is now clean
`cyrius 5.9.25\n`).
**Filed:** 2026-05-06
**Resolved:** 2026-05-07
**Reporter:** agnosys 1.1.5 (during V1.1.3 audit-gate adoption —
discovered while writing up the `defer { }` audit findings; the
"DCE-gated" hypothesis in the 1.1.5 CHANGELOG turned out wrong.
The real failure mode was fn-name-dependent.)
**agnosys version observed:** 1.1.5
**cyrius version active at filing:** 5.9.21 (also reproduced under 5.9.20)
**cyrius version with fix:** 5.9.25
**Severity at filing:** MEDIUM — the documented quality gate was
non-deterministic across fn names. A library author's match-block
coverage check could silently disappear by renaming the enclosing
fn. CI gates built on top of this check were unreliable.

**Local reproducer:** [`/tmp/cyrius-match-coverage-dce-gated/`](/tmp/cyrius-match-coverage-dce-gated/)
— self-contained, ~2 KB. Contains:

```
README.md            ← full diagnostic + suggested upstream investigation
minimal_repro.cyr    ← single-name probe (default `name` — silent;
                       rename to `n` and the warning fires)
sweep.sh             ← runs ~14 fn-name variations and reports
                       which fire the warning
```

## Summary

Same source, same enum, same match body, same call-graph
reachability — only the **fn identifier** changes between runs.
Some fn names trigger the documented `non-exhaustive match`
warning; others silently bypass the check.

```
fn-name         warning fired?
  n               yes
  x               yes
  f               yes
  g               yes
  hi              yes
  map_to          yes
  dispatch_e1     yes
  enum_to_str     yes
  load_x          yes
  x_y             yes
  nm              no
  ab              no
  xy              no
  mn              no
  nx              no
  name            no
  named           no
  namex           no
  func            no
  hello           no
  world           no
  abc             no
  abcdef          no
  check           no
  describe        no
  handle          no
  process         no
```

The match block is non-exhaustive in every case (covers 2 of 3
variants of a 3-variant enum). Per
`vidya content/cyrius/language/features.cyml exhaustive_match_v58x`
the check should fire unconditionally.

The pattern is **not length-based** (`g` fires but `gh` doesn't;
`n` fires but `nm` doesn't), **not stdlib-overlap-based** (no
stdlib fn named `name`, `func`, `handle`, etc.), and **not
character-class-based** (`hi` fires but `ab` and `xy` don't).
Most likely a **hash-table collision** in the coverage check's
internal bookkeeping.

## Reproduction

```sh
cd /tmp/cyrius-match-coverage-dce-gated
./sweep.sh
```

Expected: 27 of 27 rows print `1` (every probe has a non-exhaustive
match; warning should fire). Observed: a roughly even mix of `1`s
and `0`s with no apparent semantic pattern beyond "some
fn-name hash-bucket slots trigger the check, others bypass it."

## Why this matters for agnosys

agnosys 1.1.5 adopted `match` in `src/error.cyr fn syserr_print`
and added a CI gate (`scripts/audit.sh` step 4) that fails the
build on any `non-exhaustive` warning. The gate is correct as
written, but **its effective coverage of agnosys's source
surface depends on which fn names happen to be in cyrius's
"lucky" hash buckets**.

`syserr_print` happens to be in a lucky bucket, so the gate
works for it. But:

- A future agnosys fn renamed to fall into an "unlucky" bucket
  would silently lose the check.
- A library author cannot trust the check to enforce coverage
  on every match block they write.

This is a structural hole in the quality-gate story, not an
acute correctness bug — but it undermines the value the slot
was trying to deliver.

## Correction to agnosys 1.1.5 CHANGELOG

The 1.1.5 CHANGELOG claimed:

> The check fires for ALL enum forms ... earlier testing
> missed this because dead-code-eliminated fns are skipped
> before the check runs. Adding a caller surfaces the warning
> reliably.

That hypothesis was wrong. Re-running the original failing probe
under controlled fn-name variations revealed the real cause is
**fn-name-dependent dispatch in the coverage check**, not
DCE-gating. The "adding a caller surfaces the warning" effect is
likely correlation: the names I happened to use in successful
probes (`dispatch_e1`, etc.) were in lucky buckets; the names in
failed probes (`name`) were in unlucky ones. Renaming the dead
fn from `name` to `n` (still dead — never called) reproduces the
warning even without a caller.

A correction note will land in the 1.1.6 CHANGELOG referencing
this issue. The 1.1.5 audit gate is still correct as a CI hook;
its coverage is just narrower than the CHANGELOG implied.

## Suggested upstream investigation

1. Likely an **internal-table indexing bug** in the coverage
   pass. The check's bookkeeping (per
   vidya `tagged_unions_v58x`: `var_enum_id[8192]`,
   `enum_count[8]`, `enum_variant_count[1024]`,
   `enum_name[1024]`) is keyed on something that interacts with
   fn-name hashing.
2. Likely first probe: log which arm idents the check *sees*
   for each row of the sweep. If some fn-name buckets cause
   arm idents to never be registered against the matched enum,
   the `at least one arm references a variant of an enum`
   short-circuit (per features.cyml `exhaustive_match_v58x`)
   fires too eagerly and skips coverage analysis.
3. Once fixed, the sweep above should produce `1` on every row.

## Side observation (separate bug)

`cyrius --version` emits a stray byte before the newline:

```
$ cyrius --version | xxd
00000000: 6379 7269 7573 2035 2e39 2e32 31b3 0a    cyrius 5.9.21..
```

`\xb3` is a partial UTF-8 sequence or buffer-tail byte. Not
blocking; worth flagging while you're in the version-output
codepath.

## References

- `/tmp/cyrius-match-coverage-dce-gated/README.md` — full reproducer
- agnosys `scripts/audit.sh` step 4 — the CI gate that depends on
  this check firing reliably
- agnosys `src/error.cyr fn syserr_print` — agnosys's first
  `match` block; in a "lucky" hash bucket
- agnosys CHANGELOG `[1.1.5]` — note correction pending in 1.1.6
- vidya `content/cyrius/language/features.cyml`
  `exhaustive_match_v58x` — documents the contract this issue
  reports as not honored
- vidya `content/cyrius/language/features.cyml`
  `tagged_unions_v58x` — documents the internal heap regions
  that likely host the indexing bug
