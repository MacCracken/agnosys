# Capacity Baseline

> Snapshot of Cyrius compiler table utilization across representative agnosys
> builds. Captured at **1.2.4** with **Cyrius 5.10.34** (initial 1.2.1 capture
> still holds — no agnosys source changes between 1.2.1 and 1.2.4; the cyrius
> 5.10.19 → 5.10.34 toolchain refresh is the only delta). Refreshed each
> minor bump. The 85% gate (`cyrius capacity --check`) is enforced on every
> CI build.
>
> Note on table-size growth: Cyrius 5.10.x bumped several table ceilings vs the
> original 1.0.0 baseline (`fixup_table` 16,384 → 262,144; `string_data` 262,144
> → 2,097,152). Percentages here use the current ceilings.

Numbers come from `CYRIUS_STATS=1 cyrius build <src> <out>`.

## Builds measured

All measurements are **core-then-profile** — i.e. consumers are expected to include `dist/agnosys-core.cyr` plus their domain profile. Standalone profile measurements would fail compile (security needs core's `ENOSYS`, system needs core's `SYS_SOCKET_NR`, etc. — by design).

| Build | fn_table | identifiers | var_table | fixup_table | string_data | code_size |
|-------|---------:|------------:|----------:|------------:|------------:|----------:|
| `src/main.cyr` (live core demo, 3 modules: error+syscall+security) | 415 / 4 096 · 10% | 10 714 / 131 072 · 8% | 325 / 8 192 · 4% | 854 / 262 144 · <1% | 1 494 / 2 097 152 · <1% | 92 208 / 1 048 576 · 9% |
| `dist/agnosys-core.cyr` (core profile alone — error + syscall + logging + arch peers) | 543 / 4 096 · 13% | 12 901 / 131 072 · 10% | 363 / 8 192 · 4% | 1 379 / 262 144 · <1% | 1 355 / 2 097 152 · <1% | 140 512 / 1 048 576 · 13% |
| core + security (kavach / aegis / shakti / libro consumer pattern) | 696 / 4 096 · 17% | 18 666 / 131 072 · 14% | 438 / 8 192 · 5% | 1 977 / 262 144 · <1% | 5 079 / 2 097 152 · <1% | 191 864 / 1 048 576 · 18% |
| core + storage (stiva / ark consumer pattern) | 653 / 4 096 · 16% | 16 687 / 131 072 · 13% | 390 / 8 192 · 5% | 1 693 / 262 144 · <1% | 3 693 / 2 097 152 · <1% | 175 224 / 1 048 576 · 17% |
| core + trust (sigil / daimon / hoosh consumer pattern) | 699 / 4 096 · 17% | 18 840 / 131 072 · 14% | 407 / 8 192 · 5% | 1 763 / 262 144 · <1% | 4 542 / 2 097 152 · <1% | 197 312 / 1 048 576 · 19% |
| core + system (argonaut / yukti / soorat / nein consumer pattern) | 810 / 4 096 · 20% | 22 967 / 131 072 · 18% | 459 / 8 192 · 6% | 2 062 / 262 144 · <1% | 5 750 / 2 097 152 · <1% | 219 512 / 1 048 576 · 21% |
| `dist/agnosys.cyr` (full bundle, all 20 modules) | 1 229 / 4 096 · 30% | 38 004 / 131 072 · 29% | 605 / 8 192 · 7% | 3 358 / 262 144 · 1% | 14 917 / 2 097 152 · 1% | 362 016 / 1 048 576 · 35% |

Highest utilization: **code_size 35%** and **fn_table 30%**, both on the full bundle. Every individual core+profile combination stays under 25% across every table — well within the 85% gate, with substantial headroom for V1.2.x or V1.3.x growth.

## Gate

CI runs `cyrius capacity --check src/main.cyr` and fails if any table crosses 85%. Per-profile and full-bundle numbers above are for visibility, not a gate — consumers that include a profile bundle (or the full one) should monitor these locally.

## Regenerate

```sh
# Live core demo (the gate's actual measurement)
cyrius capacity --check src/main.cyr

# Any source file with full stats (the form used to populate this table)
CYRIUS_STATS=1 cyrius build src/main.cyr build/agnosys

# Profile-bundle measurements: consumer needs core + profile + a tiny main wiring.
# Sample wiring in /tmp/cap_meas/ during the 1.2.1 capacity refresh:
#   include "lib/<all consumed stdlib>"
#   include "<repo>/dist/agnosys-core.cyr"
#   include "<repo>/dist/agnosys-<profile>.cyr"
#   fn main() { return 0; }
#   var exit_code = main(); syscall(60, exit_code);
```

## Historical baseline (1.0.0 — Cyrius 5.2.0)

For comparison; superseded by the 1.2.1 numbers above:

| Build | fn_table | identifiers | var_table | fixup_table | string_data | code_size |
|-------|---------:|------------:|----------:|------------:|------------:|----------:|
| `src/main.cyr` (core demo, 3 modules) | 289 / 4096 · 7% | 8 027 / 131 072 · 6% | 296 / 8192 · 4% | 851 / 16 384 · 5% | 1 349 / 262 144 · 1% | 64 000 / 1 048 576 · 6% |
| Consumer pattern (security only) | 236 / 4096 · 6% | 6 788 / 131 072 · 5% | 248 / 8192 · 3% | 697 / 16 384 · 4% | 1 095 / 262 144 · 0% | 50 240 / 1 048 576 · 5% |
| `dist/agnosys.cyr` (full bundle) | 804 / 4096 · 20% | 26 627 / 131 072 · 20% | 883 / 8192 · 11% | 5 227 / 16 384 · 32% | 12 453 / 262 144 · 5% | 444 648 / 1 048 576 · 42% |

The 1.2.1 numbers are higher in absolute fn_table / identifiers (V1.1.0 added 174 derive-emitted fns; V1.1.12 added 14 more for Serialize) but lower in `code_size` percentage (cyrius 5.10.x DCE eats more dead code than 5.2.0; the full bundle is now 35% vs 42%). The `var_table` dropped from 11% to 7% — V1.1.x's typed-struct migrations replaced many heap-allocated globals with per-fn-scope locals.
