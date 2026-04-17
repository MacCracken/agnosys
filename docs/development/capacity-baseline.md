# Capacity Baseline

> Snapshot of Cyrius compiler table utilization across representative agnosys
> builds. Captured at **0.98.0** with **Cyrius 5.2.0**. The 85% gate
> (`cyrius capacity --check`) must stay clean through 1.0 and beyond.

Numbers come from `CYRIUS_STATS=1 cyrius build <src> <out>`.

## Builds measured

| Build | fn_table | identifiers | var_table | fixup_table | string_data | code_size |
|-------|---------:|------------:|----------:|------------:|------------:|----------:|
| `src/main.cyr` (core demo, 3 modules) | 289 / 4096 · 7% | 8 027 / 131 072 · 6% | 296 / 8192 · 4% | 851 / 16 384 · 5% | 1 349 / 262 144 · 1% | 64 000 / 1 048 576 · 6% |
| Consumer pattern (security only, no parent manifest) | 236 / 4096 · 6% | 6 788 / 131 072 · 5% | 248 / 8192 · 3% | 697 / 16 384 · 4% | 1 095 / 262 144 · 0% | 50 240 / 1 048 576 · 5% |
| `dist/agnosys.cyr` (full bundle, 20 modules) | 804 / 4096 · 20% | 26 627 / 131 072 · 20% | 883 / 8192 · 11% | 5 227 / 16 384 · 32% | 12 453 / 262 144 · 5% | 444 648 / 1 048 576 · 42% |

Highest utilization today: **fixup_table 32%** and **code_size 42%**, both on
the full bundle. Core demo and single-module consumers stay under 10% across
every table.

## Gate

CI runs `cyrius capacity --check` on `src/main.cyr` and fails if any table
crosses 85%. The full-bundle numbers above are for visibility, not a gate —
consumers that pull everything via `dist/agnosys.cyr` should monitor these
locally.

## Regenerate

```sh
# Core demo
cyrius capacity --check src/main.cyr

# Any file, with full stats
CYRIUS_STATS=1 cyrius build src/main.cyr build/agnosys
```
