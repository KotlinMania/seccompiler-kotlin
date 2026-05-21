# Immediate Actions - High-Value Files

Based on AST analysis, here are the concrete next steps.

## Summary

- **Files Present:** 4/12 (33.3%)
- **Function parity:** 21/59 matched (target 28) — 35.6%
- **Class/type parity:** 10/23 matched (target 32) — 43.5%
- **Combined symbol parity:** 31/82 matched (target 60) — 37.8%
- **Average inline-code cosine:** 0.79 (function body across 2 matched files)
- **Average documentation cosine:** 0.84 (doc text across 2 matched files)
- **Cheat-zeroed Files:** 2
- **Critical Issues:** 2 files with <0.60 function similarity

## Priority 1: Fix Incomplete High-Dependency Files

No incomplete high-dependency files detected.

## Priority 2: Port Missing High-Value Files

Critical missing files (>10 dependencies):

No missing high-value files detected.

## Detailed Work Items

Every matched file is listed below with function and type symbol parity.

### 1. backend.mod

- **Target:** `backend.Mod [STUB]`
- **Similarity:** 0.00
- **Dependents:** 0
- **Priority Score:** 31110.0
- **Functions:** 2/5 matched (target 6)
- **Missing functions:** `fmt`, `from`, `test_target_arch`
- **Types:** 6/6 matched (target 25)
- **Missing types:** _none_
- **Tests:** 0/1 matched

### 2. backend.condition

- **Target:** `backend.Condition`
- **Similarity:** 0.76
- **Dependents:** 0
- **Priority Score:** 1602.4
- **Functions:** 15/15 matched (target 16)
- **Missing functions:** _none_
- **Types:** 1/1 matched (target 2)
- **Missing types:** _none_
- **Tests:** 3/3 matched

### 3. backend.bpf

- **Target:** `backend.Bpf`
- **Similarity:** 0.81
- **Dependents:** 0
- **Priority Score:** 701.9
- **Functions:** 4/4 matched
- **Missing functions:** _none_
- **Types:** 3/3 matched (target 4)
- **Missing types:** _none_
- **Tests:** 1/1 matched

### 4. frontend.mod

- **Target:** `backend.ModTest [STUB] [PROVENANCE-FALLBACK]`
- **Similarity:** 0.00
- **Dependents:** 0
- **Priority Score:** 10.0
- **Functions:** 0/0 matched (target 2)
- **Missing functions:** _none_
- **Types:** 0/0 matched (target 1)
- **Missing types:** _none_
- **Provenance warning:** port-lint provenance header matched only by basename: `backend/mod.rs` vs expected `frontend/mod.rs`
- **Proposed provenance header:** `// port-lint: source frontend/mod.rs` (current: `// port-lint: source backend/mod.rs`)
- **Lint issues:** 1

## Success Criteria

For each file to be considered "complete":
- **Similarity ≥ 0.85** (Excellent threshold)
- All public APIs ported
- All tests ported
- Documentation ported
- port-lint header present

## Next Commands

```bash
# Initialize task queue for systematic porting
cd tools/ast_distance
./ast_distance --init-tasks ../../tmp/seccompiler/src rust ../../src/commonMain/kotlin/io/github/kotlinmania/seccompiler kotlin tasks.json ../../AGENTS.md

# Get next high-priority task
./ast_distance --assign tasks.json <agent-id>
```
## Reexport / Wiring Modules

These files match `reexport_modules` patterns in `.ast_distance_config.json`. They are filtered out of
normal priority and missing-file ladders because they are wiring
modules, not direct logic ports. Consult them for call-site routing;
do not treat them as the next implementation target by default.

### Missing

| Source | Expected target | Deps | Source path | Expected path |
|--------|-----------------|------|-------------|---------------|
| `lib` | `Lib` | 0 | `lib.rs` | `Lib.kt` |
| `syscall_table.mod` | `syscalltable.Mod` | 0 | `syscall_table/mod.rs` | `syscalltable/Mod.kt` |

