# Immediate Actions - High-Value Files

Based on AST analysis, here are the concrete next steps.

## Summary

- **Files Present:** 8/12 (66.7%)
- **Function parity:** 40/54 matched (target 63) — 74.1%
- **Class/type parity:** 12/17 matched (target 24) — 70.6%
- **Combined symbol parity:** 52/71 matched (target 87) — 73.2%
- **Average inline-code cosine:** 0.25 (function body across 8 matched files)
- **Average documentation cosine:** 0.48 (doc text across 8 matched files)
- **Cheat-zeroed Files:** 0
- **Critical Issues:** 8 files with <0.60 function similarity
- **Needs Review:** 0 files with 0.60-0.84 function similarity
- **Excellent:** 0 files with >=0.85 function similarity

## Priority 1: Fix Incomplete High-Dependency Files

No incomplete high-dependency files detected.

## Priority 2: Port Missing High-Value Files

Critical missing files (>10 dependencies):

No missing high-value files detected.

## Detailed Work Items

Every matched file is listed below with function and type symbol parity.

### 1. frontend.json

- **Target:** `frontend.Json`
- **Similarity:** 0.03
- **Dependents:** 0
- **Priority Score:** 152509.7
- **Functions:** 4/15 matched (target 23)
- **Missing functions:** `source`, `fmt`, `deserialize`, `expecting`, `visit_map`, `deserialize`, `try_from`, `new`, `new`, `new`, `new`
- **Types:** 6/10 matched (target 11)
- **Missing types:** `JsonFilterMap`, `JsonFilterMapVisitor`, `Value`, `JsonComment`
- **Tests:** 2/5 matched

### 2. backend.filter

- **Target:** `backend.Filter`
- **Similarity:** 0.25
- **Dependents:** 0
- **Priority Score:** 31207.5
- **Functions:** 8/10 matched
- **Missing functions:** `try_from`, `create_test_bpf_filter`
- **Types:** 1/2 matched
- **Missing types:** `Error`
- **Tests:** 5/6 matched

### 3. backend.rule

- **Target:** `backend.Rule`
- **Similarity:** 0.17
- **Dependents:** 0
- **Priority Score:** 10808.3
- **Functions:** 6/7 matched
- **Missing functions:** `from`
- **Types:** 1/1 matched (target 2)
- **Missing types:** _none_
- **Tests:** 3/3 matched

### 4. backend.condition

- **Target:** `backend.Condition`
- **Similarity:** 0.32
- **Dependents:** 0
- **Priority Score:** 1606.8
- **Functions:** 15/15 matched (target 16)
- **Missing functions:** _none_
- **Types:** 1/1 matched (target 2)
- **Missing types:** _none_
- **Tests:** 3/3 matched

### 5. backend.bpf

- **Target:** `backend.Bpf`
- **Similarity:** 0.36
- **Dependents:** 0
- **Priority Score:** 706.4
- **Functions:** 4/4 matched
- **Missing functions:** _none_
- **Types:** 3/3 matched (target 4)
- **Missing types:** _none_
- **Tests:** 1/1 matched

### 6. syscall_table.aarch64

- **Target:** `syscalltable.Aarch64`
- **Similarity:** 0.30
- **Dependents:** 0
- **Priority Score:** 107.0
- **Functions:** 1/1 matched
- **Missing functions:** _none_
- **Types:** 0/0 matched (target 1)
- **Missing types:** _none_

### 7. syscall_table.riscv64

- **Target:** `syscalltable.Riscv64`
- **Similarity:** 0.30
- **Dependents:** 0
- **Priority Score:** 107.0
- **Functions:** 1/1 matched
- **Missing functions:** _none_
- **Types:** 0/0 matched (target 1)
- **Missing types:** _none_

### 8. syscall_table.x86_64

- **Target:** `syscalltable.X86_64`
- **Similarity:** 0.30
- **Dependents:** 0
- **Priority Score:** 107.0
- **Functions:** 1/1 matched
- **Missing functions:** _none_
- **Types:** 0/0 matched (target 1)
- **Missing types:** _none_

## Success Criteria

For each file to be considered "complete":
- **Similarity ≥ 0.85** (Excellent threshold)
- All public APIs ported
- All tests ported
- Documentation ported
- port-lint header present

## Reexport / Wiring Modules

These files match `reexport_modules` patterns in `.ast_distance_config.json`. They are filtered out of
normal priority and missing-file ladders because they are wiring
modules, not direct logic ports. Consult them for call-site routing;
do not treat them as the next implementation target by default.

### Missing

| Source | Expected target | Deps | Source path | Expected path |
|--------|-----------------|------|-------------|---------------|
| `backend.mod` | `backend.Mod` | 0 | `backend/mod.rs` | `backend/Mod.kt` |
| `frontend.mod` | `frontend.Mod` | 0 | `frontend/mod.rs` | `frontend/Mod.kt` |
| `lib` | `Lib` | 0 | `lib.rs` | `Lib.kt` |
| `syscall_table.mod` | `syscalltable.Mod` | 0 | `syscall_table/mod.rs` | `syscalltable/Mod.kt` |

