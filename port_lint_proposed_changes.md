# port-lint Proposed Changes

**Generated:** 2026-05-20
**Source:** tmp/seccompiler/src
**Target:** src/commonMain/kotlin/io/github/kotlinmania/seccompiler

These are review proposals only. They are emitted when a Rust -> Kotlin pair matches only after fallback normalization, so the existing `port-lint` header is not an exact provenance match.

| Target file | Current header | Proposed header | Source path | Reason |
|-------------|----------------|-----------------|-------------|--------|
| `src/commonTest/kotlin/io/github/kotlinmania/seccompiler/backend/ModTest.kt` | `// port-lint: source backend/mod.rs` | `// port-lint: source frontend/mod.rs` | `frontend/mod.rs` | `port-lint provenance header matched only by basename: 'backend/mod.rs' vs expected 'frontend/mod.rs'` |
