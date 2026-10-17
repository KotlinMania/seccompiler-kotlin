// port-lint: source backend/filter.rs
// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler.backend

/** Filter containing rules assigned to syscall numbers. */
@ConsistentCopyVisibility
public data class SeccompFilter internal constructor(
    /** Map of syscall numbers and corresponding rule chains. */
    internal val rules: Map<Long, List<SeccompRule>>,
    /** Default action to apply to syscalls that do not match the filter. */
    internal val mismatchAction: SeccompAction,
    /** Filter action to apply to syscalls that match the filter. */
    internal val matchAction: SeccompAction,
    /** Target architecture of the generated BPF filter. */
    internal val targetArch: TargetArch,
) {
    public companion object {
        /**
         * Creates a new filter with a set of rules, an on-match and default action.
         *
         * @param rules Map containing syscall numbers and their respective [SeccompRule]s.
         * @param mismatchAction [SeccompAction] taken for all syscalls that do not match the filter.
         * @param matchAction [SeccompAction] taken for system calls that match the filter.
         * @param targetArch Target architecture of the generated BPF filter.
         */
        public fun new(
            rules: Map<Long, List<SeccompRule>>,
            mismatchAction: SeccompAction,
            matchAction: SeccompAction,
            targetArch: TargetArch,
        ): Result<SeccompFilter> {
            val instance = SeccompFilter(rules, mismatchAction, matchAction, targetArch)
            val validation = instance.validate()
            if (validation.isFailure) {
                return Result.failure(validation.exceptionOrNull()!!)
            }
            return Result.success(instance)
        }

        /**
         * Appends a chain of rules to an accumulator, updating the length of the filter.
         */
        internal fun appendSyscallChain(
            syscallNumber: Long,
            chain: List<SeccompRule>,
            mismatchAction: SeccompAction,
            matchAction: SeccompAction,
            accumulator: MutableList<List<SockFilter>>,
        ): Result<Unit> {
            val chainBpf =
                chain.map { rule ->
                    val bpf = rule.toBpf().toMutableList()
                    bpf.add(bpfStmt(BPF_RET or BPF_K, matchAction.toUInt()))
                    bpf
                }
            val chainLen = chainBpf.sumOf { it.size }

            val builtSyscall = ArrayList<SockFilter>(chainLen + 2)
            builtSyscall.add(
                bpfJump(
                    BPF_JMP or BPF_JEQ or BPF_K,
                    syscallNumber.toUInt(),
                    0u,
                    1u,
                ),
            )

            if (chainBpf.isEmpty()) {
                builtSyscall.add(bpfStmt(BPF_JMP or BPF_JA, 1u))
                builtSyscall.add(bpfStmt(BPF_JMP or BPF_JA, 2u))
                builtSyscall.add(bpfStmt(BPF_RET or BPF_K, matchAction.toUInt()))
            } else {
                for (rule in chainBpf) {
                    builtSyscall.addAll(rule)
                }
            }

            builtSyscall.add(bpfStmt(BPF_RET or BPF_K, mismatchAction.toUInt()))
            accumulator.add(builtSyscall)
            return Result.success(Unit)
        }
    }

    /** Performs semantic checks on the SeccompFilter. */
    internal fun validate(): Result<Unit> {
        if (mismatchAction == matchAction) {
            return Result.failure(Error.IdenticalActions)
        }
        return Result.success(Unit)
    }

    public fun toBpf(): Result<BpfProgram> {
        val result = buildArchValidationSequence(targetArch).toMutableList()

        if (rules.isEmpty()) {
            result.add(bpfStmt(BPF_RET or BPF_K, mismatchAction.toUInt()))
            return Result.success(result)
        }

        val accumulator =
            mutableListOf(
                listOf(
                    bpfStmt(
                        BPF_LD or BPF_W or BPF_ABS,
                        SECCOMP_DATA_NR_OFFSET,
                    ),
                ),
            )

        val sortedRules = rules.entries.sortedBy { it.key }
        for ((syscallNumber, chain) in sortedRules) {
            val res =
                appendSyscallChain(
                    syscallNumber,
                    chain,
                    mismatchAction,
                    matchAction,
                    accumulator,
                )
            if (res.isFailure) {
                return Result.failure(res.exceptionOrNull()!!)
            }
        }

        accumulator.add(listOf(bpfStmt(BPF_RET or BPF_K, mismatchAction.toUInt())))

        for (instructions in accumulator) {
            result.addAll(instructions)
        }

        if (result.size >= BPF_MAX_LEN) {
            return Result.failure(Error.FilterTooLarge(result.size))
        }

        return Result.success(result)
    }
}
