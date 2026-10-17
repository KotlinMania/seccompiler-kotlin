// port-lint: source backend/rule.rs
// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler.backend

/**
 * Rule that a filter attempts to match for a syscall.
 *
 * If all conditions match then rule gets matched.
 * A syscall can have many rules associated. If either of them matches, the `matchAction` of the
 * [SeccompFilter] is triggered.
 */
@ConsistentCopyVisibility
public data class SeccompRule internal constructor(
    /** Conditions of rule that need to match in order for the rule to get matched. */
    internal val conditions: List<SeccompCondition>,
) {
    public companion object {
        /**
         * Creates a new rule. Rules with 0 conditions are not allowed; to match a syscall regardless
         * of argument values, map the syscall number to an empty vector of rules when constructing
         * the [SeccompFilter] instead.
         *
         * @param conditions List of [SeccompCondition]s that the syscall must match.
         */
        public fun new(conditions: List<SeccompCondition>): Result<SeccompRule> {
            val instance = SeccompRule(conditions)
            val validation = instance.validate()
            if (validation.isFailure) {
                return Result.failure(validation.exceptionOrNull()!!)
            }
            return Result.success(instance)
        }

        /**
         * Appends a condition of the rule to an accumulator.
         *
         * The length of the rule and offset to the next rule are updated.
         */
        internal fun appendCondition(
            condition: SeccompCondition,
            accumulator: MutableList<List<SockFilter>>,
            offsetRef: IntArray,
        ) {
            var offset = offsetRef[0]
            if (offset + CONDITION_MAX_LEN.toInt() + 1 > 255) {
                val helperJumps =
                    listOf(
                        bpfStmt(BPF_JMP or BPF_JA, 2u),
                        bpfStmt(BPF_JMP or BPF_JA, offset.toUInt() + 1u),
                        bpfStmt(BPF_JMP or BPF_JA, offset.toUInt() + 1u),
                    )
                accumulator.add(helperJumps)
                offset = 1
            }

            val bpfCondition = condition.intoBpf(offset.toUInt())
            offset += bpfCondition.size
            offsetRef[0] = offset
            accumulator.add(bpfCondition)
        }
    }

    /** Performs semantic checks on the SeccompRule. */
    internal fun validate(): Result<Unit> {
        if (conditions.isEmpty()) {
            return Result.failure(Error.EmptyRule)
        }
        return Result.success(Unit)
    }

    public fun toBpf(): BpfProgram {
        val accumulator = ArrayList<List<SockFilter>>(conditions.size * CONDITION_MAX_LEN.toInt())
        val offsetRef = intArrayOf(1)

        for (condition in conditions) {
            appendCondition(condition, accumulator, offsetRef)
        }

        accumulator.add(
            listOf(
                bpfStmt(BPF_JMP or BPF_JA, 1u),
                bpfStmt(BPF_JMP or BPF_JA, offsetRef[0].toUInt() + 1u),
            ),
        )

        val result = mutableListOf<SockFilter>()
        for (instructions in accumulator.asReversed()) {
            result.addAll(instructions)
        }
        return result
    }
}
