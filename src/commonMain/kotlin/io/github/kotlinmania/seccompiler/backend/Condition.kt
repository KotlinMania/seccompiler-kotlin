// port-lint: source src/backend/condition.rs
// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler.backend

/** Condition that a syscall must match in order to satisfy a rule. */
@ConsistentCopyVisibility
public data class SeccompCondition internal constructor(
    /** Index of the argument that is to be compared. */
    internal val argIndex: UInt,
    /** Length of the argument value that is to be compared. */
    internal val argLen: SeccompCmpArgLen,
    /** Comparison operator to perform. */
    internal val operator: SeccompCmpOp,
    /** The value that will be compared with the argument value of the syscall. */
    internal val value: ULong,
) {
    public companion object {
        /**
         * Creates a new [SeccompCondition].
         *
         * @param argIndex Index of the argument that is to be compared.
         * @param argLen Length of the argument value that is to be compared.
         * @param operator Comparison operator to perform.
         * @param value The value that will be compared with the argument value of the syscall.
         *
         * Example:
         *
         * ```
         * val condition = SeccompCondition.new(0u, SeccompCmpArgLen.DWORD, SeccompCmpOp.Eq, 1u)
         *     .getOrThrow()
         * ```
         */
        public fun new(
            argIndex: UInt,
            argLen: SeccompCmpArgLen,
            operator: SeccompCmpOp,
            value: ULong,
        ): Result<SeccompCondition> {
            val instance = SeccompCondition(argIndex, argLen, operator, value)
            return instance.validate().map { instance }
        }
    }

    /** Validates the [SeccompCondition] data. */
    private fun validate(): Result<Unit> {
        // Checks that the given argument number is valid.
        if (argIndex > ARG_NUMBER_MAX) {
            return Result.failure(Error.InvalidArgumentNumber)
        }

        return Result.success(Unit)
    }

    /**
     * Computes the offsets of the syscall argument data passed to the BPF program.
     *
     * Returns the offsets of the most significant and least significant halves of the argument
     * specified by [argIndex] relative to the `struct seccomp_data` passed to the BPF program by
     * the kernel.
     */
    internal fun getDataOffsets(): Pair<UInt, UInt> {
        // Offset to the argument specified by `argIndex`.
        // Cannot overflow because the value will be at most 16 + 5 * 8 = 56.
        val argOffset = SECCOMP_DATA_ARGS_OFFSET + argIndex * SECCOMP_DATA_ARG_SIZE

        // Extracts offsets of most significant and least significant halves of argument.
        // Addition cannot overflow because it's at most `argOffset` + 4 = 68.
        return Pair(argOffset + SECCOMP_DATA_ARG_SIZE / 2u, argOffset)
    }

    /**
     * Splits the [value] field into 32 bit chunks.
     *
     * Returns the most significant and least significant halves of [value].
     */
    internal fun splitValue(): Pair<UInt, UInt> =
        Pair((value shr 32).toUInt(), value.toUInt())

    /**
     * Translates the `eq` (equal) condition into BPF statements.
     *
     * @param offset The given jump offset to the start of the next rule.
     */
    private fun intoEqBpf(offset: UInt): MutableList<SockFilter> {
        val (msb, lsb) = splitValue()
        val (msbOffset, lsbOffset) = getDataOffsets()

        val bpf: MutableList<SockFilter> = when (argLen) {
            SeccompCmpArgLen.DWORD -> mutableListOf()
            SeccompCmpArgLen.QWORD -> mutableListOf(
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, msbOffset),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, msb, 0u, offset + 2u),
            )
        }

        bpf.addAll(
            listOf(
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, lsbOffset),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, lsb, 0u, offset),
            ),
        )
        return bpf
    }

    /**
     * Translates the `ne` (not equal) condition into BPF statements.
     *
     * @param offset The given jump offset to the start of the next rule.
     */
    private fun intoNeBpf(offset: UInt): MutableList<SockFilter> {
        val (msb, lsb) = splitValue()
        val (msbOffset, lsbOffset) = getDataOffsets()

        val bpf: MutableList<SockFilter> = when (argLen) {
            SeccompCmpArgLen.DWORD -> mutableListOf()
            SeccompCmpArgLen.QWORD -> mutableListOf(
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, msbOffset),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, msb, 0u, 2u),
            )
        }

        bpf.addAll(
            listOf(
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, lsbOffset),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, lsb, offset, 0u),
            ),
        )
        return bpf
    }

    /**
     * Translates the `ge` (greater than or equal) condition into BPF statements.
     *
     * @param offset The given jump offset to the start of the next rule.
     */
    private fun intoGeBpf(offset: UInt): MutableList<SockFilter> {
        val (msb, lsb) = splitValue()
        val (msbOffset, lsbOffset) = getDataOffsets()

        val bpf: MutableList<SockFilter> = when (argLen) {
            SeccompCmpArgLen.DWORD -> mutableListOf()
            SeccompCmpArgLen.QWORD -> mutableListOf(
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, msbOffset),
                bpfJump(BPF_JMP or BPF_JGT or BPF_K, msb, 3u, 0u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, msb, 0u, offset + 2u),
            )
        }

        bpf.addAll(
            listOf(
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, lsbOffset),
                bpfJump(BPF_JMP or BPF_JGE or BPF_K, lsb, 0u, offset),
            ),
        )
        return bpf
    }

    /**
     * Translates the `gt` (greater than) condition into BPF statements.
     *
     * @param offset The given jump offset to the start of the next rule.
     */
    private fun intoGtBpf(offset: UInt): MutableList<SockFilter> {
        val (msb, lsb) = splitValue()
        val (msbOffset, lsbOffset) = getDataOffsets()

        val bpf: MutableList<SockFilter> = when (argLen) {
            SeccompCmpArgLen.DWORD -> mutableListOf()
            SeccompCmpArgLen.QWORD -> mutableListOf(
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, msbOffset),
                bpfJump(BPF_JMP or BPF_JGT or BPF_K, msb, 3u, 0u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, msb, 0u, offset + 2u),
            )
        }

        bpf.addAll(
            listOf(
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, lsbOffset),
                bpfJump(BPF_JMP or BPF_JGT or BPF_K, lsb, 0u, offset),
            ),
        )
        return bpf
    }

    /**
     * Translates the `le` (less than or equal) condition into BPF statements.
     *
     * @param offset The given jump offset to the start of the next rule.
     */
    private fun intoLeBpf(offset: UInt): MutableList<SockFilter> {
        val (msb, lsb) = splitValue()
        val (msbOffset, lsbOffset) = getDataOffsets()

        val bpf: MutableList<SockFilter> = when (argLen) {
            SeccompCmpArgLen.DWORD -> mutableListOf()
            SeccompCmpArgLen.QWORD -> mutableListOf(
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, msbOffset),
                bpfJump(BPF_JMP or BPF_JGT or BPF_K, msb, offset + 3u, 0u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, msb, 0u, 2u),
            )
        }

        bpf.addAll(
            listOf(
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, lsbOffset),
                bpfJump(BPF_JMP or BPF_JGT or BPF_K, lsb, offset, 0u),
            ),
        )
        return bpf
    }

    /**
     * Translates the `lt` (less than) condition into BPF statements.
     *
     * @param offset The given jump offset to the start of the next rule.
     */
    private fun intoLtBpf(offset: UInt): MutableList<SockFilter> {
        val (msb, lsb) = splitValue()
        val (msbOffset, lsbOffset) = getDataOffsets()

        val bpf: MutableList<SockFilter> = when (argLen) {
            SeccompCmpArgLen.DWORD -> mutableListOf()
            SeccompCmpArgLen.QWORD -> mutableListOf(
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, msbOffset),
                bpfJump(BPF_JMP or BPF_JGT or BPF_K, msb, offset + 3u, 0u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, msb, 0u, 2u),
            )
        }

        bpf.addAll(
            listOf(
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, lsbOffset),
                bpfJump(BPF_JMP or BPF_JGE or BPF_K, lsb, offset, 0u),
            ),
        )
        return bpf
    }

    /**
     * Translates the `maskedEq` (masked equal) condition into BPF statements.
     *
     * The `maskedEq` condition is `true` if the result of logical `AND` between the given value
     * and the mask is the value being compared against.
     *
     * @param offset The given jump offset to the start of the next rule.
     */
    private fun intoMaskedEqBpf(offset: UInt, mask: ULong): MutableList<SockFilter> {
        // Mask the current value.
        val maskedValue = value and mask

        val (msbOffset, lsbOffset) = getDataOffsets()
        val msb = (maskedValue shr 32).toUInt()
        val lsb = maskedValue.toUInt()
        val maskMsb = (mask shr 32).toUInt()
        val maskLsb = mask.toUInt()

        val bpf: MutableList<SockFilter> = when (argLen) {
            SeccompCmpArgLen.DWORD -> mutableListOf()
            SeccompCmpArgLen.QWORD -> mutableListOf(
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, msbOffset),
                bpfStmt(BPF_ALU or BPF_AND or BPF_K, maskMsb),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, msb, 0u, offset + 3u),
            )
        }

        bpf.addAll(
            listOf(
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, lsbOffset),
                bpfStmt(BPF_ALU or BPF_AND or BPF_K, maskLsb),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, lsb, 0u, offset),
            ),
        )
        return bpf
    }

    /**
     * Translates the [SeccompCondition] into BPF statements.
     *
     * @param offset The given jump offset to the start of the next rule.
     *
     * The jump is performed if the condition fails and thus the current rule does not match so
     * `seccomp` tries to match the next rule by jumping out of the current rule.
     *
     * In case the condition is part of the last rule, the jump offset is to the default action of
     * the respective filter.
     *
     * The most significant and least significant halves of the argument value are compared
     * separately since the BPF operand and accumulator are 4 bytes whereas an argument value is 8.
     */
    internal fun intoBpf(offset: UInt): MutableList<SockFilter> {
        val result = when (val op = operator) {
            is SeccompCmpOp.Eq -> intoEqBpf(offset)
            is SeccompCmpOp.Ge -> intoGeBpf(offset)
            is SeccompCmpOp.Gt -> intoGtBpf(offset)
            is SeccompCmpOp.Le -> intoLeBpf(offset)
            is SeccompCmpOp.Lt -> intoLtBpf(offset)
            is SeccompCmpOp.MaskedEq -> intoMaskedEqBpf(offset, op.mask)
            is SeccompCmpOp.Ne -> intoNeBpf(offset)
        }

        // Verifies that the `CONDITION_MAX_LEN` constant was properly updated.
        check(result.size.toUInt() <= CONDITION_MAX_LEN)

        return result
    }
}
