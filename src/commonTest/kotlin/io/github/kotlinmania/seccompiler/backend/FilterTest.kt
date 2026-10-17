// port-lint: tests backend/filter.rs
// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler.backend

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

internal class FilterTest {
    private fun createTestBpfFilter(argLen: SeccompCmpArgLen): SeccompFilter =
        SeccompFilter
            .new(
                mapOf(
                    1L to
                        listOf(
                            SeccompRule
                                .new(
                                    listOf(
                                        SeccompCondition.new(2u, argLen, SeccompCmpOp.Le, 14uL).getOrThrow(),
                                        SeccompCondition.new(2u, argLen, SeccompCmpOp.Ne, 10uL).getOrThrow(),
                                    ),
                                ).getOrThrow(),
                            SeccompRule
                                .new(
                                    listOf(
                                        SeccompCondition.new(2u, argLen, SeccompCmpOp.Gt, 20uL).getOrThrow(),
                                        SeccompCondition.new(2u, argLen, SeccompCmpOp.Lt, 30uL).getOrThrow(),
                                    ),
                                ).getOrThrow(),
                            SeccompRule
                                .new(
                                    listOf(
                                        SeccompCondition.new(2u, argLen, SeccompCmpOp.Ge, 42uL).getOrThrow(),
                                    ),
                                ).getOrThrow(),
                        ),
                    9L to
                        listOf(
                            SeccompRule
                                .new(
                                    listOf(
                                        SeccompCondition.new(1u, argLen, SeccompCmpOp.MaskedEq(0b100uL), 36uL).getOrThrow(),
                                    ),
                                ).getOrThrow(),
                        ),
                    10L to emptyList(),
                ),
                SeccompAction.Trap,
                SeccompAction.Allow,
                TargetArch.X86_64,
            ).getOrThrow()

    @Test
    fun testSeccompFilterValidate() {
        val result =
            SeccompFilter.new(
                emptyMap(),
                SeccompAction.Allow,
                SeccompAction.Allow,
                TargetArch.X86_64,
            )
        assertTrue(result.isFailure)
        assertEquals(Error.IdenticalActions, result.exceptionOrNull())
    }

    @Test
    fun testSeccompFilterTooLarge() {
        val rulesList = ArrayList<SeccompRule>(1000)
        repeat(999) {
            rulesList.add(
                SeccompRule
                    .new(
                        listOf(
                            SeccompCondition.new(2u, SeccompCmpArgLen.DWORD, SeccompCmpOp.Le, 14uL).getOrThrow(),
                        ),
                    ).getOrThrow(),
            )
        }

        val filter =
            SeccompFilter
                .new(
                    mapOf(1L to rulesList),
                    SeccompAction.Allow,
                    SeccompAction.Trap,
                    TargetArch.X86_64,
                ).getOrThrow()

        val result = filter.toBpf()
        assertTrue(result.isFailure)
        assertEquals(Error.FilterTooLarge(5002), result.exceptionOrNull())
    }

    @Test
    fun testEmptyFilterOutput() {
        val expectedProgram = ArrayList<SockFilter>()
        expectedProgram.addAll(buildArchValidationSequence(TargetArch.X86_64))
        expectedProgram.add(bpfStmt(BPF_RET, 0x7fff0000u))

        val filter =
            SeccompFilter
                .new(
                    emptyMap(),
                    SeccompAction.Allow,
                    SeccompAction.Trap,
                    TargetArch.X86_64,
                ).getOrThrow()

        val prog = filter.toBpf().getOrThrow()
        assertEquals(expectedProgram, prog)
    }

    @Test
    fun testFilterBpfOutputDword() {
        val filter = createTestBpfFilter(SeccompCmpArgLen.DWORD)

        val instructions = ArrayList<SockFilter>()
        instructions.addAll(buildArchValidationSequence(TargetArch.X86_64))
        instructions.addAll(
            listOf(
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 0u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 1u, 0u, 1u),
                bpfStmt(BPF_JMP or BPF_JA, 1u),
                bpfStmt(BPF_JMP or BPF_JA, 6u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 32u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 10u, 3u, 0u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 32u),
                bpfJump(BPF_JMP or BPF_JGT or BPF_K, 14u, 1u, 0u),
                bpfStmt(BPF_RET, 0x7fff0000u),
                bpfStmt(BPF_JMP or BPF_JA, 1u),
                bpfStmt(BPF_JMP or BPF_JA, 6u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 32u),
                bpfJump(BPF_JMP or BPF_JGE or BPF_K, 30u, 3u, 0u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 32u),
                bpfJump(BPF_JMP or BPF_JGT or BPF_K, 20u, 0u, 1u),
                bpfStmt(BPF_RET, 0x7fff0000u),
                bpfStmt(BPF_JMP or BPF_JA, 1u),
                bpfStmt(BPF_JMP or BPF_JA, 4u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 32u),
                bpfJump(BPF_JMP or BPF_JGE or BPF_K, 42u, 0u, 1u),
                bpfStmt(BPF_RET, 0x7fff0000u),
                bpfStmt(BPF_RET, 0x00030000u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 9u, 0u, 1u),
                bpfStmt(BPF_JMP or BPF_JA, 1u),
                bpfStmt(BPF_JMP or BPF_JA, 5u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 24u),
                bpfStmt(BPF_ALU or BPF_AND or BPF_K, 0b100u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 36u and 0b100u, 0u, 1u),
                bpfStmt(BPF_RET, 0x7fff0000u),
                bpfStmt(BPF_RET, 0x00030000u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 10u, 0u, 1u),
                bpfStmt(BPF_JMP or BPF_JA, 1u),
                bpfStmt(BPF_JMP or BPF_JA, 2u),
                bpfStmt(BPF_RET or BPF_K, 0x7fff0000u),
                bpfStmt(BPF_RET, 0x00030000u),
                bpfStmt(BPF_RET, 0x00030000u),
            ),
        )

        val bpfprog = filter.toBpf().getOrThrow()
        assertEquals(instructions, bpfprog)
    }

    @Test
    fun testFilterBpfOutputQword() {
        val filter = createTestBpfFilter(SeccompCmpArgLen.QWORD)

        val instructions = ArrayList<SockFilter>()
        instructions.addAll(buildArchValidationSequence(TargetArch.X86_64))
        instructions.addAll(
            listOf(
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 0u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 1u, 0u, 1u),
                bpfStmt(BPF_JMP or BPF_JA, 1u),
                bpfStmt(BPF_JMP or BPF_JA, 11u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 36u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 0u, 0u, 2u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 32u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 10u, 6u, 0u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 36u),
                bpfJump(BPF_JMP or BPF_JGT or BPF_K, 0u, 4u, 0u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 0u, 0u, 2u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 32u),
                bpfJump(BPF_JMP or BPF_JGT or BPF_K, 14u, 1u, 0u),
                bpfStmt(BPF_RET, 0x7fff0000u),
                bpfStmt(BPF_JMP or BPF_JA, 1u),
                bpfStmt(BPF_JMP or BPF_JA, 12u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 36u),
                bpfJump(BPF_JMP or BPF_JGT or BPF_K, 0u, 9u, 0u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 0u, 0u, 2u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 32u),
                bpfJump(BPF_JMP or BPF_JGE or BPF_K, 30u, 6u, 0u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 36u),
                bpfJump(BPF_JMP or BPF_JGT or BPF_K, 0u, 3u, 0u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 0u, 0u, 3u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 32u),
                bpfJump(BPF_JMP or BPF_JGT or BPF_K, 20u, 0u, 1u),
                bpfStmt(BPF_RET, 0x7fff0000u),
                bpfStmt(BPF_JMP or BPF_JA, 1u),
                bpfStmt(BPF_JMP or BPF_JA, 7u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 36u),
                bpfJump(BPF_JMP or BPF_JGT or BPF_K, 0u, 3u, 0u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 0u, 0u, 3u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 32u),
                bpfJump(BPF_JMP or BPF_JGE or BPF_K, 42u, 0u, 1u),
                bpfStmt(BPF_RET, 0x7fff0000u),
                bpfStmt(BPF_RET, 0x00030000u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 9u, 0u, 1u),
                bpfStmt(BPF_JMP or BPF_JA, 1u),
                bpfStmt(BPF_JMP or BPF_JA, 8u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 28u),
                bpfStmt(BPF_ALU or BPF_AND or BPF_K, 0u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 0u, 0u, 4u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 24u),
                bpfStmt(BPF_ALU or BPF_AND or BPF_K, 0b100u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 36u and 0b100u, 0u, 1u),
                bpfStmt(BPF_RET, 0x7fff0000u),
                bpfStmt(BPF_RET, 0x00030000u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 10u, 0u, 1u),
                bpfStmt(BPF_JMP or BPF_JA, 1u),
                bpfStmt(BPF_JMP or BPF_JA, 2u),
                bpfStmt(BPF_RET or BPF_K, 0x7fff0000u),
                bpfStmt(BPF_RET, 0x00030000u),
                bpfStmt(BPF_RET, 0x00030000u),
            ),
        )

        val bpfprog = filter.toBpf().getOrThrow()
        assertEquals(instructions, bpfprog)
    }
}
