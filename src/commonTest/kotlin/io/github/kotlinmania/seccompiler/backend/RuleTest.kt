// port-lint: tests backend/rule.rs
// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler.backend

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

internal class RuleTest {
    @Test
    fun testValidateRule() {
        val result = SeccompRule.new(emptyList())
        assertTrue(result.isFailure)
        assertEquals(Error.EmptyRule, result.exceptionOrNull())
    }

    // Checks that rule gets translated correctly into BPF statements.
    @Test
    fun testRuleBpfOutput() {
        val rule =
            SeccompRule
                .new(
                    listOf(
                        SeccompCondition.new(0u, SeccompCmpArgLen.DWORD, SeccompCmpOp.Eq, 1uL).getOrThrow(),
                        SeccompCondition.new(2u, SeccompCmpArgLen.QWORD, SeccompCmpOp.MaskedEq(0b1010uL), 14uL).getOrThrow(),
                    ),
                ).getOrThrow()

        val msbOffset: UInt = 4u
        val lsbOffset: UInt = 0u

        // Builds hardcoded BPF instructions.
        val instructions =
            listOf(
                bpfStmt(BPF_JMP or BPF_JA, 1u), // Start evaluating the rule.
                bpfStmt(BPF_JMP or BPF_JA, 10u), // Jump to the next rule.
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 32u + msbOffset),
                bpfStmt(BPF_ALU or BPF_AND or BPF_K, 0u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 0u, 0u, 6u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 32u + lsbOffset),
                bpfStmt(BPF_ALU or BPF_AND or BPF_K, 0b1010u),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 14u and 0b1010u, 0u, 3u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 16u + lsbOffset),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 1u, 0u, 1u),
            )

        val bpfprog: BpfProgram = rule.toBpf()
        assertEquals(instructions, bpfprog)
    }

    // Checks that rule with too many conditions gets translated correctly into BPF statements
    // using three helper jumps.
    @Test
    fun testRuleManyConditionsBpfOutput() {
        // Builds rule.
        val conditions = ArrayList<SeccompCondition>(43)
        repeat(42) {
            conditions.add(SeccompCondition.new(0u, SeccompCmpArgLen.QWORD, SeccompCmpOp.MaskedEq(0uL), 0uL).getOrThrow())
        }
        conditions.add(SeccompCondition.new(0u, SeccompCmpArgLen.QWORD, SeccompCmpOp.Eq, 0uL).getOrThrow())
        val rule = SeccompRule.new(conditions).getOrThrow()

        val msbOffset: UInt = 4u
        val lsbOffset: UInt = 0u

        // Builds hardcoded BPF instructions.
        val instructions =
            mutableListOf(
                bpfStmt(BPF_JMP or BPF_JA, 1u), // Start evaluating the rule.
                bpfStmt(BPF_JMP or BPF_JA, 6u), // Jump to the next rule. Actually to a helper jump.
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 16u + msbOffset),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 0u, 0u, 3u),
                bpfStmt(BPF_LD or BPF_W or BPF_ABS, 16u + lsbOffset),
                bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 0u, 0u, 1u),
                bpfStmt(BPF_JMP or BPF_JA, 2u),
                bpfStmt(BPF_JMP or BPF_JA, 254u),
                bpfStmt(BPF_JMP or BPF_JA, 254u),
            )
        var offset: UInt = 253u
        repeat(42) {
            offset -= 6u
            // Add the rest of the MaskedEq conditions.
            instructions.addAll(
                listOf(
                    bpfStmt(BPF_LD or BPF_W or BPF_ABS, 16u + msbOffset),
                    bpfStmt(BPF_ALU or BPF_AND or BPF_K, 0u),
                    bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 0u, 0u, offset + 3u),
                    bpfStmt(BPF_LD or BPF_W or BPF_ABS, 16u + lsbOffset),
                    bpfStmt(BPF_ALU or BPF_AND or BPF_K, 0u),
                    bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 0u, 0u, offset),
                ),
            )
        }

        val bpfprog: BpfProgram = rule.toBpf()
        assertEquals(instructions, bpfprog)
    }
}
