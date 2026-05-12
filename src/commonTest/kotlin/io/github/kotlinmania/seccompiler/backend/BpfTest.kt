// port-lint: source src/backend/bpf.rs
// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler.backend

import kotlin.test.Test
import kotlin.test.assertEquals

internal class BpfTest {
    @Test
    fun testBpfFunctions() {
        // Compares the output of the BPF instruction generating functions to hardcoded
        // instructions.
        assertEquals(
            SockFilter(
                code = 0x20u,
                jt = 0u,
                jf = 0u,
                k = 16u,
            ),
            bpfStmt(BPF_LD or BPF_W or BPF_ABS, 16u),
        )
        assertEquals(
            SockFilter(
                code = 0x15u,
                jt = 2u,
                jf = 5u,
                k = 10u,
            ),
            bpfJump(BPF_JMP or BPF_JEQ or BPF_K, 10u, 2u, 5u),
        )
    }
}
