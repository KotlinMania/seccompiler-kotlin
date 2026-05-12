// port-lint: source src/backend/mod.rs
// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler.backend

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

internal class ModTest {
    @Test
    fun testTargetArch() {
        assertTrue(TargetArch.tryFrom("invalid").isFailure)
        assertTrue(TargetArch.tryFrom("x8664").isFailure)

        assertEquals(TargetArch.X86_64, TargetArch.tryFrom("x86_64").getOrThrow())
        assertEquals(TargetArch.X86_64, TargetArch.tryFrom("X86_64").getOrThrow())

        assertEquals(TargetArch.AARCH64, TargetArch.tryFrom("aarch64").getOrThrow())
        assertEquals(TargetArch.AARCH64, TargetArch.tryFrom("aARch64").getOrThrow())

        assertEquals(TargetArch.RISCV64, TargetArch.tryFrom("riscv64").getOrThrow())
        assertEquals(TargetArch.RISCV64, TargetArch.tryFrom("RiScV64").getOrThrow())
    }
}
