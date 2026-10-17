// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler.syscalltable

import io.github.kotlinmania.seccompiler.backend.TargetArch
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

internal class SyscallTableTest {
    @Test
    fun testGetSyscallNr() {
        val instanceX8664 = SyscallTable(TargetArch.X86_64)
        val instanceAarch64 = SyscallTable(TargetArch.AARCH64)
        val instanceRiscv64 = SyscallTable(TargetArch.RISCV64)

        assertEquals(3L, instanceX8664.getSyscallNr("close"))
        assertEquals(57L, instanceAarch64.getSyscallNr("close"))
        assertEquals(57L, instanceRiscv64.getSyscallNr("close"))

        assertNull(instanceX8664.getSyscallNr("nosyscall"))
        assertNull(instanceAarch64.getSyscallNr("nosyscall"))
        assertNull(instanceRiscv64.getSyscallNr("nosyscall"))
    }
}
