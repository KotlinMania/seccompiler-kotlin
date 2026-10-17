// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler

import io.github.kotlinmania.seccompiler.backend.TargetArch
import kotlin.test.Test
import kotlin.test.assertEquals
import io.github.kotlinmania.seccompiler.backend.Error as BackendError
import io.github.kotlinmania.seccompiler.frontend.Error as JsonFrontendError

internal class ErrorTest {
    @Test
    fun testRootErrors() {
        assertEquals("Backend error: The condition vector of a rule cannot be empty.", Error.Backend(BackendError.EmptyRule).toString())
        assertEquals("Cannot install empty filter.", Error.EmptyFilter.toString())
        assertEquals("Error calling `prctl`: 1", Error.Prctl(1).toString())
        assertEquals("Error calling `seccomp`: 2", Error.Seccomp(2).toString())
        assertEquals("Seccomp filter synchronization failed in thread `42`", Error.ThreadSync(42L).toString())
        assertEquals(
            "Json Frontend error: Invalid syscall name: fake for given arch: X86_64.",
            Error.JsonFrontend(JsonFrontendError.SyscallName("fake", TargetArch.X86_64)).toString(),
        )
    }
}
