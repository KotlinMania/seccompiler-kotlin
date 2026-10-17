// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler.syscalltable

import io.github.kotlinmania.seccompiler.backend.TargetArch

/** Creates and owns a mapping from the arch-specific syscall name to the right number. */
internal class SyscallTable(
    arch: TargetArch,
) {
    private val map: Map<String, Long> =
        when (arch) {
            TargetArch.AARCH64 -> Aarch64.makeSyscallTable()
            TargetArch.X86_64 -> X8664.makeSyscallTable()
            TargetArch.RISCV64 -> Riscv64.makeSyscallTable()
        }

    /** Returns the arch-specific syscall number based on the given name. */
    fun getSyscallNr(sysName: String): Long? = map[sysName]
}
