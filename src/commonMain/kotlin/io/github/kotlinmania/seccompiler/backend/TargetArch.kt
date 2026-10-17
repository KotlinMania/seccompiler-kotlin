// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler.backend

/** Supported target architectures. */
public enum class TargetArch {
    /** x86-64 architecture. */
    X86_64,

    /** AArch64 architecture. */
    AARCH64,

    /** RISC-V 64 architecture. */
    RISCV64,
    ;

    /** Get the arch audit value. Used for the runtime arch check embedded in the BPF filter. */
    internal fun getAuditValue(): UInt =
        when (this) {
            X86_64 -> AUDIT_ARCH_X86_64
            AARCH64 -> AUDIT_ARCH_AARCH64
            RISCV64 -> AUDIT_ARCH_RISCV64
        }

    public companion object {
        public fun tryFrom(input: String): Result<TargetArch> =
            when (input.lowercase()) {
                "x86_64" -> Result.success(X86_64)
                "aarch64" -> Result.success(AARCH64)
                "riscv64" -> Result.success(RISCV64)
                else -> Result.failure(Error.InvalidTargetArch(input))
            }
    }
}
