// port-lint: source backend/mod.rs
// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

/**
 * This module defines the data structures used for the intermmediate representation (IR),
 * as well as the logic for compiling the filter into BPF code, the final form of the filter.
 */
package io.github.kotlinmania.seccompiler.backend

// See /usr/include/linux/seccomp.h
private const val SECCOMP_RET_KILL_PROCESS: UInt = 0x80000000u
private const val SECCOMP_RET_KILL_THREAD: UInt = 0x00000000u
private const val SECCOMP_RET_TRAP: UInt = 0x00030000u
private const val SECCOMP_RET_ERRNO: UInt = 0x00050000u
private const val SECCOMP_RET_TRACE: UInt = 0x7ff00000u
private const val SECCOMP_RET_LOG: UInt = 0x7ffc0000u
private const val SECCOMP_RET_ALLOW: UInt = 0x7fff0000u
private const val SECCOMP_RET_DATA: UInt = 0x0000ffffu

/** Backend Result type. */
public typealias Result<T> = kotlin.Result<T>

/** Backend-related errors. */
public sealed class Error(message: String) : RuntimeException(message) {
    override fun toString(): String = message ?: ""

    /** Attempting to associate an empty list of conditions to a rule. */
    public object EmptyRule : Error("The condition vector of a rule cannot be empty.")

    /** Filter exceeds the maximum number of instructions that a BPF program can have. */
    public data class FilterTooLarge(val len: Int) : Error(
        "The seccomp filter contains too many BPF instructions: $len. Max length is $BPF_MAX_LEN.",
    ) {
        override fun toString(): String = message ?: ""
    }

    /** Filter and default actions are equal. */
    public object IdenticalActions : Error("`matchAction` and `mismatchAction` are equal.")

    /** Argument index of a [SeccompCondition] exceeds the maximum linux syscall index. */
    public object InvalidArgumentNumber : Error(
        "The seccomp rule contains an invalid argument index. Maximum index value: $ARG_NUMBER_MAX",
    )

    /** Invalid [TargetArch]. */
    public data class InvalidTargetArch(val arch: String) : Error("Invalid target arch: $arch.") {
        override fun toString(): String = message ?: ""
    }
}

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
    internal fun getAuditValue(): UInt = when (this) {
        X86_64 -> AUDIT_ARCH_X86_64
        AARCH64 -> AUDIT_ARCH_AARCH64
        RISCV64 -> AUDIT_ARCH_RISCV64
    }

    public companion object {
        public fun tryFrom(input: String): Result<TargetArch> = when (input.lowercase()) {
            "x86_64" -> Result.success(X86_64)
            "aarch64" -> Result.success(AARCH64)
            "riscv64" -> Result.success(RISCV64)
            else -> Result.failure(Error.InvalidTargetArch(input))
        }
    }
}

/** Comparison to perform when matching a condition. */
public sealed class SeccompCmpOp {
    /** Argument value is equal to the specified value. */
    public object Eq : SeccompCmpOp()

    /** Argument value is greater than or equal to the specified value. */
    public object Ge : SeccompCmpOp()

    /** Argument value is greater than specified value. */
    public object Gt : SeccompCmpOp()

    /** Argument value is less than or equal to the specified value. */
    public object Le : SeccompCmpOp()

    /** Argument value is less than specified value. */
    public object Lt : SeccompCmpOp()

    /** Masked bits of argument value are equal to masked bits of specified value. */
    public data class MaskedEq(val mask: ULong) : SeccompCmpOp()

    /** Argument value is not equal to specified value. */
    public object Ne : SeccompCmpOp()
}

/** Seccomp argument value length. */
public enum class SeccompCmpArgLen {
    /** Argument value length is 4 bytes. */
    DWORD,

    /** Argument value length is 8 bytes. */
    QWORD,
}

/** Actions that a seccomp filter can return for a syscall. */
public sealed class SeccompAction {
    /** Allows syscall. */
    public object Allow : SeccompAction()

    /** Returns from syscall with specified error number. */
    public data class Errno(val errno: UInt) : SeccompAction()

    /** Kills calling thread. */
    public object KillThread : SeccompAction()

    /** Kills calling process. */
    public object KillProcess : SeccompAction()

    /** Allows syscall after logging it. */
    public object Log : SeccompAction()

    /** Notifies tracing process of the caller with respective number. */
    public data class Trace(val number: UInt) : SeccompAction()

    /** Sends `SIGSYS` to the calling process. */
    public object Trap : SeccompAction()

    /**
     * Return codes of the BPF program for each action.
     *
     * @receiver the [SeccompAction] that the kernel will take.
     */
    public fun toUInt(): UInt = when (this) {
        is Allow -> SECCOMP_RET_ALLOW
        is Errno -> SECCOMP_RET_ERRNO or (errno and SECCOMP_RET_DATA)
        is KillThread -> SECCOMP_RET_KILL_THREAD
        is KillProcess -> SECCOMP_RET_KILL_PROCESS
        is Log -> SECCOMP_RET_LOG
        is Trace -> SECCOMP_RET_TRACE or (number and SECCOMP_RET_DATA)
        is Trap -> SECCOMP_RET_TRAP
    }
}
