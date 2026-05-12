// port-lint: source src/backend/bpf.rs
// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

/** Define constants, helpers and types used for BPF codegen. */
package io.github.kotlinmania.seccompiler.backend

/** Program made up of a sequence of BPF instructions. */
public typealias BpfProgram = MutableList<SockFilter>

/** Reference to program made up of a sequence of BPF instructions. */
public typealias BpfProgramRef = List<SockFilter>

// The maximum number of a syscall argument.
// A syscall can have at most 6 arguments.
// Arguments are numbered from 0 to 5.
public const val ARG_NUMBER_MAX: UInt = 5u

// The maximum number of BPF statements that a condition will be translated into.
// This is not a linux requirement but is based on the current BPF compilation logic.
// This is used in the backend code for preallocating vectors and for detecting unjumpable offsets.
public const val CONDITION_MAX_LEN: UInt = 6u

// The maximum seccomp-BPF program length allowed by the linux kernel.
public const val BPF_MAX_LEN: Int = 4096

// `struct seccomp_data` offsets and sizes of fields in bytes:
//
// ```c
// struct seccomp_data {
//     int nr;
//     __u32 arch;
//     __u64 instruction_pointer;
//     __u64 args[6];
// };
// ```
public const val SECCOMP_DATA_NR_OFFSET: UInt = 0u
private const val SECCOMP_DATA_ARCH_OFFSET: UInt = 4u
public const val SECCOMP_DATA_ARGS_OFFSET: UInt = 16u
public const val SECCOMP_DATA_ARG_SIZE: UInt = 8u

/**
 * Builds a `jump` BPF instruction.
 *
 * @param code The operation code.
 * @param jt The jump offset in case the operation returns `true`.
 * @param jf The jump offset in case the operation returns `false`.
 * @param k The operand.
 */
internal fun bpfJump(code: UInt, k: UInt, jt: UInt, jf: UInt): SockFilter =
    SockFilter(code = code, jt = jt, jf = jf, k = k)

/**
 * Builds a "statement" BPF instruction.
 *
 * @param code The operation code.
 * @param k The operand.
 */
internal fun bpfStmt(code: UInt, k: UInt): SockFilter =
    SockFilter(code = code, jt = 0u, jf = 0u, k = k)

// Builds a sequence of BPF instructions that validate the underlying architecture.
internal fun buildArchValidationSequence(targetArch: TargetArch): MutableList<SockFilter> {
    val auditArchValue = targetArch.getAuditValue()
    return mutableListOf(
        bpfStmt(BPF_LD or BPF_W or BPF_ABS, SECCOMP_DATA_ARCH_OFFSET),
        bpfJump(BPF_JMP or BPF_JEQ or BPF_K, auditArchValue, 1u, 0u),
        bpfStmt(BPF_RET or BPF_K, SECCOMP_RET_KILL_PROCESS),
    )
}

// BPF Instruction classes.
// See /usr/include/linux/bpf_common.h .
// Load operation.
public const val BPF_LD: UInt = 0x00u

// ALU operation.
public const val BPF_ALU: UInt = 0x04u

// Jump operation.
public const val BPF_JMP: UInt = 0x05u

// Return operation.
public const val BPF_RET: UInt = 0x06u

// BPF ld/ldx fields.
// See /usr/include/linux/bpf_common.h .
// Operand size is a word.
public const val BPF_W: UInt = 0x00u

// Load from data area (where `seccomp_data` is).
public const val BPF_ABS: UInt = 0x20u

// BPF alu fields.
// See /usr/include/linux/bpf_common.h .
public const val BPF_AND: UInt = 0x50u

// BPF jmp fields.
// See /usr/include/linux/bpf_common.h .
// Unconditional jump.
public const val BPF_JA: UInt = 0x00u

// Jump with comparisons.
public const val BPF_JEQ: UInt = 0x10u
public const val BPF_JGT: UInt = 0x20u
public const val BPF_JGE: UInt = 0x30u

// Test against the value in the K register.
public const val BPF_K: UInt = 0x00u

// Architecture identifier for x86_64 LE.
// See /usr/include/linux/audit.h .
// Defined as:
// `#define AUDIT_ARCH_X86_64	(EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)`
// 62 | 0x80000000 | 0x40000000
public const val AUDIT_ARCH_X86_64: UInt = 0xC000003Eu

// Architecture identifier for aarch64 LE.
// Defined as:
// `#define AUDIT_ARCH_AARCH64	(EM_AARCH64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)`
// 183 | 0x80000000 | 0x40000000
public const val AUDIT_ARCH_AARCH64: UInt = 0xC00000B7u

// Architecture identifier for riscv64 LE.
// Defined as:
// `#define AUDIT_ARCH_RISCV64  (EM_RISCV|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)`
// 243 | 0x80000000 | 0x40000000
public const val AUDIT_ARCH_RISCV64: UInt = 0xC00000F3u

// See /usr/include/linux/seccomp.h .
private const val SECCOMP_RET_KILL_PROCESS: UInt = 0x80000000u

/**
 * BPF instruction structure definition.
 *
 * See /usr/include/linux/filter.h .
 */
public data class SockFilter(
    /** Code of the instruction. */
    public val code: UInt,
    /** Jump if true offset. */
    public val jt: UInt,
    /** Jump if false offset. */
    public val jf: UInt,
    /** Immediate value. */
    public val k: UInt,
)
