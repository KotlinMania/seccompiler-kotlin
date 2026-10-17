// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler.backend

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
    public data class MaskedEq(
        val mask: ULong,
    ) : SeccompCmpOp()

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
