// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler.backend

/** Backend Result type. */
public typealias Result<T> = kotlin.Result<T>

/** Backend-related errors. */
public sealed class Error(
    message: String,
) : RuntimeException(message) {
    override fun toString(): String = message.orEmpty()

    /** Attempting to associate an empty list of conditions to a rule. */
    public object EmptyRule : Error("The condition vector of a rule cannot be empty.")

    /** Filter exceeds the maximum number of instructions that a BPF program can have. */
    public data class FilterTooLarge(
        val len: Int,
    ) : Error(
            "The seccomp filter contains too many BPF instructions: $len. Max length is $BPF_MAX_LEN.",
        ) {
        override fun toString(): String = message.orEmpty()
    }

    /** Filter and default actions are equal. */
    public object IdenticalActions : Error("`matchAction` and `mismatchAction` are equal.")

    /** Argument index of a [SeccompCondition] exceeds the maximum linux syscall index. */
    public object InvalidArgumentNumber : Error(
        "The seccomp rule contains an invalid argument index. Maximum index value: $ARG_NUMBER_MAX",
    )

    /** Invalid [TargetArch]. */
    public data class InvalidTargetArch(
        val arch: String,
    ) : Error("Invalid target arch: $arch.") {
        override fun toString(): String = message.orEmpty()
    }
}
