// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler

import io.github.kotlinmania.seccompiler.backend.Error as BackendError
import io.github.kotlinmania.seccompiler.frontend.Error as JsonFrontendError

public typealias Result<T> = kotlin.Result<T>

/** Library errors. */
public sealed class Error(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause) {
    override fun toString(): String = message.orEmpty()

    /** Error originating in the backend compiler. */
    public data class Backend(
        val error: BackendError,
    ) : Error("Backend error: $error", error) {
        override fun toString(): String = message.orEmpty()
    }

    /** Attempting to install an empty filter. */
    public object EmptyFilter : Error("Cannot install empty filter.")

    /** System error related to calling `prctl`. */
    public data class Prctl(
        val errorNumber: Int,
    ) : Error("Error calling `prctl`: $errorNumber") {
        override fun toString(): String = message.orEmpty()
    }

    /** System error related to calling `seccomp` syscall. */
    public data class Seccomp(
        val errorNumber: Int,
    ) : Error("Error calling `seccomp`: $errorNumber") {
        override fun toString(): String = message.orEmpty()
    }

    /**
     * Returned when calling `seccomp` with the thread sync flag (TSYNC) fails. Contains the pid
     * of the thread that caused the failure.
     */
    public data class ThreadSync(
        val pid: Long,
    ) : Error("Seccomp filter synchronization failed in thread `$pid`") {
        override fun toString(): String = message.orEmpty()
    }

    /** Json Frontend Error. */
    public data class JsonFrontend(
        val error: JsonFrontendError,
    ) : Error("Json Frontend error: $error", error) {
        override fun toString(): String = message.orEmpty()
    }
}
