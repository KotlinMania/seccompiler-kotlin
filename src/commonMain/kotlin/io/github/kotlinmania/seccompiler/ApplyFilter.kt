// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler

import io.github.kotlinmania.libc.unix.linuxlike.android.PR_SET_NO_NEW_PRIVS
import io.github.kotlinmania.libc.unix.linuxlike.android.prctl
import io.github.kotlinmania.seccompiler.backend.BpfProgramRef

/**
 * Apply a BPF filter to the calling thread.
 *
 * @param bpfFilter A reference to the [BpfProgramRef] to be installed.
 */
public fun applyFilter(bpfFilter: BpfProgramRef): Result<Unit> =
    applyFilterWithFlags(bpfFilter, 0uL)

/**
 * Apply a BPF filter to all threads in the process via the TSYNC feature.
 *
 * @param bpfFilter A reference to the [BpfProgramRef] to be installed.
 */
public fun applyFilterAllThreads(bpfFilter: BpfProgramRef): Result<Unit> =
    applyFilterWithFlags(bpfFilter, SECCOMP_FILTER_FLAG_TSYNC)

public const val SECCOMP_FILTER_FLAG_TSYNC: ULong = 1uL

/**
 * Apply a BPF filter with flags.
 *
 * @param bpfFilter A reference to the [BpfProgramRef] to be installed.
 * @param flags A bitset of seccomp flags.
 */
public fun applyFilterWithFlags(bpfFilter: BpfProgramRef, flags: ULong): Result<Unit> {
    if (bpfFilter.isEmpty()) {
        return Result.failure(Error.EmptyFilter)
    }

    val rc =
        try {
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        } catch (e: Exception) {
            return Result.failure(Error.Prctl(-1))
        }

    if (rc != 0) {
        return Result.failure(Error.Prctl(rc))
    }

    return Result.success(Unit)
}
