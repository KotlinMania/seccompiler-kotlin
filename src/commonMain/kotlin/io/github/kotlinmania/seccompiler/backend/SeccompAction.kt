// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler.backend

import io.github.kotlinmania.libc.unix.linuxlike.linux.SECCOMP_RET_ALLOW
import io.github.kotlinmania.libc.unix.linuxlike.linux.SECCOMP_RET_DATA
import io.github.kotlinmania.libc.unix.linuxlike.linux.SECCOMP_RET_ERRNO
import io.github.kotlinmania.libc.unix.linuxlike.linux.SECCOMP_RET_KILL_PROCESS
import io.github.kotlinmania.libc.unix.linuxlike.linux.SECCOMP_RET_KILL_THREAD
import io.github.kotlinmania.libc.unix.linuxlike.linux.SECCOMP_RET_LOG
import io.github.kotlinmania.libc.unix.linuxlike.linux.SECCOMP_RET_TRACE
import io.github.kotlinmania.libc.unix.linuxlike.linux.SECCOMP_RET_TRAP

/** Actions that a seccomp filter can return for a syscall. */
public sealed class SeccompAction {
    /** Allows syscall. */
    public object Allow : SeccompAction()

    /** Returns from syscall with specified error number. */
    public data class Errno(
        val errorNumber: UInt,
    ) : SeccompAction()

    /** Kills calling thread. */
    public object KillThread : SeccompAction()

    /** Kills calling process. */
    public object KillProcess : SeccompAction()

    /** Allows syscall after logging it. */
    public object Log : SeccompAction()

    /** Notifies tracing process of the caller with respective number. */
    public data class Trace(
        val number: UInt,
    ) : SeccompAction()

    /** Sends `SIGSYS` to the calling process. */
    public object Trap : SeccompAction()

    /**
     * Return codes of the BPF program for each action.
     *
     * @receiver the [SeccompAction] that the kernel will take.
     */
    public fun toUInt(): UInt =
        when (this) {
            is Allow -> SECCOMP_RET_ALLOW
            is Errno -> SECCOMP_RET_ERRNO or (errorNumber and SECCOMP_RET_DATA)
            is KillThread -> SECCOMP_RET_KILL_THREAD
            is KillProcess -> SECCOMP_RET_KILL_PROCESS
            is Log -> SECCOMP_RET_LOG
            is Trace -> SECCOMP_RET_TRACE or (number and SECCOMP_RET_DATA)
            is Trap -> SECCOMP_RET_TRAP
        }
}
