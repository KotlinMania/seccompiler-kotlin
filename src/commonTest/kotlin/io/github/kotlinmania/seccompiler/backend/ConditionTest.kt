// port-lint: source src/backend/condition.rs
// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler.backend

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

internal class ConditionTest {
    @Test
    fun testNewCondition() {
        assertTrue(
            SeccompCondition.new(0u, SeccompCmpArgLen.DWORD, SeccompCmpOp.Eq, 60uL).isSuccess,
        )
        assertEquals(
            Error.InvalidArgumentNumber,
            SeccompCondition.new(7u, SeccompCmpArgLen.DWORD, SeccompCmpOp.Eq, 60uL)
                .exceptionOrNull(),
        )
    }

    @Test
    fun testGetDataOffsets() {
        val cond = SeccompCondition.new(1u, SeccompCmpArgLen.QWORD, SeccompCmpOp.Eq, 60uL)
            .getOrThrow()
        val (msbOffset, lsbOffset) = cond.getDataOffsets()
        assertEquals(
            Pair(
                SECCOMP_DATA_ARGS_OFFSET + SECCOMP_DATA_ARG_SIZE + 4u,
                SECCOMP_DATA_ARGS_OFFSET + SECCOMP_DATA_ARG_SIZE,
            ),
            Pair(msbOffset, lsbOffset),
        )

        // Upstream additionally constructs a `libc::seccomp_data` and indexes into it via raw
        // pointer arithmetic to confirm the offset values land in the right `u32` slots of the
        // packed layout. KMP has no libc, so the equivalent check synthesises the same packed
        // layout into a 64-byte buffer and reads the two u32 words back at the computed offsets.
        val data = ByteArray(64)
        // args[1] = u32::MAX as u64 + 1 = 0x1_0000_0000 (little-endian).
        // Bytes 24..32 cover args[1]: 00 00 00 00 01 00 00 00.
        data[28] = 1
        // The other args plus header are left at 0 for this assertion (lsb/msb are the only
        // u32 chunks being read), and args[1] is the only argument the test inspects.
        assertEquals(0u, readU32Le(data, lsbOffset.toInt()))
        assertEquals(1u, readU32Le(data, msbOffset.toInt()))
    }

    @Test
    fun testSplitValue() {
        val cond = SeccompCondition.new(
            1u,
            SeccompCmpArgLen.QWORD,
            SeccompCmpOp.Eq,
            UInt.MAX_VALUE.toULong() + 1uL,
        ).getOrThrow()
        assertEquals(Pair(1u, 0u), cond.splitValue())
    }

    private fun readU32Le(bytes: ByteArray, offset: Int): UInt =
        (bytes[offset].toUByte().toUInt()) or
            (bytes[offset + 1].toUByte().toUInt() shl 8) or
            (bytes[offset + 2].toUByte().toUInt() shl 16) or
            (bytes[offset + 3].toUByte().toUInt() shl 24)
}
