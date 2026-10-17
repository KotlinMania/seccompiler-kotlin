// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

internal class ApplyFilterTest {
    @Test
    fun testEmptyFilterError() {
        val res1 = applyFilter(emptyList())
        assertTrue(res1.isFailure)
        assertEquals(Error.EmptyFilter, res1.exceptionOrNull())

        val res2 = applyFilterAllThreads(emptyList())
        assertTrue(res2.isFailure)
        assertEquals(Error.EmptyFilter, res2.exceptionOrNull())
    }
}
