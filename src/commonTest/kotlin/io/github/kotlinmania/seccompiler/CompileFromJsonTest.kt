// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler

import io.github.kotlinmania.seccompiler.backend.TargetArch
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

internal class CompileFromJsonTest {
    @Test
    fun testCompileFromJson() {
        val jsonInput = """{
            "main_thread": {
                "mismatch_action": "allow",
                "match_action": "trap",
                "filter": []
            }
        }"""

        val filtersResult = compileFromJson(jsonInput, TargetArch.X86_64)
        assertTrue(filtersResult.isSuccess)
        val filters = filtersResult.getOrThrow()
        assertTrue(filters.containsKey("main_thread"))
        val filter = filters.getValue("main_thread")
        // Architecture validation (3) + default mismatch action (1) = 4
        assertEquals(4, filter.size)
    }

    @Test
    fun testCompileFromJsonInvalid() {
        val jsonInput = "{ invalid json }"
        val filtersResult = compileFromJson(jsonInput, TargetArch.X86_64)
        assertTrue(filtersResult.isFailure)
        assertTrue(filtersResult.exceptionOrNull() is Error.JsonFrontend)
    }
}
