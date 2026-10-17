// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler

import io.github.kotlinmania.seccompiler.backend.BpfProgram
import io.github.kotlinmania.seccompiler.backend.TargetArch
import io.github.kotlinmania.seccompiler.frontend.JsonCompiler
import io.github.kotlinmania.seccompiler.backend.Error as BackendError
import io.github.kotlinmania.seccompiler.frontend.Error as JsonFrontendError

/**
 * Compile [BpfProgram]s from JSON.
 *
 * @param jsonStr String containing the JSON data conforming to the seccompiler JSON schema.
 * @param arch Target architecture of the filter.
 */
public fun compileFromJson(jsonStr: String, arch: TargetArch): Result<BpfMap> {
    val compiler = JsonCompiler(arch)
    val seccompFiltersResult = compiler.compile(jsonStr)
    if (seccompFiltersResult.isFailure) {
        val err = seccompFiltersResult.exceptionOrNull()
        return Result.failure(
            when (err) {
                is JsonFrontendError -> Error.JsonFrontend(err)
                is BackendError -> Error.Backend(err)
                else -> Error.JsonFrontend(JsonFrontendError.SerdeJson(err?.message ?: "Unknown error"))
            },
        )
    }

    val seccompFilters = seccompFiltersResult.getOrThrow()
    val bpfData = HashMap<String, BpfProgram>(seccompFilters.size)
    for ((name, seccompFilter) in seccompFilters) {
        val bpfResult = seccompFilter.toBpf()
        if (bpfResult.isFailure) {
            val err = bpfResult.exceptionOrNull() as BackendError
            return Result.failure(Error.Backend(err))
        }
        bpfData[name] = bpfResult.getOrThrow()
    }

    return Result.success(bpfData)
}

/**
 * Compile [BpfProgram]s from JSON bytes.
 *
 * @param bytes Byte array containing the JSON data conforming to the seccompiler JSON schema.
 * @param arch Target architecture of the filter.
 */
public fun compileFromJson(bytes: ByteArray, arch: TargetArch): Result<BpfMap> =
    compileFromJson(bytes.decodeToString(), arch)
