// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler

import io.github.kotlinmania.seccompiler.backend.SockFilter

/** BPF structure definition for filter array. */
public data class SockFprog(
    public val len: UShort,
    public val filter: List<SockFilter>,
)
