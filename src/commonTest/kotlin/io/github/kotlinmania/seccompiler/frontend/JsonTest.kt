// port-lint: tests frontend/json.rs
// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

package io.github.kotlinmania.seccompiler.frontend

import io.github.kotlinmania.seccompiler.backend.SeccompAction
import io.github.kotlinmania.seccompiler.backend.SeccompCmpArgLen
import io.github.kotlinmania.seccompiler.backend.SeccompCmpOp
import io.github.kotlinmania.seccompiler.backend.SeccompCondition
import io.github.kotlinmania.seccompiler.backend.SeccompFilter
import io.github.kotlinmania.seccompiler.backend.SeccompRule
import io.github.kotlinmania.seccompiler.backend.TargetArch
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import io.github.kotlinmania.seccompiler.backend.Error as BackendError

internal class JsonTest {
    @Test
    fun testMakeSeccompFilter() {
        val compiler = JsonCompiler(TargetArch.X86_64)

        // Test with malformed filters: invalid syscall name
        val wrongSyscallNameFilter =
            JsonFilter(
                mismatchAction = SeccompAction.Trap,
                matchAction = SeccompAction.Allow,
                rules = listOf(JsonRule(syscall = "wrong_syscall")),
            )
        val wrongSyscallResult = compiler.makeSeccompFilter(wrongSyscallNameFilter)
        assertTrue(wrongSyscallResult.isFailure)
        assertTrue(wrongSyscallResult.exceptionOrNull() is Error.SyscallName)

        // Test that SeccompConditions validations are triggered and caught by compilation
        val wrongArgIndexFilter =
            JsonFilter(
                mismatchAction = SeccompAction.Allow,
                matchAction = SeccompAction.Trap,
                rules =
                    listOf(
                        JsonRule(
                            syscall = "futex",
                            conditions =
                                listOf(
                                    JsonCondition(8u, SeccompCmpArgLen.DWORD, SeccompCmpOp.Le, 65uL),
                                ),
                        ),
                    ),
            )
        val wrongArgResult = compiler.makeSeccompFilter(wrongArgIndexFilter)
        assertTrue(wrongArgResult.isFailure)
        val wrongArgErr = wrongArgResult.exceptionOrNull()
        assertTrue(wrongArgErr is Error.Backend && wrongArgErr.error == BackendError.InvalidArgumentNumber)

        // Test that SeccompRule validations are triggered: empty conditions rule
        val emptyRuleFilter =
            JsonFilter(
                mismatchAction = SeccompAction.Allow,
                matchAction = SeccompAction.Trap,
                rules = listOf(JsonRule(syscall = "read", conditions = emptyList())),
            )
        val emptyRuleResult = compiler.makeSeccompFilter(emptyRuleFilter)
        assertTrue(emptyRuleResult.isFailure)
        val emptyRuleErr = emptyRuleResult.exceptionOrNull()
        assertTrue(emptyRuleErr is Error.Backend && emptyRuleErr.error == BackendError.EmptyRule)

        // Test that SeccompFilter validations are triggered: identical actions
        val identicalActionsFilter =
            JsonFilter(
                mismatchAction = SeccompAction.Allow,
                matchAction = SeccompAction.Allow,
                rules = listOf(JsonRule(syscall = "read")),
            )
        val identicalActionsResult = compiler.makeSeccompFilter(identicalActionsFilter)
        assertTrue(identicalActionsResult.isFailure)
        val identicalActionsErr = identicalActionsResult.exceptionOrNull()
        assertTrue(identicalActionsErr is Error.Backend && identicalActionsErr.error == BackendError.IdenticalActions)

        // Test a well-formed filter
        val filter =
            JsonFilter(
                mismatchAction = SeccompAction.Trap,
                matchAction = SeccompAction.Allow,
                rules =
                    listOf(
                        JsonRule("read", null),
                        JsonRule(
                            "futex",
                            listOf(
                                JsonCondition(2u, SeccompCmpArgLen.DWORD, SeccompCmpOp.Le, 65uL),
                                JsonCondition(1u, SeccompCmpArgLen.QWORD, SeccompCmpOp.Ne, 80uL),
                            ),
                        ),
                        JsonRule(
                            "futex",
                            listOf(
                                JsonCondition(3u, SeccompCmpArgLen.QWORD, SeccompCmpOp.Gt, 65uL),
                                JsonCondition(1u, SeccompCmpArgLen.QWORD, SeccompCmpOp.Lt, 80uL),
                            ),
                        ),
                        JsonRule(
                            "futex",
                            listOf(
                                JsonCondition(3u, SeccompCmpArgLen.QWORD, SeccompCmpOp.Ge, 65uL),
                            ),
                        ),
                        JsonRule(
                            "ioctl",
                            listOf(
                                JsonCondition(3u, SeccompCmpArgLen.DWORD, SeccompCmpOp.MaskedEq(100uL), 65uL),
                            ),
                        ),
                    ),
            )

        val readNr = compiler.syscallTable.getSyscallNr("read")!!
        val futexNr = compiler.syscallTable.getSyscallNr("futex")!!
        val ioctlNr = compiler.syscallTable.getSyscallNr("ioctl")!!

        val expectedSeccompFilter =
            SeccompFilter
                .new(
                    mapOf(
                        readNr to emptyList(),
                        futexNr to
                            listOf(
                                SeccompRule
                                    .new(
                                        listOf(
                                            SeccompCondition.new(2u, SeccompCmpArgLen.DWORD, SeccompCmpOp.Le, 65uL).getOrThrow(),
                                            SeccompCondition.new(1u, SeccompCmpArgLen.QWORD, SeccompCmpOp.Ne, 80uL).getOrThrow(),
                                        ),
                                    ).getOrThrow(),
                                SeccompRule
                                    .new(
                                        listOf(
                                            SeccompCondition.new(3u, SeccompCmpArgLen.QWORD, SeccompCmpOp.Gt, 65uL).getOrThrow(),
                                            SeccompCondition.new(1u, SeccompCmpArgLen.QWORD, SeccompCmpOp.Lt, 80uL).getOrThrow(),
                                        ),
                                    ).getOrThrow(),
                                SeccompRule
                                    .new(
                                        listOf(
                                            SeccompCondition.new(3u, SeccompCmpArgLen.QWORD, SeccompCmpOp.Ge, 65uL).getOrThrow(),
                                        ),
                                    ).getOrThrow(),
                            ),
                        ioctlNr to
                            listOf(
                                SeccompRule
                                    .new(
                                        listOf(
                                            SeccompCondition.new(3u, SeccompCmpArgLen.DWORD, SeccompCmpOp.MaskedEq(100uL), 65uL).getOrThrow(),
                                        ),
                                    ).getOrThrow(),
                            ),
                    ),
                    SeccompAction.Trap,
                    SeccompAction.Allow,
                    TargetArch.X86_64,
                ).getOrThrow()

        val compiledFilter = compiler.makeSeccompFilter(filter).getOrThrow()
        assertEquals(expectedSeccompFilter, compiledFilter)
    }

    @Test
    fun testCompile() {
        val compiler = JsonCompiler(TargetArch.X86_64)

        // Malformed JSON cases
        assertTrue(compiler.compile("").isFailure)
        assertTrue(compiler.compile("hjkln").isFailure)
        assertTrue(compiler.compile("[]").isFailure)
        assertTrue(compiler.compile("{1}").isFailure)
        assertTrue(compiler.compile("""{"a": {}}""").isFailure)
        assertTrue(compiler.compile("""{"a": {"match_action": "allow", "mismatch_action":"log"}}""").isFailure)
        assertTrue(compiler.compile("""{"a": {"match_action": "allow", "mismatch_action":"log", "filters": []}}""").isFailure)
        assertTrue(compiler.compile("""{"a": {"match_action": "allow", "mismatch_action":"logs", "filter": []}}""").isFailure)
        assertTrue(
            compiler
                .compile(
                    """{"a": {"match_action": "allow", "mismatch_action":"log", "filter_action": "trap", "filter": []}}""",
                ).isFailure,
        )
        assertTrue(compiler.compile("""{"a": {"match_action": "allow", "mismatch_action":"errno", "filter": []}}""").isFailure)
        assertTrue(
            compiler
                .compile(
                    """{
                    "thread_2": {
                        "mismatch_action": "trap",
                        "match_action": "allow",
                        "filter": [
                            {
                                "syscall": "ioctl",
                                "args": [
                                    {
                                        "index": 3,
                                        "type": "qword",
                                        "op": "eq",
                                        "val": 18446744073709551616
                                    }
                                ]
                            }
                        ]
                    }
                }""",
                ).isFailure,
        )
        assertTrue(
            compiler
                .compile(
                    """{
                    "thread_2": {
                        "mismatch_action": "trap",
                        "match_action": "allow",
                        "filter": [
                            {
                                "syscall": "ioctl",
                                "args": [
                                    {
                                        "index": 3,
                                        "type": "qword",
                                        "op": "eq",
                                        "val": -1846
                                    }
                                ]
                            }
                        ]
                    }
                }""",
                ).isFailure,
        )
        assertTrue(
            compiler
                .compile(
                    """{
                    "thread_2": {
                        "mismatch_action": "trap",
                        "match_action": "allow",
                        "filter": [
                            {
                                "syscall": "ioctl",
                                "args": [
                                    {
                                        "index": 3,
                                        "type": "qword",
                                        "op": "eq",
                                        "val": 1846.4
                                    }
                                ]
                            }
                        ]
                    }
                }""",
                ).isFailure,
        )
        assertTrue(
            compiler
                .compile(
                    """{
                    "thread_2": {
                        "mismatch_action": "trap",
                        "match_action": "allow",
                        "filter": [
                            {
                                "syscall": "ioctl",
                                "args": [
                                    {
                                        "index": 3,
                                        "type": "qword",
                                        "op": "eq",
                                        "val": 14,
                                        "comment": 15
                                    }
                                ]
                            }
                        ]
                    }
                }""",
                ).isFailure,
        )
        assertTrue(
            compiler
                .compile(
                    """{
                    "thread_1": {
                        "mismatch_action": "trap",
                        "match_action": "allow",
                        "filter": []
                    },
                    "thread_1": {
                        "mismatch_action": "trap",
                        "match_action": "allow",
                        "filter": []
                    }
                }""",
                ).isFailure,
        )

        // Well-formed JSON cases
        val emptyResult = compiler.compile("{}").getOrThrow()
        assertEquals(0, emptyResult.size)

        val emptyFilterInput = """{"a": {"match_action": "allow", "mismatch_action":"log", "filter": []}}"""
        assertTrue(compiler.compile(emptyFilterInput).isSuccess)

        val aliasInput = """{
            "a": {
                "default_action":"log",
                "filter_action": "allow",
                "filter": []
            }
        }"""
        val filterWithAliases = compiler.compile(aliasInput).getOrThrow()

        val withoutAliasInput = """{
            "a": {
                "mismatch_action":"log",
                "match_action": "allow",
                "filter": []
            }
        }"""
        val filterWithoutAliases = compiler.compile(withoutAliasInput).getOrThrow()
        assertEquals(filterWithAliases["a"], filterWithoutAliases["a"])

        val fullJsonInput = """{
            "thread_1": {
                "mismatch_action": {
                    "errno": 12
                },
                "match_action": "allow",
                "filter": [
                    {
                        "syscall": "openat"
                    },
                    {
                        "syscall": "close"
                    },
                    {
                        "syscall": "read"
                    },
                    {
                        "syscall": "futex",
                        "args": [
                            {
                                "index": 2,
                                "type": "dword",
                                "op": "le",
                                "val": 65
                            },
                            {
                                "index": 1,
                                "type": "qword",
                                "op": "ne",
                                "val": 80
                            }
                        ]
                    },
                    {
                        "syscall": "futex",
                        "args": [
                            {
                                "index": 3,
                                "type": "qword",
                                "op": "gt",
                                "val": 65
                            },
                            {
                                "index": 1,
                                "type": "qword",
                                "op": "lt",
                                "val": 80
                            }
                        ]
                    },
                    {
                        "syscall": "futex",
                        "args": [
                            {
                                "index": 3,
                                "type": "qword",
                                "op": "ge",
                                "val": 65,
                                "comment": "dummy comment"
                            }
                        ]
                    },
                    {
                        "syscall": "ioctl",
                        "args": [
                            {
                                "index": 3,
                                "type": "dword",
                                "op": {
                                    "masked_eq": 100
                                },
                                "val": 65
                            }
                        ]
                    }
                ]
            },
            "thread_2": {
                "mismatch_action": "trap",
                "match_action": "allow",
                "filter": [
                    {
                        "syscall": "ioctl",
                        "comment": "dummy comment",
                        "args": [
                            {
                                "index": 3,
                                "type": "dword",
                                "op": "eq",
                                "val": 65,
                                "comment": "dummy comment"
                            }
                        ]
                    }
                ]
            }
        }"""

        val compiledFull = compiler.compile(fullJsonInput).getOrThrow()
        assertEquals(2, compiledFull.size)
        assertTrue(compiledFull.containsKey("thread_1"))
        assertTrue(compiledFull.containsKey("thread_2"))
    }
}
