// port-lint: source frontend/json.rs
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
import io.github.kotlinmania.seccompiler.syscalltable.SyscallTable
import io.github.kotlinmania.seccompiler.backend.Error as BackendError

public typealias Result<T> = kotlin.Result<T>

/** Error compiling JSON into IR. */
public sealed class Error(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause) {
    override fun toString(): String = message.orEmpty()

    /** Backend error creating the `SeccompFilter` IR. */
    public data class Backend(
        val error: BackendError,
    ) : Error(error.toString(), error) {
        override fun toString(): String = message.orEmpty()
    }

    /** Error deserializing JSON. */
    public data class SerdeJson(
        val errorMsg: String,
    ) : Error("Error parsing Json: $errorMsg") {
        override fun toString(): String = message.orEmpty()
    }

    /** Invalid syscall name for the given arch. */
    public data class SyscallName(
        val syscallName: String,
        val arch: TargetArch,
    ) : Error("Invalid syscall name: $syscallName for given arch: $arch.") {
        override fun toString(): String = message.orEmpty()
    }
}

/** Condition that a syscall must match in order to satisfy a rule. */
public data class JsonCondition(
    val argIndex: UInt,
    val argLen: SeccompCmpArgLen,
    val operator: SeccompCmpOp,
    val value: ULong,
    val comment: String? = null,
) {
    public fun tryInto(): Result<SeccompCondition> {
        val res = SeccompCondition.new(argIndex, argLen, operator, value)
        if (res.isFailure) {
            return Result.failure(Error.Backend(res.exceptionOrNull() as BackendError))
        }
        return Result.success(res.getOrThrow())
    }
}

/** Deserializable object representing a rule associated to a syscall. */
public data class JsonRule(
    val syscall: String,
    val conditions: List<JsonCondition>? = null,
    val comment: String? = null,
)

/** Deserializable seccomp filter. */
public data class JsonFilter(
    val mismatchAction: SeccompAction,
    val matchAction: SeccompAction,
    val rules: List<JsonRule>,
)

/**
 * Object responsible for compiling [JsonFilter]s into [SeccompFilter]s, which represent the IR.
 */
public class JsonCompiler(
    public val arch: TargetArch,
) {
    internal val syscallTable: SyscallTable = SyscallTable(arch)

    /** Main compilation function. */
    public fun compile(jsonStr: String): Result<Map<String, SeccompFilter>> {
        val filters =
            try {
                parseJsonFilters(jsonStr)
            } catch (e: Exception) {
                return Result.failure(Error.SerdeJson(e.message ?: "Unknown JSON error"))
            }

        val bpfMap = HashMap<String, SeccompFilter>(filters.size)
        for ((name, filter) in filters) {
            val filterRes = makeSeccompFilter(filter)
            if (filterRes.isFailure) {
                return Result.failure(filterRes.exceptionOrNull()!!)
            }
            bpfMap[name] = filterRes.getOrThrow()
        }
        return Result.success(bpfMap)
    }

    public fun compile(bytes: ByteArray): Result<Map<String, SeccompFilter>> =
        compile(bytes.decodeToString())

    /** Transforms the deserialized [JsonFilter] into a [SeccompFilter] (IR language). */
    public fun makeSeccompFilter(filter: JsonFilter): Result<SeccompFilter> {
        val ruleMap = mutableMapOf<Long, MutableList<SeccompRule>>()

        for (jsonRule in filter.rules) {
            val syscallName = jsonRule.syscall
            val syscallNr =
                syscallTable.getSyscallNr(syscallName)
                    ?: return Result.failure(Error.SyscallName(syscallName, arch))
            val ruleAccumulator = ruleMap.getOrPut(syscallNr) { mutableListOf() }

            if (jsonRule.conditions != null) {
                val seccompConditions = ArrayList<SeccompCondition>(jsonRule.conditions.size)
                for (condition in jsonRule.conditions) {
                    val condResult = condition.tryInto()
                    if (condResult.isFailure) {
                        return Result.failure(condResult.exceptionOrNull()!!)
                    }
                    seccompConditions.add(condResult.getOrThrow())
                }
                val ruleResult = SeccompRule.new(seccompConditions)
                if (ruleResult.isFailure) {
                    return Result.failure(Error.Backend(ruleResult.exceptionOrNull() as BackendError))
                }
                ruleAccumulator.add(ruleResult.getOrThrow())
            }
        }

        val filterResult =
            SeccompFilter.new(
                ruleMap,
                filter.mismatchAction,
                filter.matchAction,
                arch,
            )
        if (filterResult.isFailure) {
            return Result.failure(Error.Backend(filterResult.exceptionOrNull() as BackendError))
        }
        return Result.success(filterResult.getOrThrow())
    }
}

private class JsonLexer(
    private val src: String,
) {
    var pos: Int = 0
    val len: Int = src.length

    fun skipWhitespace() {
        while (pos < len && src[pos].isWhitespace()) {
            pos++
        }
    }

    fun hasMore(): Boolean {
        skipWhitespace()
        return pos < len
    }

    fun peek(): Char {
        skipWhitespace()
        if (pos >= len) throw IllegalArgumentException("Unexpected end of JSON input")
        return src[pos]
    }

    fun expect(c: Char) {
        skipWhitespace()
        if (pos >= len || src[pos] != c) {
            throw IllegalArgumentException("Expected '$c' at offset $pos")
        }
        pos++
    }

    fun parseString(): String {
        expect('"')
        val sb = StringBuilder()
        while (pos < len) {
            val c = src[pos++]
            if (c == '"') return sb.toString()
            if (c == '\\') {
                if (pos >= len) throw IllegalArgumentException("Unterminated string escape")
                when (val esc = src[pos++]) {
                    '"' -> {
                        sb.append('"')
                    }

                    '\\' -> {
                        sb.append('\\')
                    }

                    '/' -> {
                        sb.append('/')
                    }

                    'b' -> {
                        sb.append('\b')
                    }

                    'f' -> {
                        sb.append('\u000C')
                    }

                    'n' -> {
                        sb.append('\n')
                    }

                    'r' -> {
                        sb.append('\r')
                    }

                    't' -> {
                        sb.append('\t')
                    }

                    'u' -> {
                        if (pos + 4 > len) throw IllegalArgumentException("Incomplete unicode escape")
                        val hex = src.substring(pos, pos + 4)
                        pos += 4
                        sb.append(hex.toInt(16).toChar())
                    }

                    else -> {
                        throw IllegalArgumentException("Invalid escape sequence: \\$esc")
                    }
                }
            } else {
                sb.append(c)
            }
        }
        throw IllegalArgumentException("Unclosed string literal")
    }

    fun parseRawNumber(): String {
        skipWhitespace()
        val start = pos
        if (pos < len && src[pos] == '-') pos++
        while (pos < len && (src[pos].isDigit() || src[pos] == '.' || src[pos] == 'e' || src[pos] == 'E' || src[pos] == '+' || src[pos] == '-')) {
            pos++
        }
        if (start == pos) throw IllegalArgumentException("Expected number at offset $start")
        return src.substring(start, pos)
    }
}

private fun parseJsonFilters(src: String): Map<String, JsonFilter> {
    val lexer = JsonLexer(src)
    if (!lexer.hasMore()) throw IllegalArgumentException("Empty input")
    lexer.expect('{')
    val seenKeys = mutableSetOf<String>()
    val result = mutableMapOf<String, JsonFilter>()
    if (lexer.peek() == '}') {
        lexer.expect('}')
        if (lexer.hasMore()) throw IllegalArgumentException("Trailing characters after JSON")
        return result
    }
    while (true) {
        val key = lexer.parseString()
        if (!seenKeys.add(key)) throw IllegalArgumentException("duplicate filter key")
        lexer.expect(':')
        val filter = parseFilter(lexer)
        result[key] = filter
        if (lexer.peek() == ',') {
            lexer.expect(',')
            if (lexer.peek() == '}') throw IllegalArgumentException("Trailing comma in object")
        } else {
            break
        }
    }
    lexer.expect('}')
    if (lexer.hasMore()) throw IllegalArgumentException("Trailing characters after JSON")
    return result
}

private fun parseFilter(lexer: JsonLexer): JsonFilter {
    lexer.expect('{')
    val seenKeys = mutableSetOf<String>()
    var mismatchAction: SeccompAction? = null
    var matchAction: SeccompAction? = null
    var rules: List<JsonRule>? = null

    if (lexer.peek() == '}') {
        lexer.expect('}')
        throw IllegalArgumentException("Empty filter object is not allowed")
    }

    while (true) {
        val key = lexer.parseString()
        if (!seenKeys.add(key)) throw IllegalArgumentException("duplicate key: $key")
        lexer.expect(':')
        when (key) {
            "mismatch_action" -> {
                if (mismatchAction != null || seenKeys.contains("default_action")) {
                    throw IllegalArgumentException("duplicate or aliased action key: $key")
                }
                mismatchAction = parseAction(lexer)
            }

            "default_action" -> {
                if (mismatchAction != null || seenKeys.contains("mismatch_action")) {
                    throw IllegalArgumentException("duplicate or aliased action key: $key")
                }
                mismatchAction = parseAction(lexer)
            }

            "match_action" -> {
                if (matchAction != null || seenKeys.contains("filter_action")) {
                    throw IllegalArgumentException("duplicate or aliased action key: $key")
                }
                matchAction = parseAction(lexer)
            }

            "filter_action" -> {
                if (matchAction != null || seenKeys.contains("match_action")) {
                    throw IllegalArgumentException("duplicate or aliased action key: $key")
                }
                matchAction = parseAction(lexer)
            }

            "filter" -> {
                rules = parseRules(lexer)
            }

            else -> {
                throw IllegalArgumentException("Unknown field in filter: $key")
            }
        }
        if (lexer.peek() == ',') {
            lexer.expect(',')
            if (lexer.peek() == '}') throw IllegalArgumentException("Trailing comma in filter object")
        } else {
            break
        }
    }
    lexer.expect('}')
    if (mismatchAction == null || matchAction == null || rules == null) {
        throw IllegalArgumentException("Missing required filter fields (match_action, mismatch_action, filter)")
    }
    return JsonFilter(mismatchAction, matchAction, rules)
}

private fun parseAction(lexer: JsonLexer): SeccompAction =
    when (lexer.peek()) {
        '"' -> {
            val str = lexer.parseString()
            when (str) {
                "allow" -> SeccompAction.Allow
                "kill_thread" -> SeccompAction.KillThread
                "kill_process" -> SeccompAction.KillProcess
                "log" -> SeccompAction.Log
                "trap" -> SeccompAction.Trap
                else -> throw IllegalArgumentException("Invalid action: $str")
            }
        }

        '{' -> {
            lexer.expect('{')
            val key = lexer.parseString()
            lexer.expect(':')
            val raw = lexer.parseRawNumber()
            if (raw.contains('.') || raw.contains('-') || raw.contains('e', ignoreCase = true)) {
                throw IllegalArgumentException("Action value must be unsigned integer")
            }
            val num = raw.toUIntOrNull() ?: throw IllegalArgumentException("Action value overflow")
            lexer.expect('}')
            when (key) {
                "errno" -> SeccompAction.Errno(num)
                "trace" -> SeccompAction.Trace(num)
                else -> throw IllegalArgumentException("Invalid action key in object: $key")
            }
        }

        else -> {
            throw IllegalArgumentException("Invalid action JSON structure")
        }
    }

private fun parseRules(lexer: JsonLexer): List<JsonRule> {
    lexer.expect('[')
    val rules = mutableListOf<JsonRule>()
    if (lexer.peek() == ']') {
        lexer.expect(']')
        return rules
    }
    while (true) {
        rules.add(parseRule(lexer))
        if (lexer.peek() == ',') {
            lexer.expect(',')
            if (lexer.peek() == ']') throw IllegalArgumentException("Trailing comma in rules array")
        } else {
            break
        }
    }
    lexer.expect(']')
    return rules
}

private fun parseRule(lexer: JsonLexer): JsonRule {
    lexer.expect('{')
    val seen = mutableSetOf<String>()
    var syscall: String? = null
    var conditions: List<JsonCondition>? = null
    var comment: String? = null

    if (lexer.peek() == '}') {
        lexer.expect('}')
        throw IllegalArgumentException("Empty rule object")
    }

    while (true) {
        val key = lexer.parseString()
        if (!seen.add(key)) throw IllegalArgumentException("duplicate key in rule: $key")
        lexer.expect(':')
        when (key) {
            "syscall" -> syscall = lexer.parseString()
            "args" -> conditions = parseConditions(lexer)
            "comment" -> comment = lexer.parseString()
            else -> throw IllegalArgumentException("Unknown field in rule: $key")
        }
        if (lexer.peek() == ',') {
            lexer.expect(',')
            if (lexer.peek() == '}') throw IllegalArgumentException("Trailing comma in rule object")
        } else {
            break
        }
    }
    lexer.expect('}')
    if (syscall == null) throw IllegalArgumentException("Missing required syscall in rule")
    return JsonRule(syscall, conditions, comment)
}

private fun parseConditions(lexer: JsonLexer): List<JsonCondition> {
    lexer.expect('[')
    val list = mutableListOf<JsonCondition>()
    if (lexer.peek() == ']') {
        lexer.expect(']')
        return list
    }
    while (true) {
        list.add(parseCondition(lexer))
        if (lexer.peek() == ',') {
            lexer.expect(',')
            if (lexer.peek() == ']') throw IllegalArgumentException("Trailing comma in conditions array")
        } else {
            break
        }
    }
    lexer.expect(']')
    return list
}

private fun parseCondition(lexer: JsonLexer): JsonCondition {
    lexer.expect('{')
    val seen = mutableSetOf<String>()
    var index: UInt? = null
    var type: SeccompCmpArgLen? = null
    var op: SeccompCmpOp? = null
    var valNum: ULong? = null
    var comment: String? = null

    while (true) {
        val key = lexer.parseString()
        if (!seen.add(key)) throw IllegalArgumentException("duplicate key in condition: $key")
        lexer.expect(':')
        when (key) {
            "index" -> {
                val raw = lexer.parseRawNumber()
                if (raw.contains('.') || raw.contains('-') || raw.contains('e', ignoreCase = true)) {
                    throw IllegalArgumentException("Index must be an unsigned integer")
                }
                index = raw.toUIntOrNull()?.takeIf { it <= 255u }
                    ?: throw IllegalArgumentException("Index out of bounds")
            }

            "type" -> {
                val t = lexer.parseString()
                type =
                    when (t.lowercase()) {
                        "dword" -> SeccompCmpArgLen.DWORD
                        "qword" -> SeccompCmpArgLen.QWORD
                        else -> throw IllegalArgumentException("Invalid type: $t")
                    }
            }

            "op" -> {
                if (lexer.peek() == '"') {
                    val o = lexer.parseString()
                    op =
                        when (o.lowercase()) {
                            "eq" -> SeccompCmpOp.Eq
                            "ge" -> SeccompCmpOp.Ge
                            "gt" -> SeccompCmpOp.Gt
                            "le" -> SeccompCmpOp.Le
                            "lt" -> SeccompCmpOp.Lt
                            "ne" -> SeccompCmpOp.Ne
                            else -> throw IllegalArgumentException("Invalid op: $o")
                        }
                } else if (lexer.peek() == '{') {
                    lexer.expect('{')
                    val opKey = lexer.parseString()
                    if (opKey != "masked_eq") throw IllegalArgumentException("Unknown op key: $opKey")
                    lexer.expect(':')
                    val raw = lexer.parseRawNumber()
                    if (raw.contains('.') || raw.contains('-') || raw.contains('e', ignoreCase = true)) {
                        throw IllegalArgumentException("Mask must be an unsigned integer")
                    }
                    val mask = raw.toULongOrNull() ?: throw IllegalArgumentException("Mask overflow")
                    lexer.expect('}')
                    op = SeccompCmpOp.MaskedEq(mask)
                } else {
                    throw IllegalArgumentException("Invalid op format")
                }
            }

            "val" -> {
                val raw = lexer.parseRawNumber()
                if (raw.contains('.') || raw.contains('-') || raw.contains('e', ignoreCase = true)) {
                    throw IllegalArgumentException("Value must be an unsigned integer")
                }
                valNum = raw.toULongOrNull() ?: throw IllegalArgumentException("Value overflow")
            }

            "comment" -> {
                comment = lexer.parseString()
            }

            else -> {
                throw IllegalArgumentException("Unknown field in condition: $key")
            }
        }
        if (lexer.peek() == ',') {
            lexer.expect(',')
            if (lexer.peek() == '}') throw IllegalArgumentException("Trailing comma in condition object")
        } else {
            break
        }
    }
    lexer.expect('}')
    if (index == null || type == null || op == null || valNum == null) {
        throw IllegalArgumentException("Missing required fields in condition")
    }
    return JsonCondition(index, type, op, valNum, comment)
}
