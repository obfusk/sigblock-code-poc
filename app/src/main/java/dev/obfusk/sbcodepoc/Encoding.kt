/*
 * Copyright (C) 2021 The Android Open Source Project
 * Copyright (C) 2023 FC Stegerman <flx@obfusk.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dev.obfusk.sbcodepoc

import java.io.InputStream
import java.io.RandomAccessFile

internal fun RandomAccessFile.read(length: Int): ByteArray {
    val buffer = ByteArray(length)
    var offset = 0
    while (offset < length) {
        val result = read(buffer, offset, length - offset)
        if (result < 0) {
            error("Not enough bytes to read: $length")
        }
        offset += result
    }
    return buffer
}

internal fun RandomAccessFile.readUInt(numberOfBytes: Int): Long {
    val buffer = read(numberOfBytes)
    var value: Long = 0
    for (k in 0 until numberOfBytes) {
        val next = buffer[k].toUByte().toLong()
        value += next shl k * java.lang.Byte.SIZE
    }
    return value
}

internal fun InputStream.read(length: Int): ByteArray {
    val buffer = ByteArray(length)
    var offset = 0
    while (offset < length) {
        val result = read(buffer, offset, length - offset)
        if (result < 0) {
            error("Not enough bytes to read: $length")
        }
        offset += result
    }
    return buffer
}

internal fun InputStream.readUInt(numberOfBytes: Int): Long {
    val buffer = read(numberOfBytes)
    var value: Long = 0
    for (k in 0 until numberOfBytes) {
        val next = buffer[k].toUByte().toLong()
        value += next shl k * java.lang.Byte.SIZE
    }
    return value
}
