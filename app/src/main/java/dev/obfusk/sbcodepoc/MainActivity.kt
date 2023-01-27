// SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net>
// SPDX-License-Identifier: GPL-3.0-or-later

package dev.obfusk.sbcodepoc

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import java.io.RandomAccessFile

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val tv: TextView = findViewById(R.id.message)
        getSigBlock(getAPK())?.let {
            parseSigBlock(it) // FIXME
            tv.text = it.size.toString()
        }
    }

    fun getAPK(): String = applicationContext.getPackageManager().getApplicationInfo(PACKAGE, 0).sourceDir

    // FIXME
    fun getSigBlock(apk: String): ByteArray? {
        RandomAccessFile(apk, "r").use {
            val len = it.length()
            var pos = len - 1024
            while (pos + 4 <= len) {
                it.seek(pos)
                if (it.read(4).contentEquals(EOCD_MAGIC)) {
                    it.seek(pos + 16)
                    val cdOff = it.readUInt(4)
                    it.seek(cdOff - 16)
                    if (!it.read(16).contentEquals(SB_MAGIC)) {
                        Log.e(TAG, "No APK Signing Block")
                        return null
                    }
                    it.seek(cdOff - 24)
                    val sbSize2 = it.readUInt(8)
                    it.seek(cdOff - sbSize2 - 8)
                    val sbSize1 = it.readUInt(8)
                    if (sbSize1 != sbSize2) {
                        Log.e(TAG, "APK Signing Block sizes not equal")
                        return null
                    }
                    it.seek(cdOff - sbSize2 - 8)
                    return it.read(sbSize2.toInt() + 8)
                }
                ++pos
            }
        }
        return null
    }

    // FIXME
    fun parseSigBlock(sigBlock: ByteArray): ArrayList<Block> {
        val results = ArrayList<Block>()
        sigBlock.inputStream().use {
            it.readUInt(8) // skip over size
            while (it.available() > 24) {
                val pairLen = it.readUInt(8)
                val pairId = it.readUInt(4)
                val pairVal = it.read(pairLen.toInt() - 4)
                results.add(Block(pairId, pairVal))
                Log.v(TAG, "Pair len ${pairLen}, ID 0x${pairId.toString(16)}")
                when (pairId) {
                    APK_SIGNATURE_SCHEME_V2_BLOCK_ID -> {
                        Log.v(TAG, "APK SIGNATURE SCHEME v2 BLOCK")
                    }
                    APK_SIGNATURE_SCHEME_V3_BLOCK_ID -> {
                        Log.v(TAG, "APK SIGNATURE SCHEME v3 BLOCK")
                    }
                    APK_SIGNATURE_SCHEME_V31_BLOCK_ID -> {
                        Log.v(TAG, "APK SIGNATURE SCHEME v3.1 BLOCK")
                    }
                    VERITY_PADDING_BLOCK_ID -> {
                        Log.v(TAG, "VERITY PADDING BLOCK BLOCK")
                    }
                }
            }
        }
        return results
    }

    class Block(val id: Long, val data: ByteArray)

    val EOCD_MAGIC = byteArrayOf(0x50, 0x4b, 0x05, 0x06)
    val SB_MAGIC = "APK Sig Block 42".toByteArray()

    val APK_SIGNATURE_SCHEME_V2_BLOCK_ID: Long = 0x7109871a
    val APK_SIGNATURE_SCHEME_V3_BLOCK_ID: Long = 0xf05368c0
    val APK_SIGNATURE_SCHEME_V31_BLOCK_ID: Long = 0x1b93ad6
    val VERITY_PADDING_BLOCK_ID: Long = 0x42726577

    val PACKAGE = "dev.obfusk.sbcodepoc"
    val TAG = "SBCodePoC"
}
