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
        handlePayload(findViewById(R.id.message))
    }

    fun handlePayload(tv: TextView) {
        val apk = getAPK()
        Log.v(TAG, "APK path=${apk}")
        getSigBlock(apk)?.let { blk ->
            parseSigBlock(blk).forEach { pair ->
                when {
                    pair.id == POC_BLOCK_ID -> {
                        Log.v(TAG, "Payload in PoC Block")
                        pair.data
                    }
                    pair.id == VERITY_PADDING_BLOCK_ID && pair.data[0].toInt() != 0 -> {
                        Log.v(TAG, "Payload in Verity Padding Block")
                        pair.data.sliceArray(0 until pair.data.indexOf(0))
                    }
                    else -> null
                }?.decodeToString()?.let {
                    Log.v(TAG, "PoC payload=${it}")
                    tv.text = it
                }
            }
        }
    }

    fun getAPK(): String =
        applicationContext.getPackageManager()
            .getApplicationInfo(applicationContext.packageName, 0).sourceDir

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
    fun parseSigBlock(sigBlock: ByteArray): ArrayList<Pair> {
        val results = ArrayList<Pair>()
        sigBlock.inputStream().use {
            it.readUInt(8) // skip over size
            while (it.available() > 24) {
                val pairLen = it.readUInt(8)
                val pairId = it.readUInt(4)
                val pairVal = it.read(pairLen.toInt() - 4)
                results.add(Pair(pairId, pairVal))
                Log.v(TAG, "Pair length=${pairLen}, ID=0x${pairId.toString(16)}")
                when (pairId) {
                    APK_SIGNATURE_SCHEME_V2_BLOCK_ID ->
                        Log.v(TAG, "APK SIGNATURE SCHEME v2 BLOCK")
                    APK_SIGNATURE_SCHEME_V3_BLOCK_ID ->
                        Log.v(TAG, "APK SIGNATURE SCHEME v3 BLOCK")
                    APK_SIGNATURE_SCHEME_V31_BLOCK_ID ->
                        Log.v(TAG, "APK SIGNATURE SCHEME v3.1 BLOCK")
                    VERITY_PADDING_BLOCK_ID ->
                        Log.v(TAG, "VERITY PADDING BLOCK")
                    POC_BLOCK_ID ->
                        Log.v(TAG, "POC BLOCK")
                    else ->
                        Log.v(TAG, "UNKNOWN BLOCK")
                }
            }
            // remaining: size + magic
        }
        return results
    }

    class Pair(val id: Long, val data: ByteArray)

    val EOCD_MAGIC = byteArrayOf(0x50, 0x4b, 0x05, 0x06)
    val SB_MAGIC = "APK Sig Block 42".toByteArray()

    val APK_SIGNATURE_SCHEME_V2_BLOCK_ID: Long = 0x7109871a
    val APK_SIGNATURE_SCHEME_V3_BLOCK_ID: Long = 0xf05368c0
    val APK_SIGNATURE_SCHEME_V31_BLOCK_ID: Long = 0x1b93ad6
    val VERITY_PADDING_BLOCK_ID: Long = 0x42726577

    val POC_BLOCK_ID: Long = 0x506f4342

    val TAG = "SBCodePoC"
}
