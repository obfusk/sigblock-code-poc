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
    fun parseSigBlock(sigBlock: ByteArray) {
        sigBlock.inputStream().use {
            val sbSize1 = it.readUInt(8)
            Log.v(TAG, "Size 1 is ${sbSize1}")
        }
    }

    val EOCD_MAGIC = byteArrayOf(0x50, 0x4b, 0x05, 0x06)
    val SB_MAGIC = "APK Sig Block 42".toByteArray()

    val PACKAGE = "dev.obfusk.sbcodepoc"
    val TAG = "SBCodePoC"
}
