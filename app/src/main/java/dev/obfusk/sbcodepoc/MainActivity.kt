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
        val apk = getAPK()
        val sig_block = getSigBlock(apk)
        tv.text = if (sig_block == null) "null" else "not null"
    }

    fun getAPK(): String {
        val pm = applicationContext.getPackageManager()
        val info = pm.getApplicationInfo("dev.obfusk.sbcodepoc", 0)
        return info.sourceDir
    }

    fun getSigBlock(apk: String): ByteArray? {
        RandomAccessFile(apk, "r").use {
            val len = it.length()
            var pos = len - 1024
            Log.v(TAG, "Length: ${len}")
            while (pos + 4 <= len) {
                it.seek(pos)
                val eocd_magic = it.read(4)
                if (eocd_magic.contentEquals(EOCD_MAGIC)) {
                    Log.v(TAG, "Found EOCD at ${pos}")
                    it.seek(pos + 16)
                    val cd_off = it.readUInt(4)
                    Log.v(TAG, "CD offset is ${cd_off}")
                    it.seek(cd_off - 16)
                    val sb_magic = it.read(4)
                    if (!sb_magic.contentEquals(SB_MAGIC)) {
                        Log.e(TAG, "No APK Signing Block")
                        return null
                    }
                    it.seek(cd_off - 8)
                    val sb_size2 = it.readUInt(8)
                    it.seek(cd_off - sb_size2)
                    val sb_size1 = it.readUInt(8)
                    if (sb_size1 != sb_size2) {
                        Log.e(TAG, "APK Signing Block sizes not equal")
                        return null
                    }
                    it.seek(cd_off - sb_size2)
                    val sig_block = it.read(sb_size2.toInt() + 8)
                    return sig_block
                }
                ++pos
            }
        }
        return null
    }

    val EOCD_MAGIC = byteArrayOf(0x50, 0x4b, 0x05, 0x06)
    val SB_MAGIC = "APK Sig Block 42".toByteArray()
    val TAG = "SBCodePoC"
}
