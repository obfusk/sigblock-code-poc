// SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net>
// SPDX-License-Identifier: GPL-3.0-or-later

package dev.obfusk.sbcodepoc

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import java.io.RandomAccessFile

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val apk = getAPK()
        Log.v(TAG, "APK: ${apk}")
        // ...
    }

    fun getAPK(): String {
        val pm = applicationContext.getPackageManager()
        val info = pm.getApplicationInfo("dev.obfusk.sbcodepoc", 0)
        return info.sourceDir
    }

    fun getSB(apk: String): ByteArray? {
        RandomAccessFile(apk, "r").use {
            val len = it.length()
            var pos = len - 1024
            while (pos < len - 1) {
                it.seek(pos)
                val eocd_magic = it.read(4)
                if (eocd_magic.contentEquals(EOCD_MAGIC)) {
                    it.seek(pos - 16)
                    val cd_off = it.readUInt(4)
                    it.seek(cd_off - 16)
                    val sb_magic = it.read(4)
                    if (!sb_magic.contentEquals(SB_MAGIC)) {
                        error("No APK Signing Block")
                    }
                    it.seek(cd_off - 8)
                    val sb_size2 = it.readUInt(8)
                    it.seek(cd_off - sb_size2)
                    val sb_size1 = it.readUInt(8)
                    if (sb_size1 != sb_size2) {
                        error("APK Signing Block sizes not equal")
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
