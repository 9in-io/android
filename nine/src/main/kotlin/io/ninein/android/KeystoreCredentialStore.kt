package io.ninein.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.BadPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The default [CredentialStore] on Android: each value is encrypted with AES-256-GCM under a key
 * that never leaves the Android Keystore (hardware-backed where the device has it), with the value's
 * name as associated data, and written atomically to the app's no-backup directory. Nothing is
 * copied to cloud backups (the key can't be restored, so a restored copy would be unreadable).
 *
 * A value that can't be decrypted (the key was lost, the file was tampered with) reads as absent
 * and is deleted, so the user simply signs in again.
 */
public class KeystoreCredentialStore internal constructor(
    context: Context,
    private val keyProvider: SecretKeyProvider,
    directoryName: String,
) : CredentialStore {
    public constructor(context: Context) : this(context, AndroidKeystoreKeyProvider(KEY_ALIAS), DIRECTORY)

    private val directory = File((context.applicationContext ?: context).noBackupFilesDir, directoryName)
    private var key: SecretKey? = null

    @Synchronized
    override fun read(key: String): String? {
        val file = fileFor(key)
        if (!file.baseFile.exists()) return null
        return try {
            decrypt(file.readFully(), key)
        } catch (e: GeneralSecurityException) {
            // A failed tag or padding (tampered data, or written with a key that's gone) is permanent;
            // anything else (the Keystore briefly unavailable) is passed on and the data kept.
            if (e !is BadPaddingException && e !is IllegalBlockSizeException) throw e
            file.delete()
            null
        } catch (e: IllegalArgumentException) {
            file.delete() // not our format
            null
        }
    }

    @Synchronized
    override fun write(key: String, value: String?) {
        val file = fileFor(key)
        if (value == null) {
            file.delete()
            return
        }
        directory.mkdirs()
        val data = encrypt(value, key)
        val out = file.startWrite()
        try {
            out.write(data)
            file.finishWrite(out)
        } catch (e: Exception) {
            file.failWrite(out)
            throw e
        }
    }

    private fun fileFor(key: String): AtomicFile {
        val hash = MessageDigest.getInstance("SHA-256").digest(key.toByteArray(Charsets.UTF_8))
        return AtomicFile(File(directory, Base64.getUrlEncoder().withoutPadding().encodeToString(hash)))
    }

    private fun secretKey(): SecretKey = key ?: keyProvider.key().also { key = it }

    private fun encrypt(value: String, name: String): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        cipher.updateAAD(name.toByteArray(Charsets.UTF_8))
        val iv = cipher.iv
        val sealed = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        return byteArrayOf(FORMAT_VERSION, iv.size.toByte()) + iv + sealed
    }

    private fun decrypt(data: ByteArray, name: String): String {
        require(data.size > 2 && data[0] == FORMAT_VERSION) { "unknown format" }
        val ivLength = data[1].toInt()
        require(ivLength in 12..16 && data.size > 2 + ivLength) { "bad IV" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(128, data, 2, ivLength))
        cipher.updateAAD(name.toByteArray(Charsets.UTF_8))
        return cipher.doFinal(data, 2 + ivLength, data.size - 2 - ivLength).toString(Charsets.UTF_8)
    }

    internal companion object {
        const val KEY_ALIAS = "io.ninein.android.credentials"
        const val DIRECTORY = "io.ninein.android"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val FORMAT_VERSION: Byte = 1
    }
}

/** Where the store's AES key comes from (the Android Keystore; a software key in tests). */
internal fun interface SecretKeyProvider {
    fun key(): SecretKey
}

/** An AES-256-GCM key in the Android Keystore, created on first use. */
internal class AndroidKeystoreKeyProvider(private val alias: String) : SecretKeyProvider {
    override fun key(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(alias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}
