package com.example.biometricapp

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.charset.Charset
import java.security.*
import javax.crypto.Cipher

object EncryptionHelper {

    private const val KEY_ALIAS = "DMSRSAKey"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val RSA_MODE = "RSA/ECB/PKCS1Padding"

    //generate RSA Key Pair (Public + Private)
    fun generateRSAKeyPair() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        if (!keyStore.containsAlias(KEY_ALIAS)) {
            val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
            val keySpec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setKeySize(2048)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setKeySize(2048)
                .build()

            keyPairGenerator.initialize(keySpec)
            keyPairGenerator.generateKeyPair()
        }
    }

    //get Public Key from Keystore
    fun getPublicKey(): PublicKey? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val keyEntry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
        return keyEntry?.certificate?.publicKey
    }

    //get Private Key from Keystore
    fun getPrivateKey(): PrivateKey? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val keyEntry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
        return keyEntry?.privateKey
    }

    //encrypt a Message using RSA Public Key
    fun encryptWithRSA(message: String, publicKey: PublicKey): String {
        val cipher = Cipher.getInstance(RSA_MODE)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)

        val encryptedBytes = cipher.doFinal(message.toByteArray(Charset.forName("UTF-8")))
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    //digitally Sign a Message using RSA Private Key
    fun signWithRSA(message: String, privateKey: PrivateKey): String {
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(privateKey)
        signature.update(message.toByteArray(Charset.forName("UTF-8")))

        val signedBytes = signature.sign()
        return Base64.encodeToString(signedBytes, Base64.DEFAULT)
    }

    fun verifySignature(message: String, signatureString: String, publicKey: PublicKey): Boolean {
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initVerify(publicKey)
        signature.update(message.toByteArray(Charset.forName("UTF-8")))

        val signatureBytes = Base64.decode(signatureString, Base64.DEFAULT)
        return signature.verify(signatureBytes)
    }
}
