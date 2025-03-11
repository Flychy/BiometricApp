package com.example.biometricapp

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.util.concurrent.Executor

class MainActivity : AppCompatActivity() {

    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo
    private lateinit var btnAuthenticate: Button
    private lateinit var inputMessageEditText: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        btnAuthenticate = findViewById(R.id.btnAuthenticate)
        inputMessageEditText = findViewById(R.id.inputMessageEditText)

        //generate RSA key pair if not present
        EncryptionHelper.generateRSAKeyPair()

        val biometricManager = BiometricManager.from(this)
        when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> setupBiometricAuthentication()
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> showMessage("No biometric hardware available.")
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> showMessage("Biometric features are unavailable.")
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> showMessage("No biometrics enrolled. Set it up in settings.")
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> {
                TODO()
            }

            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> {
                TODO()
            }

            BiometricManager.BIOMETRIC_STATUS_UNKNOWN -> {
                TODO()
            }
        }

        btnAuthenticate.setOnClickListener {
            biometricPrompt.authenticate(promptInfo)
        }
    }

    private fun setupBiometricAuthentication() {
        val executor: Executor = ContextCompat.getMainExecutor(this)

        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)

                    val messageToEncrypt = inputMessageEditText.text.toString()
                    if (messageToEncrypt.isBlank()) {
                        showMessage("Please enter a message before encrypting.")
                        return
                    }

                    val publicKey = EncryptionHelper.getPublicKey()
                    val privateKey = EncryptionHelper.getPrivateKey()

                    if (publicKey != null && privateKey != null) {
                        // Encrypt and Sign the message
                        val encryptedMessage = EncryptionHelper.encryptWithRSA(messageToEncrypt, publicKey)
                        val signature = EncryptionHelper.signWithRSA(messageToEncrypt, privateKey)

                        // Navigate to next activity with encrypted data & signature
                        val intent = Intent(this@MainActivity, AuthSuccessfullyActivity::class.java)
                        intent.putExtra("encrypted_message", encryptedMessage)
                        intent.putExtra("signature", signature)
                        intent.putExtra("original_message", messageToEncrypt)
                        startActivity(intent)
                    } else {
                        showMessage("Failed to retrieve RSA keys!")
                    }
                }
            })

        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric Authentication")
            .setSubtitle("Use your fingerprint to authenticate")
            .setNegativeButtonText("Cancel")
            .build()
    }

    private fun showMessage(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }
}
