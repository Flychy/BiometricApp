package com.example.biometricapp

import android.annotation.SuppressLint
import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class AuthSuccessfullyActivity : AppCompatActivity() {

    @SuppressLint("SetTextI18n", "MissingInflatedId")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_auth_successfully)

        val encryptedMessageTextView: TextView = findViewById(R.id.encryptedMessageTextView)
        val verificationStatusTextView: TextView = findViewById(R.id.verificationStatusTextView)

        //retrieve data passed from MainActivity
        val encryptedMessage = intent.getStringExtra("encrypted_message")
        val signature = intent.getStringExtra("signature")
        val originalMessage = intent.getStringExtra("original_message")

        encryptedMessageTextView.text = "Encrypted Message:\n$encryptedMessage"

        //verify Signature
        val publicKey = EncryptionHelper.getPublicKey()
        if (publicKey != null && signature != null && originalMessage != null) {
            val isVerified = EncryptionHelper.verifySignature(originalMessage, signature, publicKey)

            if (isVerified) {
                verificationStatusTextView.text = "Signature Verified: The message is authentic!"
                verificationStatusTextView.setTextColor(getColor(R.color.teal_200))
            } else {
                verificationStatusTextView.text = "Signature Verification Failed!"
                verificationStatusTextView.setTextColor(getColor(R.color.purple_200))
            }
        } else {
            verificationStatusTextView.text = "Unable to verify signature!"
        }
    }
}
