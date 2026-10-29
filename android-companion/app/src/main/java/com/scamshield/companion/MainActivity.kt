package com.scamshield.companion

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {
    private val preferences by lazy { getSharedPreferences("scamshield", MODE_PRIVATE) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val endpoint = EditText(this).apply {
            hint = "HTTPS API endpoint, e.g. https://host/api/device/check"
            setText(preferences.getString("endpoint", ""))
        }
        val token = EditText(this).apply {
            hint = "Device token"
            setText(preferences.getString("token", ""))
            inputType = 0x81
        }
        val language = EditText(this).apply {
            hint = "Report language (English)"
            setText(preferences.getString("language", "en"))
        }
        val status = TextView(this).apply {
            text = "Nothing is monitored until you enable each Android service."
            setPadding(0, 24, 0, 24)
        }
        val save = Button(this).apply {
            text = "Save settings"
            setOnClickListener {
                preferences.edit()
                    .putString("endpoint", endpoint.text.toString().trim())
                    .putString("token", token.text.toString())
                    .putString("language", language.text.toString().trim())
                    .apply()
                status.text = "Saved. Enable message checks and caller screening below."
            }
        }
        val notifications = Button(this).apply {
            text = "Enable message checks"
            setOnClickListener {
                startActivity(Intent("android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS"))
            }
        }
        val calls = Button(this).apply {
            text = "Choose ScamShield for caller screening"
            setOnClickListener {
                startActivity(Intent(Settings.ACTION_MANAGE_DEFAULT_APP_SETTINGS))
            }
        }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 48, 32, 32)
            addView(TextView(context).apply { text = "ScamShield companion"; textSize = 26f })
            addView(status)
            addView(endpoint)
            addView(token)
            addView(language)
            addView(save)
            addView(notifications)
            addView(calls)
        })
    }
}
