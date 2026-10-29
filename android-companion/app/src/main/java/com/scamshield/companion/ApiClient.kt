package com.scamshield.companion

import android.util.Base64
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.nio.charset.StandardCharsets

data class DeviceSettings(val endpoint: String, val token: String, val language: String)

object ApiClient {
    fun checkCaller(settings: DeviceSettings, number: String): String? =
        post(settings, """{"event_type":"caller","phone_number":"${escape(number)}","language":"${escape(settings.language)}"}""")

    fun checkMessage(settings: DeviceSettings, content: String): String? =
        post(settings, """{"event_type":"message","content":"${escape(content)}","language":"${escape(settings.language)}"}""")

    private fun post(settings: DeviceSettings, body: String): String? {
        val uri = runCatching { URI(settings.endpoint) }.getOrNull() ?: return null
        if (uri.scheme != "https" && uri.host != "10.0.2.2" && uri.host != "127.0.0.1") return null
        val connection = (URL(settings.endpoint).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 8_000
            readTimeout = 8_000
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("X-Device-Token", settings.token)
        }
        return try {
            connection.outputStream.use { it.write(body.toByteArray(StandardCharsets.UTF_8)) }
            if (connection.responseCode in 200..299) {
                connection.inputStream.bufferedReader().use { it.readText() }
            } else {
                null
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun escape(value: String): String =
        value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
}
