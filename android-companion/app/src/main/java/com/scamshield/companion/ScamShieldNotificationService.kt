package com.scamshield.companion

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import java.util.concurrent.Executors

class ScamShieldNotificationService : NotificationListenerService() {
    override fun onNotificationPosted(notification: StatusBarNotification) {
        val extras = notification.notification.extras
        val content = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)
            ?: extras.getCharSequence(Notification.EXTRA_TEXT)
            ?: return
        val packageName = notification.packageName.lowercase()
        if (!packageName.contains("messaging") && !packageName.contains("sms")
            && !packageName.contains("whatsapp") && !packageName.contains("telegram")) return
        val prefs = getSharedPreferences("scamshield", MODE_PRIVATE)
        val settings = DeviceSettings(
            prefs.getString("endpoint", "") ?: "",
            prefs.getString("token", "") ?: "",
            prefs.getString("language", "en") ?: "en",
        )
        Executors.newSingleThreadExecutor().execute {
            ApiClient.checkMessage(settings, content.toString().take(20_000))
        }
    }
}
