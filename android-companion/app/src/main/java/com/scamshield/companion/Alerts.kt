package com.scamshield.companion

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import androidx.core.app.NotificationCompat

object Alerts {
    private const val CHANNEL_ID = "scamshield-alerts"

    fun showIfRisky(context: Context, result: String?, title: String) {
        if (result == null || (!result.contains("\"scam\"") && !result.contains("\"suspicious\""))) {
            return
        }
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "ScamShield warnings",
                NotificationManager.IMPORTANCE_HIGH,
            ),
        )
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText("ScamShield found risk signals. Review before responding.")
            .setAutoCancel(true)
            .build()
        manager.notify(System.currentTimeMillis().toInt(), notification)
    }
}
