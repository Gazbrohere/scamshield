package com.scamshield.companion

import android.telecom.Call
import android.telecom.CallScreeningService
import java.util.concurrent.Executors

class ScamShieldCallScreeningService : CallScreeningService() {
    override fun onScreenCall(callDetails: Call.Details) {
        if (callDetails.callDirection != Call.Details.DIRECTION_INCOMING) return
        val number = callDetails.handle?.schemeSpecificPart ?: return
        val prefs = getSharedPreferences("scamshield", MODE_PRIVATE)
        val settings = DeviceSettings(
            prefs.getString("endpoint", "") ?: "",
            prefs.getString("token", "") ?: "",
            prefs.getString("language", "en") ?: "en",
        )
        Executors.newSingleThreadExecutor().execute {
            val result = ApiClient.checkCaller(settings, number)
            if (result != null) {
                respondToCall(callDetails, CallResponse.Builder().setDisallowCall(false).build())
            }
        }
    }
}
