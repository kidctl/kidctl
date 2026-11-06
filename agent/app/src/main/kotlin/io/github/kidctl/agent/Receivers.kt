package io.github.kidctl.agent

import android.app.admin.DeviceAdminReceiver
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class AdminReceiver : DeviceAdminReceiver() {
    override fun onEnabled(context: Context, intent: Intent) {
        State(context).addEvent("admin_enabled")
        EnforcerService.start(context)
    }

    override fun onDisableRequested(context: Context, intent: Intent): CharSequence {
        State(context).addEvent("admin_disable_requested")
        return "Le contrôle parental est géré par tes parents."
    }

    override fun onDisabled(context: Context, intent: Intent) {
        State(context).addEvent("admin_disabled")
    }
}

/** Starts the service after a boot, and after an update of the agent itself (MY_PACKAGE_REPLACED). */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val s = State(context)
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            s.addEvent("boot")
        } else {
            val now = runCatching { context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode }.getOrDefault(0)
            s.addEvent("updated", "version_code ${s.lastVersionCode} -> $now")
        }
        EnforcerService.start(context)
    }
}

/**
 * Provisioning over adb (only the shell holds WRITE_SECURE_SETTINGS):
 * adb shell am broadcast -a io.github.kidctl.agent.CONFIGURE -n io.github.kidctl.agent/.ConfigReceiver \
 *   --es url https://kidctl.example --es device_id alex-phone --es token_file /data/local/tmp/kidctl.token
 * (`token_file` keeps the token out of adbd's command log; `--es token` also works).
 * Without extras it just forces a sync.
 */
class ConfigReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val s = State(context)
        intent.getStringExtra("url")?.let { s.serverUrl = it }
        intent.getStringExtra("device_id")?.let { s.deviceId = it }
        intent.getStringExtra("token")?.let { s.token = it }
        intent.getStringExtra("token_file")?.let { path ->
            runCatching { java.io.File(path).readText().trim() }
                .onSuccess { if (it.isNotEmpty()) s.token = it }
                .onFailure { Log.w("kidctl", "token_file unreadable: $it") }
        }
        s.lastSyncMs = 0
        s.addEvent("configured", s.serverUrl ?: "")
        Log.i("kidctl", "configured: ${s.serverUrl} as ${s.deviceId}")
        resultData = "configured ${s.deviceId} -> ${s.serverUrl}"
        EnforcerService.start(context)
    }
}
