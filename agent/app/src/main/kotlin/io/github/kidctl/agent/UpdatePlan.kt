package io.github.kidctl.agent

import org.json.JSONObject
import java.io.InputStream
import java.security.MessageDigest

/**
 * Self-update decisions, kept free of Android APIs so they are unit tested
 * (UpdatePlanTest). The Android side is [Updater].
 */

/** The agent release offered by the server (sync response `agent`, see src/api.rs). */
data class Release(val versionCode: Long, val versionName: String, val sha256: String, val size: Long, val url: String) {
    fun toJson(): JSONObject = JSONObject().put("version_code", versionCode).put("version_name", versionName)
        .put("sha256", sha256).put("size", size).put("url", url)

    companion object {
        private val HEX64 = Regex("[0-9a-f]{64}")

        /** null when absent or unusable. Never throws: a bad offer must not break the sync. */
        fun parse(o: JSONObject?): Release? {
            if (o == null) return null
            val vc = o.optLong("version_code", 0)
            val sha = o.optString("sha256", "").lowercase()
            val size = o.optLong("size", 0)
            val url = o.optString("url", "")
            if (vc <= 0 || !HEX64.matches(sha) || size <= 0 || size > UpdatePlan.MAX_APK_BYTES) return null
            // Relative to the configured server only: the device token is sent
            // with the download and must never go to another host.
            if (!url.startsWith("/") || url.startsWith("//") || url.contains("..")) return null
            return Release(vc, o.optString("version_name", ""), sha, size, url)
        }
    }
}

/** The last update attempt (recorded before it starts), so failures back off. */
data class Attempt(val versionCode: Long, val sha256: String, val count: Int, val nextMs: Long) {
    fun toJson(): JSONObject = JSONObject().put("version_code", versionCode).put("sha256", sha256)
        .put("count", count).put("next_ms", nextMs)

    companion object {
        fun parse(s: String?): Attempt? = try {
            s?.let { JSONObject(it) }?.let {
                Attempt(it.getLong("version_code"), it.getString("sha256"), it.getInt("count"), it.getLong("next_ms"))
            }
        } catch (e: Exception) {
            null
        }
    }
}

object UpdatePlan {
    const val MAX_APK_BYTES = 64L * 1024 * 1024
    const val FIRST_BACKOFF_MS = 15 * 60_000L
    const val MAX_BACKOFF_MS = 24 * 3600_000L

    /**
     * Download now? Only a strictly higher versionCode, and a release that
     * already failed waits for its backoff. A different release (other code or
     * hash) is tried at once.
     */
    fun shouldDownload(offer: Release?, installedCode: Long, last: Attempt?, nowMs: Long): Boolean {
        if (offer == null || offer.versionCode <= installedCode) return false
        if (last == null || last.versionCode != offer.versionCode || last.sha256 != offer.sha256) return true
        // A clock set far back must not freeze updates for longer than the max backoff.
        return nowMs >= last.nextMs || last.nextMs - nowMs > MAX_BACKOFF_MS
    }

    /** Attempt record for trying [offer] now: 15 min, 30 min, 1 h ... capped at 24 h. */
    fun nextAttempt(offer: Release, last: Attempt?, nowMs: Long): Attempt {
        val same = last != null && last.versionCode == offer.versionCode && last.sha256 == offer.sha256
        val count = if (same) last!!.count + 1 else 1
        val backoff = (FIRST_BACKOFF_MS shl (count - 1).coerceAtMost(16)).coerceAtMost(MAX_BACKOFF_MS)
        return Attempt(offer.versionCode, offer.sha256, count, nowMs + backoff)
    }

    /** null when the downloaded bytes are exactly the offered APK, else why not. */
    fun checkDownload(offer: Release, size: Long, sha256: String): String? = when {
        size != offer.size -> "size mismatch: got $size bytes, offered ${offer.size}"
        !sha256.equals(offer.sha256, ignoreCase = true) -> "sha256 mismatch: got $sha256, offered ${offer.sha256}"
        else -> null
    }

    /** null when the APK is an update of this very app at the offered version. */
    fun checkArchive(offer: Release, ownPackage: String, apkPackage: String?, apkVersionCode: Long?): String? = when {
        apkPackage == null -> "not a readable APK"
        apkPackage != ownPackage -> "APK is $apkPackage, not $ownPackage"
        apkVersionCode != offer.versionCode -> "APK versionCode $apkVersionCode, offered ${offer.versionCode}"
        else -> null
    }

    /** PackageInstaller.DEVELOPER_VERIFICATION_FAILED_REASON_* (API 37), checked in UpdatePlanTest. */
    const val DEV_VERIFICATION_UNKNOWN = 0
    const val DEV_VERIFICATION_NETWORK_UNAVAILABLE = 1
    const val DEV_VERIFICATION_DEVELOPER_BLOCKED = 2

    /**
     * `agent_update_failed` detail for a failed install session: the status,
     * the installer's message and, when Android's developer verification
     * refused the APK (PackageInstaller.EXTRA_DEVELOPER_VERIFICATION_FAILURE_REASON,
     * API 37; null when absent), why.
     */
    fun installFailure(status: Int, message: String, devVerificationReason: Int?): String {
        val base = "install status $status: $message"
        val reason = when (devVerificationReason) {
            null -> return base
            DEV_VERIFICATION_UNKNOWN -> "unknown"
            DEV_VERIFICATION_NETWORK_UNAVAILABLE -> "network unavailable"
            DEV_VERIFICATION_DEVELOPER_BLOCKED -> "developer blocked"
            else -> "reason $devVerificationReason"
        }
        return "$base; developer verification failed: $reason"
    }

    fun sha256Hex(input: InputStream): String {
        val md = MessageDigest.getInstance("SHA-256")
        val buf = ByteArray(64 * 1024)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            md.update(buf, 0, n)
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}
