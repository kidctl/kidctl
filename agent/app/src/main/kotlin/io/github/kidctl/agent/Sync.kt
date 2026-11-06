package io.github.kidctl.agent

import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/** POST /api/v1/sync (see src/api.rs). Runs on the service's worker thread. */
object Sync {
    data class Result(val newPolicy: Boolean, val error: String?)

    fun run(
        state: State,
        agentVersion: String,
        agentVersionCode: Long,
        sdk: Int,
        deviceOwner: Boolean,
        date: String,
        usage: Map<String, Long>,
        apps: List<AppInfo>,
    ): Result {
        val url = state.serverUrl ?: return Result(false, "not configured")
        val token = state.token ?: return Result(false, "not configured")
        val appsJson = JSONArray()
        apps.forEach {
            appsJson.put(JSONObject().put("package", it.pkg).put("label", it.label)
                .put("user_installed", it.userInstalled).put("suspended", it.suspended))
        }
        val hash = sha256(appsJson.toString())
        val events = state.takeEvents()
        val body = JSONObject()
            .put("device_id", state.deviceId)
            .put("agent_version", agentVersion)
            .put("agent_version_code", agentVersionCode)
            .put("android_sdk", sdk)
            .put("device_owner", deviceOwner)
            .put("policy_version", state.policyVersion)
            .put("date", date)
            .put("usage", JSONObject(usage))
            .put("events", events)
            .put("last_error", state.lastError ?: JSONObject.NULL)
        if (hash != state.appsHash) body.put("apps", appsJson)
        return try {
            val c = (URL(url.trimEnd('/') + "/api/v1/sync").openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 15_000
                readTimeout = 20_000
                doOutput = true
                setRequestProperty("content-type", "application/json")
                setRequestProperty("authorization", "Bearer $token")
            }
            c.outputStream.use { it.write(body.toString().toByteArray()) }
            val code = c.responseCode
            val text = (if (code in 200..299) c.inputStream else c.errorStream)?.bufferedReader()?.use { it.readText() } ?: ""
            if (code !in 200..299) {
                state.restoreEvents(events)
                return Result(false, "HTTP $code: ${text.take(200)}")
            }
            val r = JSONObject(text)
            // First, before anything that could fail on a policy problem: the
            // update offer (an update may be what fixes that problem).
            state.agentOffer = Release.parse(r.optJSONObject("agent"))
            var newPolicy = false
            if (!r.isNull("policy")) {
                state.savePolicy(r.getString("policy_version"), r.getJSONObject("policy"))
                newPolicy = true
            }
            val other = r.getJSONObject("other_usage")
            state.otherUsage = other.keyList().associateWith { other.getLong(it) }
            state.otherUsageDate = date
            state.syncIntervalSecs = r.optLong("sync_interval_secs", 60).coerceIn(15, 3600)
            state.appsHash = hash
            state.lastError = null
            Result(newPolicy, null)
        } catch (e: Exception) {
            state.restoreEvents(events)
            Result(false, e.toString())
        }
    }

    private fun sha256(s: String): String =
        MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString("") { "%02x".format(it) }
}
