package io.github.kidctl.agent

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Small persistent state: server config, cached policy, what we applied. */
class State(private val ctx: Context) {
    private val prefs: SharedPreferences = ctx.getSharedPreferences("kidctl", Context.MODE_PRIVATE)
    private val policyFile = File(ctx.filesDir, "policy.json")

    var serverUrl: String?
        get() = prefs.getString("server_url", null)
        set(v) = prefs.edit().putString("server_url", v).apply()
    var token: String?
        get() = prefs.getString("token", null)
        set(v) = prefs.edit().putString("token", v).apply()
    var deviceId: String?
        get() = prefs.getString("device_id", null)
        set(v) = prefs.edit().putString("device_id", v).apply()

    var policyVersion: String
        get() = prefs.getString("policy_version", "") ?: ""
        private set(v) = prefs.edit().putString("policy_version", v).apply()

    var lastSyncMs: Long
        get() = prefs.getLong("last_sync_ms", 0)
        set(v) = prefs.edit().putLong("last_sync_ms", v).apply()
    var syncIntervalSecs: Long
        get() = prefs.getLong("sync_interval_secs", 60)
        set(v) = prefs.edit().putLong("sync_interval_secs", v).apply()
    var lastError: String?
        get() = prefs.getString("last_error", null)
        set(v) = prefs.edit().putString("last_error", v).apply()
    var appsHash: String
        get() = prefs.getString("apps_hash", "") ?: ""
        set(v) = prefs.edit().putString("apps_hash", v).apply()

    // What we applied through DevicePolicyManager: written synchronously
    // (commit), so that a process killed right after a change (low memory)
    // still knows what to undo. apply() writes ~100 ms later, or never.
    var suspendedByUs: Set<String>
        get() = prefs.getStringSet("suspended", emptySet())!!.toSet()
        set(v) { prefs.edit().putStringSet("suspended", v).commit() }
    var appliedRestrictions: Set<String>
        get() = prefs.getStringSet("restrictions", emptySet())!!.toSet()
        set(v) { prefs.edit().putStringSet("restrictions", v).commit() }
    var uninstallBlockedByUs: Set<String>
        get() = prefs.getStringSet("uninstall_blocked", emptySet())!!.toSet()
        set(v) { prefs.edit().putStringSet("uninstall_blocked", v).commit() }

    /** Packages whose managed configuration (device.app_config) we set: cleared when they leave the policy. */
    var appConfigByUs: Set<String>
        get() = prefs.getStringSet("app_config", emptySet())!!.toSet()
        set(v) { prefs.edit().putStringSet("app_config", v).commit() }

    var hiddenByUs: Set<String>
        get() = prefs.getStringSet("hidden", emptySet())!!.toSet()
        set(v) { prefs.edit().putStringSet("hidden", v).commit() }

    /** The policy set private DNS: when it no longer does, Android's default comes back. */
    var privateDnsByUs: Boolean
        get() = prefs.getBoolean("private_dns", false)
        set(v) { prefs.edit().putBoolean("private_dns", v).commit() }

    /**
     * Default apps we locked with addPersistentPreferredActivity: role
     * ("browser", "launcher") -> the components, flattened, joined by ';'.
     * Kept so that removing an entry clears exactly what we set.
     */
    var defaultAppsByUs: Map<String, String>
        get() = JSONObject(prefs.getString("default_apps", "{}")!!).let { o -> o.keyList().associateWith { o.getString(it) } }
        set(v) { prefs.edit().putString("default_apps", JSONObject(v).toString()).commit() }

    /**
     * The home app before we locked a launcher. Locking HOME also moves
     * Android's home role, which clearing does not move back: we restore it.
     */
    var launcherBefore: String?
        get() = prefs.getString("launcher_before", null)
        set(v) { prefs.edit().putString("launcher_before", v).commit() }

    /**
     * Notifications already posted (quota thresholds per limit today, last
     * downtime start noticed). Written synchronously (commit): a notice must
     * not come again because the process was killed right after posting it.
     */
    var notifyState: NotifyState
        get() = NotifyState.parse(prefs.getString("notify_state", null))
        set(v) { prefs.edit().putString("notify_state", v.toJson().toString()).commit() }

    /** Usage of the child's other devices for [otherUsageDate] (from the server). */
    var otherUsageDate: String
        get() = prefs.getString("other_usage_date", "") ?: ""
        set(v) = prefs.edit().putString("other_usage_date", v).apply()
    var otherUsage: Map<String, Long>
        get() = JSONObject(prefs.getString("other_usage", "{}")!!).let { o -> o.keyList().associateWith { o.getLong(it) } }
        set(v) = prefs.edit().putString("other_usage", JSONObject(v).toString()).apply()

    /** Agent release offered at the last successful sync (null: none). */
    var agentOffer: Release?
        get() = try {
            prefs.getString("agent_offer", null)?.let { Release.parse(JSONObject(it)) }
        } catch (e: Exception) {
            null
        }
        set(v) = prefs.edit().putString("agent_offer", v?.toJson()?.toString()).apply()
    var updateAttempt: Attempt?
        get() = Attempt.parse(prefs.getString("update_attempt", null))
        set(v) = prefs.edit().putString("update_attempt", v?.toJson()?.toString()).apply()
    /** versionCode of the agent that last ran (to report updates). */
    var lastVersionCode: Long
        get() = prefs.getLong("last_version_code", 0)
        set(v) = prefs.edit().putLong("last_version_code", v).apply()

    fun loadPolicy(): Policy? = try {
        if (policyFile.exists()) Policy.parse(JSONObject(policyFile.readText())) else null
    } catch (e: Exception) {
        lastError = "cached policy unreadable: $e"
        null
    }

    fun savePolicy(version: String, json: JSONObject) {
        Policy.parse(json) // throws on an unusable policy: keep the previous one
        val tmp = File(ctx.filesDir, "policy.json.tmp")
        tmp.writeText(json.toString())
        tmp.renameTo(policyFile)
        policyVersion = version
    }

    @Synchronized
    fun addEvent(kind: String, detail: String = "") {
        val a = JSONArray(prefs.getString("events", "[]"))
        if (a.length() >= 200) a.remove(0)
        a.put(JSONObject().put("ts", System.currentTimeMillis() / 1000).put("kind", kind).put("detail", detail))
        prefs.edit().putString("events", a.toString()).apply()
    }

    @Synchronized
    fun takeEvents(): JSONArray {
        val a = JSONArray(prefs.getString("events", "[]"))
        prefs.edit().putString("events", "[]").apply()
        return a
    }

    @Synchronized
    fun restoreEvents(a: JSONArray) {
        val cur = JSONArray(prefs.getString("events", "[]"))
        for (i in 0 until cur.length()) a.put(cur.get(i))
        prefs.edit().putString("events", a.toString()).apply()
    }
}
