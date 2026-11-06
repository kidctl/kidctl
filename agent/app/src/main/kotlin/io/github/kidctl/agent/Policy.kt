package io.github.kidctl.agent

import org.json.JSONArray
import org.json.JSONObject

/** Normalized policy as served by the kidctl server (see src/policy.rs `Compiled`). */
data class Policy(
    val child: String,
    val timezone: String,
    val downtime: List<Downtime>,
    val alwaysAllowed: Set<String>,
    val blocked: Set<String>,
    val limits: List<Limit>,
    val approval: Boolean,
    val approved: Set<String>,
    val overrides: List<Override>,
    val device: DeviceConfig,
    /** Notifications on the phone; null = off (absent from older servers / policies). */
    val notify: Notify? = null,
) {
    companion object {
        fun parse(o: JSONObject): Policy = Policy(
            child = o.getString("child"),
            timezone = o.getString("timezone"),
            downtime = o.getJSONArray("downtime").objects().map {
                Downtime(
                    it.getInt("start_min"), it.getInt("end_min"), it.getJSONArray("days").booleans(),
                    lockScreen = it.optBoolean("lock_screen", false),
                )
            },
            alwaysAllowed = o.getJSONArray("always_allowed").strings().toSet(),
            blocked = o.getJSONArray("blocked").strings().toSet(),
            limits = o.getJSONArray("limits").objects().map {
                Limit(
                    name = it.getString("name"),
                    apps = it.getJSONArray("apps").strings().toSet(),
                    wildcard = it.getBoolean("wildcard"),
                    exclude = it.getJSONArray("exclude").strings().toSet(),
                    dailySecs = it.getJSONArray("daily_secs").let { a -> LongArray(7) { i -> a.getLong(i) } },
                    notifyAt = it.optJSONArray("notify_at")?.let { a -> List(a.length()) { i -> a.getInt(i) } } ?: emptyList(),
                )
            },
            approval = o.optBoolean("approval", false),
            approved = o.optJSONArray("approved")?.strings()?.toSet() ?: emptySet(),
            overrides = o.getJSONArray("overrides").objects().map {
                Override(
                    kind = it.getString("kind"),
                    limit = if (it.isNull("limit")) null else it.optString("limit", null),
                    secs = it.optLong("secs", 0),
                    from = it.getLong("from"),
                    until = it.getLong("until"),
                    screen = it.optBoolean("screen", false),
                )
            },
            device = DeviceConfig.parse(o.getJSONObject("device")),
            notify = o.optJSONObject("notify")?.let {
                Notify(beforeDowntimeSecs = it.optLong("before_downtime_secs", 0), locale = it.optString("locale", "fr"))
            },
        )
    }
}

data class Downtime(val startMin: Int, val endMin: Int, val days: BooleanArray, val lockScreen: Boolean = false)

data class Limit(
    val name: String,
    val apps: Set<String>,
    val wildcard: Boolean,
    val exclude: Set<String>,
    val dailySecs: LongArray,
    /** Percentages of the budget that trigger a notification (ascending); empty = none. */
    val notifyAt: List<Int> = emptyList(),
)

/** Compiled `notify:` (src/policy.rs `Notify`). */
data class Notify(val beforeDowntimeSecs: Long, val locale: String)

data class Override(
    val kind: String,
    val limit: String?,
    val secs: Long,
    val from: Long,
    val until: Long,
    /** kind == "lock": also keep the screen locked. */
    val screen: Boolean = false,
) {
    fun activeAt(now: Long) = now in from until until
}

data class DeviceConfig(
    val restrictions: List<String>,
    val alwaysOnVpnPackage: String?,
    val alwaysOnVpnLockdown: Boolean,
    val privateDnsMode: String?,
    val privateDnsHost: String?,
    val uninstallBlocked: List<String>,
    val lockScreenInfo: String?,
    val supportMessage: String?,
    val hidden: List<String> = emptyList(),
    val cameraDisabled: Boolean = false,
    val screenCaptureDisabled: Boolean = false,
    val autoSystemUpdates: Boolean = false,
    val locationAlwaysOn: Boolean = false,
    val permittedAccessibilityServices: List<String>? = null,
    val permittedInputMethods: List<String>? = null,
    /** Exactly one of these is non-null when the policy restricts Wi-Fi networks. */
    val wifiSsidsAllow: List<String>? = null,
    val wifiSsidsDeny: List<String>? = null,
    val defaultBrowser: String? = null,
    val defaultLauncher: String? = null,
    /** "This device belongs to <name>"; null = Android's generic text. */
    val organizationName: String? = null,
    /**
     * Managed configurations: package -> key -> Boolean, Int/Long, String or
     * List<String> (converted to the app's declared types by [AppConfig]).
     * Absent from older servers / policies: empty.
     */
    val appConfig: Map<String, Map<String, Any>> = emptyMap(),
    /**
     * Packages the user cannot force-stop or clear from Settings (the agent
     * adds itself, see [UserControl]). Absent from older servers / policies: empty.
     */
    val userControlDisabled: List<String> = emptyList(),
) {
    companion object {
        fun parse(o: JSONObject): DeviceConfig {
            val vpn = o.optJSONObject("always_on_vpn")
            val dns = o.optJSONObject("private_dns")
            val wifi = o.optJSONObject("wifi_ssids")
            val defaults = o.optJSONObject("default_apps")
            return DeviceConfig(
                restrictions = o.optJSONArray("restrictions")?.strings() ?: emptyList(),
                alwaysOnVpnPackage = vpn?.getString("package"),
                alwaysOnVpnLockdown = vpn?.optBoolean("lockdown", true) ?: false,
                privateDnsMode = dns?.getString("mode"),
                privateDnsHost = dns?.optString("host", null),
                uninstallBlocked = o.optJSONArray("uninstall_blocked")?.strings() ?: emptyList(),
                userControlDisabled = o.optJSONArray("user_control_disabled")?.strings() ?: emptyList(),
                lockScreenInfo = o.optString("lock_screen_info", null),
                supportMessage = o.optString("support_message", null),
                hidden = o.optJSONArray("hidden")?.strings() ?: emptyList(),
                cameraDisabled = o.optBoolean("camera_disabled", false),
                screenCaptureDisabled = o.optBoolean("screen_capture_disabled", false),
                autoSystemUpdates = o.optBoolean("auto_system_updates", false),
                locationAlwaysOn = o.optBoolean("location_always_on", false),
                permittedAccessibilityServices = o.optJSONArray("permitted_accessibility_services")?.strings(),
                permittedInputMethods = o.optJSONArray("permitted_input_methods")?.strings(),
                wifiSsidsAllow = wifi?.optJSONArray("allow")?.strings(),
                wifiSsidsDeny = wifi?.optJSONArray("deny")?.strings(),
                defaultBrowser = defaults?.optStringOrNull("browser"),
                defaultLauncher = defaults?.optStringOrNull("launcher"),
                organizationName = o.optStringOrNull("organization_name"),
                appConfig = o.optJSONObject("app_config")?.let { m ->
                    m.keyList().associateWith { pkg ->
                        val c = m.getJSONObject(pkg)
                        c.keyList().associateWith { k ->
                            when (val v = c.get(k)) {
                                is JSONArray -> v.strings()
                                else -> v
                            }
                        }
                    }
                } ?: emptyMap(),
            )
        }
    }
}

internal fun JSONArray.objects(): List<JSONObject> = (0 until length()).map { getJSONObject(it) }
internal fun JSONArray.strings(): List<String> = (0 until length()).map { getString(it) }
internal fun JSONArray.booleans(): BooleanArray = BooleanArray(length()) { getBoolean(it) }
/** Missing or JSON null -> null. */
internal fun JSONObject.optStringOrNull(key: String): String? = if (isNull(key)) null else getString(key)
/** Android's org.json has keys() but no keySet(). */
internal fun JSONObject.keyList(): List<String> = keys().asSequence().toList()
