package io.github.kidctl.agent

import android.Manifest
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.app.admin.WifiSsidPolicy
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.RestrictionEntry
import android.content.RestrictionsManager
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.location.LocationManager
import android.media.AudioManager
import android.net.Uri
import android.net.wifi.WifiSsid
import android.os.Bundle
import android.os.PowerManager
import android.os.SystemClock
import android.os.UserManager
import android.telecom.TelecomManager
import android.util.Log

data class AppInfo(val pkg: String, val label: String, val userInstalled: Boolean, var suspended: Boolean)

/** Applies a policy through DevicePolicyManager. Requires device owner. */
class Enforcer(private val ctx: Context, private val state: State) {
    private val dpm = ctx.getSystemService(DevicePolicyManager::class.java)
    private val pm = ctx.packageManager
    val admin = ComponentName(ctx, AdminReceiver::class.java)

    /** Whether [enforceApps] already took Android's real suspension state in this process. */
    private var suspensionsReconciled = false
    private fun reporter(kind: String, detail: String) {
        Log.w(TAG, "$kind: $detail")
        state.addEvent(kind, detail)
    }
    /** Problems of each enforcement pass, reported once while they last (see [Problems]). */
    private val deviceProblems = Problems(::reporter)
    private val appProblems = Problems(::reporter)
    private val lockProblems = Problems(::reporter)
    /** elapsedRealtime until which periodic screen-lock checks hold off (set by EnforcerService). */
    var holdUntilMs = 0L

    fun isDeviceOwner(): Boolean = dpm.isDeviceOwnerApp(ctx.packageName)

    /** Packages never suspended: the agent itself and what the phone needs to work. */
    fun exempt(): Set<String> {
        val s = mutableSetOf(ctx.packageName, "com.android.settings", "com.android.systemui", "com.android.phone",
            "com.android.emergency", "com.google.android.apps.safetyhub",
            // Cannot be suspended by a device owner (protected package).
            "com.android.vending")
        pm.resolveActivity(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME), PackageManager.MATCH_DEFAULT_ONLY)
            ?.activityInfo?.packageName?.let { s += it }
        ctx.getSystemService(TelecomManager::class.java)?.defaultDialerPackage?.let { s += it }
        return s
    }

    /** Launchable apps (what a child can open), minus exempt ones. */
    fun launchableApps(): List<AppInfo> {
        val ex = exempt()
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return pm.queryIntentActivities(intent, PackageManager.MATCH_DISABLED_COMPONENTS)
            .map { it.activityInfo.applicationInfo }
            .distinctBy { it.packageName }
            .filter { it.packageName !in ex }
            .map {
                AppInfo(
                    pkg = it.packageName,
                    label = pm.getApplicationLabel(it).toString(),
                    userInstalled = (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0,
                    suspended = it.packageName in state.suspendedByUs,
                )
            }
            .sortedBy { it.label.lowercase() }
    }

    /** Suspend/unsuspend apps per the policy. Returns the app list with final states. */
    fun enforceApps(p: Policy, now: Long, usage: Map<String, Long>): List<AppInfo> {
        val apps = launchableApps()
        if (!isDeviceOwner()) {
            state.lastError = "not device owner: cannot enforce"
            return apps
        }
        val want = apps.filter { Evaluator.decide(p, now, usage, it.pkg, it.userInstalled) != Evaluator.ALLOWED }
            .map { it.pkg }.toSet()
        val present = apps.map { it.pkg }.toSet()
        var had = state.suspendedByUs
        val pr = appProblems
        try {
            if (!suspensionsReconciled) {
                // The bookkeeping is saved after each change: a process killed in
                // between (low memory) loses it, and an app we suspended would then
                // stay suspended for good, or one we released never come back.
                // Within a process it cannot diverge, so once per process start take
                // what Android really has suspended for the launchable apps.
                val actual = present.filter { pr.call("suspend_failed", "$it: isPackageSuspended") { dpm.isPackageSuspended(admin, it) } == true }.toSet()
                if (actual != had.intersect(present)) Log.i(TAG, "suspensions reconciled: bookkeeping ${had.intersect(present)}, actual $actual")
                had = (had - present) + actual
                state.suspendedByUs = had
                suspensionsReconciled = true
            }
            // Unsuspend what no longer needs it (including uninstalled / now exempt apps we suspended).
            val toUnsuspend = (had - want).toTypedArray()
            val toSuspend = (want - had).toTypedArray()
            var now_ = had
            // setPackagesSuspended returns the packages it could not change.
            if (toUnsuspend.isNotEmpty()) {
                val r = pr.call("unsuspend_failed", toUnsuspend.joinToString(",")) { dpm.setPackagesSuspended(admin, toUnsuspend, false).toSet() }
                val failed = r ?: toUnsuspend.toSet()
                now_ = now_ - (toUnsuspend.toSet() - failed)
                r?.forEach { pr.add("unsuspend_failed", it) }
            }
            if (toSuspend.isNotEmpty()) {
                val r = pr.call("suspend_failed", toSuspend.joinToString(",")) { dpm.setPackagesSuspended(admin, toSuspend, true).toSet() }
                val failed = r ?: toSuspend.toSet()
                now_ = now_ + (toSuspend.toSet() - failed)
                r?.forEach { pr.add("suspend_failed", it) }
            }
            state.suspendedByUs = now_.filter { it in present || it in want }.toSet()
        } finally {
            pr.end()
        }
        apps.forEach { it.suspended = it.pkg in state.suspendedByUs }
        return apps
    }

    /** Installed for the user, hidden or not. */
    private fun installed(pkg: String): Boolean =
        runCatching { pm.getApplicationInfo(pkg, PackageManager.MATCH_UNINSTALLED_PACKAGES) }
            .getOrNull()?.let { (it.flags and ApplicationInfo.FLAG_INSTALLED) != 0 } ?: false

    /**
     * Device-wide settings from policy.device plus built-in self-protection.
     * Every device-policy call goes through [deviceProblems]: one that throws,
     * returns an error, or whose effect is not there when read back is
     * reported as a `*_failed` event (once while it lasts).
     */
    fun enforceDevice(p: Policy) {
        if (!isDeviceOwner()) return
        val pr = deviceProblems
        try {
            enforceDevice(p.device, pr)
        } catch (e: Exception) {
            // Reported once; tried again at the next policy change or package
            // change (thrown to the service, it would come back every tick).
            pr.add("device_policy_failed", "enforceDevice: $e")
        } finally {
            pr.end()
        }
    }

    private fun enforceDevice(d: DeviceConfig, pr: Problems) {
        // Self-protection: cannot uninstall the agent; no force stop / clear
        // storage for it nor for device.user_control_disabled.
        uninstallBlocked(pr, ctx.packageName, true)
        enforceUserControl(d, pr)
        // Screen-time notifications (policy notify): the agent may always post
        // them, and the child cannot revoke that (permission fixed by policy).
        val perm = Manifest.permission.POST_NOTIFICATIONS
        when (pr.call("notify_permission_failed", perm) {
            dpm.setPermissionGrantState(admin, ctx.packageName, perm, DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED)
        }) {
            true -> pr.verify("notify_permission_failed", perm) {
                dpm.getPermissionGrantState(admin, ctx.packageName, perm) == DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED
            }
            false -> pr.add("notify_permission_failed", "$perm: setPermissionGrantState returned false")
            null -> {}
        }

        enforceRestrictions(d, pr)

        val wantU = d.uninstallBlocked.toSet()
        for (pkg in wantU) uninstallBlocked(pr, pkg, true)
        val stillU = (state.uninstallBlockedByUs - wantU).filterNot { uninstallBlocked(pr, it, false) }
        state.uninstallBlockedByUs = wantU + stillU

        enforceVpn(d, pr)
        enforcePrivateDns(d, pr)

        val wantH = d.hidden.toSet()
        for (pkg in wantH) hidden(pr, pkg, true)
        val stillH = (state.hiddenByUs - wantH).filterNot { hidden(pr, it, false) }
        state.hiddenByUs = wantH + stillH

        if (pr.call("camera_failed", "setCameraDisabled(${d.cameraDisabled})") { dpm.setCameraDisabled(admin, d.cameraDisabled) } != null) {
            pr.verify("camera_failed", "setCameraDisabled(${d.cameraDisabled})") { dpm.getCameraDisabled(admin) == d.cameraDisabled }
        }
        val sc = "setScreenCaptureDisabled(${d.screenCaptureDisabled})"
        if (pr.call("screen_capture_failed", sc) { dpm.setScreenCaptureDisabled(admin, d.screenCaptureDisabled) } != null) {
            pr.verify("screen_capture_failed", sc) { dpm.getScreenCaptureDisabled(admin) == d.screenCaptureDisabled }
        }
        val up = if (d.autoSystemUpdates) "automatic" else "none"
        if (pr.call("update_policy_failed", up) {
                dpm.setSystemUpdatePolicy(admin, if (d.autoSystemUpdates) android.app.admin.SystemUpdatePolicy.createAutomaticInstallPolicy() else null)
            } != null
        ) {
            pr.verify("update_policy_failed", up) {
                val t = dpm.systemUpdatePolicy?.policyType
                if (d.autoSystemUpdates) t == android.app.admin.SystemUpdatePolicy.TYPE_INSTALL_AUTOMATIC else t == null
            }
        }
        if (d.locationAlwaysOn && pr.call("location_failed", "setLocationEnabled(true)") { dpm.setLocationEnabled(admin, true) } != null) {
            pr.verify("location_failed", "setLocationEnabled(true)", "location still off") {
                ctx.getSystemService(LocationManager::class.java).isLocationEnabled
            }
        }
        // false: an enabled non-system service / keyboard is not in the list
        // (Android then keeps the previous list).
        permitted(pr, "a11y_policy_failed", "setPermittedAccessibilityServices", d.permittedAccessibilityServices,
            { dpm.setPermittedAccessibilityServices(admin, it) }, { dpm.getPermittedAccessibilityServices(admin) })
        permitted(pr, "ime_policy_failed", "setPermittedInputMethods", d.permittedInputMethods,
            { dpm.setPermittedInputMethods(admin, it) }, { dpm.getPermittedInputMethods(admin) })

        // null clears each of these (Android's default text comes back).
        text(pr, "lock_screen_info_failed", "setDeviceOwnerLockScreenInfo", d.lockScreenInfo,
            { dpm.setDeviceOwnerLockScreenInfo(admin, it) }, { dpm.deviceOwnerLockScreenInfo })
        text(pr, "support_message_failed", "setShortSupportMessage", d.supportMessage,
            { dpm.setShortSupportMessage(admin, it) }, { dpm.getShortSupportMessage(admin) })
        // Not read back: getOrganizationName is for profile owners of a managed
        // profile (a device owner gets SecurityException "Calling user is not
        // authorized", API 37), getDeviceOwnerOrganizationName is a system API.
        text(pr, "organization_name_failed", "setOrganizationName", d.organizationName,
            { dpm.setOrganizationName(admin, it) }, null)

        pr.call("wifi_ssid_policy_failed", "setWifiSsidPolicy") { enforceWifiSsids(d, pr) }
        enforceDefaultApps(d, pr)
        enforceAppConfig(d, pr)
    }

    /**
     * Adds the wanted restrictions this admin has not set yet (a failed one
     * is tried again at the next pass), clears those it set that the policy
     * dropped, then checks that each wanted one is in force.
     */
    private fun enforceRestrictions(d: DeviceConfig, pr: Problems) {
        val wantR = d.restrictions.toSet()
        val mine = pr.call("restriction_failed", "getUserRestrictions") { dpm.getUserRestrictions(admin) }
        for (r in wantR) if (mine?.getBoolean(r) != true) pr.call("restriction_failed", r) { dpm.addUserRestriction(admin, r) }
        val stillR = (state.appliedRestrictions - wantR).filter { r -> pr.call("restriction_failed", "clear $r") { dpm.clearUserRestriction(admin, r) } == null }
        state.appliedRestrictions = wantR + stillR
        val um = ctx.getSystemService(UserManager::class.java)
        for (r in wantR) pr.verify("restriction_failed", r, "not in force (UserManager.hasUserRestriction false)") { um.hasUserRestriction(r) }
    }

    /**
     * setUserControlDisabledPackages replaces the whole list: the agent itself
     * plus device.user_control_disabled (a package removed from the policy
     * gets its Force stop / Clear storage buttons back). Packages not
     * installed yet are kept by Android and apply once installed. Read back
     * with getUserControlDisabledPackages, one problem per missing package.
     */
    private fun enforceUserControl(d: DeviceConfig, pr: Problems) {
        val kind = "user_control_disabled_failed"
        val want = UserControl.wanted(ctx.packageName, d.userControlDisabled)
        val got = pr.call(kind, "getUserControlDisabledPackages") { dpm.getUserControlDisabledPackages(admin) }
        if (got == null || !UserControl.same(want, got)) {
            pr.call(kind, want.joinToString(",")) { dpm.setUserControlDisabledPackages(admin, want) } ?: return
        }
        val now = pr.call(kind, "${want.joinToString(",")}: read back") { dpm.getUserControlDisabledPackages(admin) } ?: return
        for (m in UserControl.missing(want, now)) pr.add(kind, "$m: not in getUserControlDisabledPackages")
        for (x in UserControl.extra(want, now)) pr.add(kind, "$x: still in getUserControlDisabledPackages")
    }

    /** setUninstallBlocked, read back with isUninstallBlocked. Returns whether it holds. */
    private fun uninstallBlocked(pr: Problems, pkg: String, block: Boolean): Boolean {
        val what = if (block) pkg else "unblock $pkg"
        pr.call("uninstall_block_failed", what) { dpm.setUninstallBlocked(admin, pkg, block) } ?: return false
        // Android keeps the setting for a package that is not installed yet
        // (it applies once installed; this pass re-runs then): nothing to read back.
        if (!installed(pkg)) {
            Log.i(TAG, "uninstall_blocked $what: not installed")
            return true
        }
        return pr.verify("uninstall_block_failed", what, "isUninstallBlocked is ${!block} after setUninstallBlocked($block)") {
            dpm.isUninstallBlocked(admin, pkg) == block
        }
    }

    /** setApplicationHidden (its boolean result), read back with isApplicationHidden. Returns whether it holds. */
    private fun hidden(pr: Problems, pkg: String, hide: Boolean): Boolean {
        val what = if (hide) pkg else "unhide $pkg"
        // Re-applied when it is installed (this pass re-runs on every package change).
        if (!installed(pkg)) {
            Log.i(TAG, "hidden $what: not installed")
            return true
        }
        val r = pr.call("hide_failed", what) { dpm.setApplicationHidden(admin, pkg, hide) } ?: return false
        return pr.verify("hide_failed", what, "isApplicationHidden is ${!hide} (setApplicationHidden returned $r)") {
            dpm.isApplicationHidden(admin, pkg) == hide
        }
    }

    private fun enforceVpn(d: DeviceConfig, pr: Problems) {
        val vpn = d.alwaysOnVpnPackage
        val what = vpn ?: "clear"
        pr.call("vpn_failed", what) {
            if (vpn == null) {
                if (dpm.getAlwaysOnVpnPackage(admin) != null) dpm.setAlwaysOnVpnPackage(admin, null, false)
            } else if (dpm.getAlwaysOnVpnPackage(admin) != vpn || dpm.isAlwaysOnVpnLockdownEnabled(admin) != d.alwaysOnVpnLockdown) {
                dpm.setAlwaysOnVpnPackage(admin, vpn, d.alwaysOnVpnLockdown)
            }
        } ?: return
        val got = pr.call("vpn_failed", "$what: read back") { dpm.getAlwaysOnVpnPackage(admin) to dpm.isAlwaysOnVpnLockdownEnabled(admin) } ?: return
        val ok = if (vpn == null) got.first == null else got == (vpn to d.alwaysOnVpnLockdown)
        if (!ok) pr.add("vpn_failed", "$what: always-on VPN is ${got.first ?: "off"}, lockdown ${got.second}")
    }

    private fun enforcePrivateDns(d: DeviceConfig, pr: Problems) {
        val hostMode = DevicePolicyManager.PRIVATE_DNS_MODE_PROVIDER_HOSTNAME
        val auto = DevicePolicyManager.PRIVATE_DNS_MODE_OPPORTUNISTIC
        /** The set* calls return PRIVATE_DNS_SET_*: anything but NO_ERROR means not applied. */
        fun result(what: String, r: Int): Boolean {
            if (r == DevicePolicyManager.PRIVATE_DNS_SET_NO_ERROR) return true
            val why = when (r) {
                DevicePolicyManager.PRIVATE_DNS_SET_ERROR_HOST_NOT_SERVING -> "host not serving DNS over TLS"
                DevicePolicyManager.PRIVATE_DNS_SET_ERROR_FAILURE_SETTING -> "failure setting"
                else -> "unknown error"
            }
            pr.add("private_dns_failed", "$what: code $r ($why)")
            return false
        }
        fun verify(what: String, mode: Int, host: String?) = pr.verify("private_dns_failed", what,
            "mode ${dpm.getGlobalPrivateDnsMode(admin)} host ${dpm.getGlobalPrivateDnsHost(admin)} after setting it") {
            dpm.getGlobalPrivateDnsMode(admin) == mode && (host == null || dpm.getGlobalPrivateDnsHost(admin) == host)
        }
        fun automatic(what: String) {
            if (dpm.getGlobalPrivateDnsMode(admin) != auto && result(what, dpm.setGlobalPrivateDnsModeOpportunistic(admin))) verify(what, auto, null)
        }
        pr.call("private_dns_failed", d.privateDnsMode ?: "back to automatic") {
            when (d.privateDnsMode) {
                "host" -> {
                    val host = d.privateDnsHost!!
                    if (dpm.getGlobalPrivateDnsMode(admin) != hostMode || dpm.getGlobalPrivateDnsHost(admin) != host) {
                        if (result("host $host", dpm.setGlobalPrivateDnsModeSpecifiedHost(admin, host))) verify("host $host", hostMode, host)
                    }
                }
                "opportunistic" -> automatic("opportunistic")
                // Removed from the policy: back to Android's default, Automatic
                // (opportunistic), if we had set it; a mode set by hand on a
                // phone that never had private_dns in its policy is left alone.
                else -> if (state.privateDnsByUs) {
                    automatic("back to automatic")
                    Log.i(TAG, "private dns: back to automatic")
                }
            }
            state.privateDnsByUs = d.privateDnsMode != null
        }
    }

    /** setPermitted* returns false when an enabled non-system app is missing from the list (nothing applied). */
    private fun permitted(pr: Problems, kind: String, call: String, want: List<String>?, set: (List<String>?) -> Boolean, get: () -> List<String>?) {
        when (pr.call(kind, call) { set(want) }) {
            true -> pr.verify(kind, call) { get()?.toSet() == want?.toSet() }
            false -> pr.add(kind, "$call(${want ?: "any"}) returned false: an enabled non-system one is not in the list")
            null -> {}
        }
    }

    /** A device text (null: Android's default), read back after setting it when Android lets us ([get]). */
    private fun text(pr: Problems, kind: String, call: String, want: String?, set: (String?) -> Unit, get: (() -> CharSequence?)?) {
        pr.call(kind, call) { set(want) } ?: return
        if (get != null) pr.verify(kind, call) { (get()?.toString() ?: "") == (want ?: "") }
    }

    /**
     * device.app_config: each package's managed configuration
     * (setApplicationRestrictions), keys checked against what the app
     * declares (RestrictionsManager.getManifestRestrictions) and values
     * converted to the declared types ([AppConfig]). Set only when what the
     * app has differs, read back after setting; an `app_config_applied` event
     * says what the app now has. A package that is not installed is skipped
     * (this pass re-runs when it is installed); one removed from the policy
     * gets an empty configuration.
     */
    private fun enforceAppConfig(d: DeviceConfig, pr: Problems) {
        val kind = "app_config_failed"
        val keep = mutableSetOf<String>()
        fun current(pkg: String): Map<String, Any?>? = pr.call(kind, "$pkg: getApplicationRestrictions") {
            dpm.getApplicationRestrictions(admin, pkg).let { b -> b.keySet().associateWith { @Suppress("DEPRECATION") b.get(it) } }
        }
        for ((pkg, want) in d.appConfig) {
            keep += pkg
            if (!installed(pkg)) {
                Log.i(TAG, "app_config $pkg: not installed, applied once it is")
                continue
            }
            val declared = declaredRestrictions(pkg, pr) ?: continue
            val plan = AppConfig.plan(declared, want)
            for ((k, why) in plan.problems) pr.add(kind, "$pkg $k: $why")
            val cur = current(pkg) ?: continue
            if (AppConfig.same(cur, plan.values)) continue
            pr.call(kind, "$pkg: setApplicationRestrictions") { dpm.setApplicationRestrictions(admin, pkg, bundle(plan.values)) } ?: continue
            val got = current(pkg) ?: continue
            if (AppConfig.same(got, plan.values)) {
                Log.i(TAG, "app_config $pkg: ${AppConfig.describe(got)}")
                state.addEvent("app_config_applied", "$pkg: ${AppConfig.describe(got)}".take(Problems.MAX_DETAIL))
            } else {
                pr.add(kind, "$pkg: read back ${AppConfig.describe(got)}, wanted ${AppConfig.describe(plan.values)}")
            }
        }
        for (pkg in state.appConfigByUs - d.appConfig.keys) {
            // Kept (tried again at the next pass) unless cleared and read back empty.
            keep += pkg
            pr.call(kind, "$pkg: clear") { dpm.setApplicationRestrictions(admin, pkg, Bundle()) } ?: continue
            val got = current(pkg) ?: continue
            if (got.isNotEmpty()) {
                pr.add(kind, "$pkg: clear: still ${AppConfig.describe(got)}")
                continue
            }
            keep -= pkg
            Log.i(TAG, "app_config $pkg: cleared")
            state.addEvent("app_config_applied", "$pkg: cleared")
        }
        state.appConfigByUs = keep
    }

    /** What [pkg] declares (null after recording why, e.g. no managed configuration at all). */
    private fun declaredRestrictions(pkg: String, pr: Problems): List<Declared>? {
        // getManifestRestrictions throws on an app without any <meta-data>: check first.
        val info = pr.call("app_config_failed", "$pkg: getApplicationInfo") {
            pm.getApplicationInfo(pkg, PackageManager.GET_META_DATA or PackageManager.MATCH_UNINSTALLED_PACKAGES)
        } ?: return null
        if (info.metaData?.containsKey(RestrictionsManager.META_DATA_APP_RESTRICTIONS) != true) {
            pr.add("app_config_failed", "$pkg: the app declares no managed configuration (no ${RestrictionsManager.META_DATA_APP_RESTRICTIONS} in its manifest)")
            return null
        }
        val rm = ctx.getSystemService(RestrictionsManager::class.java)
        val entries = pr.call("app_config_failed", "$pkg: getManifestRestrictions") { rm.getManifestRestrictions(pkg) } ?: return null
        return entries.map { e ->
            val t = when (e.type) {
                RestrictionEntry.TYPE_BOOLEAN -> Declared.Type.BOOLEAN
                RestrictionEntry.TYPE_INTEGER -> Declared.Type.INTEGER
                RestrictionEntry.TYPE_STRING -> Declared.Type.STRING
                RestrictionEntry.TYPE_CHOICE -> Declared.Type.CHOICE
                RestrictionEntry.TYPE_MULTI_SELECT -> Declared.Type.MULTI_SELECT
                RestrictionEntry.TYPE_BUNDLE -> Declared.Type.BUNDLE
                RestrictionEntry.TYPE_BUNDLE_ARRAY -> Declared.Type.BUNDLE_ARRAY
                else -> Declared.Type.HIDDEN
            }
            Declared(e.key, t, e.choiceValues?.toList() ?: emptyList())
        }
    }

    private fun bundle(values: Map<String, Any>): Bundle = Bundle().apply {
        for ((k, v) in values) when (v) {
            is Boolean -> putBoolean(k, v)
            is Int -> putInt(k, v)
            is String -> putString(k, v)
            is Array<*> -> putStringArray(k, v.map { it as String }.toTypedArray())
            else -> error("app_config $k: unexpected ${v.javaClass}")
        }
    }

    /** setWifiSsidPolicy (API 33+); null clears it when the policy has no wifi_ssids. Read back after setting. */
    private fun enforceWifiSsids(d: DeviceConfig, pr: Problems) {
        fun ssids(l: List<String>) = l.map { WifiSsid.fromBytes(it.toByteArray(Charsets.UTF_8)) }.toSet()
        val want = when {
            d.wifiSsidsAllow != null -> WifiSsidPolicy(WifiSsidPolicy.WIFI_SSID_POLICY_TYPE_ALLOWLIST, ssids(d.wifiSsidsAllow))
            d.wifiSsidsDeny != null -> WifiSsidPolicy(WifiSsidPolicy.WIFI_SSID_POLICY_TYPE_DENYLIST, ssids(d.wifiSsidsDeny))
            else -> null
        }
        fun same(cur: WifiSsidPolicy?) = (cur == null && want == null) ||
            (cur != null && want != null && cur.policyType == want.policyType && cur.ssids == want.ssids)
        if (!same(dpm.wifiSsidPolicy)) {
            dpm.wifiSsidPolicy = want
            val what = d.wifiSsidsAllow?.let { "allow $it" } ?: d.wifiSsidsDeny?.let { "deny $it" } ?: "none"
            Log.i(TAG, "wifi ssid policy: $what")
            pr.verify("wifi_ssid_policy_failed", what) { same(dpm.wifiSsidPolicy) }
        }
    }

    /** The intents a default-app role answers, each with the filter we lock for it. */
    private fun roleIntents(role: String): List<Pair<IntentFilter, Intent>> = when (role) {
        "launcher" -> listOf(
            IntentFilter(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_HOME)
                addCategory(Intent.CATEGORY_DEFAULT)
            } to Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME),
        )
        "browser" -> listOf("https", "http").map { scheme ->
            IntentFilter(Intent.ACTION_VIEW).apply {
                addCategory(Intent.CATEGORY_BROWSABLE)
                addCategory(Intent.CATEGORY_DEFAULT)
                addDataScheme(scheme)
            } to Intent(Intent.ACTION_VIEW, Uri.parse("$scheme://example.com/")).addCategory(Intent.CATEGORY_BROWSABLE)
        }
        else -> error("unknown default app role $role")
    }

    private fun describe(i: Intent) = listOfNotNull(i.action, i.categories?.joinToString(","), i.scheme).joinToString(" ")

    /**
     * Filters to lock for [role], each with the activity of [pkg] that handles
     * it on this device; or null and the reason [pkg] cannot fill the role.
     */
    private fun defaultAppTargets(role: String, pkg: String): Pair<List<Pair<IntentFilter, ComponentName>>?, String?> {
        if (runCatching { pm.getPackageInfo(pkg, 0) }.isFailure) return null to "not installed"
        val out = roleIntents(role).map { (filter, intent) ->
            val ri = pm.queryIntentActivities(Intent(intent).setPackage(pkg), PackageManager.MATCH_DEFAULT_ONLY).firstOrNull()
                ?: return null to "does not handle ${describe(intent)}"
            filter to ComponentName(ri.activityInfo.packageName, ri.activityInfo.name)
        }
        return out to null
    }

    /**
     * device.default_apps: lock the browser / launcher with persistent preferred
     * activities, after checking the package really handles the intents here.
     * An entry that cannot be applied is skipped (the role falls back to the
     * system default) and reported as a `default_app_failed` event. After
     * applying, the intents are resolved again: if they still open another app
     * (for links: the holder of Android's browser role wins over persistent
     * preferred activities), a `default_app_ineffective` event says so.
     */
    private fun enforceDefaultApps(d: DeviceConfig, pr: Problems) {
        val targets = mutableMapOf<String, List<Pair<IntentFilter, ComponentName>>>()
        val problems = mutableSetOf<Pair<String, String>>()
        val roles = listOf("browser" to d.defaultBrowser, "launcher" to d.defaultLauncher).filter { it.second != null }
        for ((role, pkg) in roles) {
            val (t, why) = defaultAppTargets(role, pkg!!)
            if (t != null) targets[role] = t else problems += "default_app_failed" to "$role $pkg: $why"
        }
        val want = targets.mapValues { (_, t) -> t.joinToString(";") { it.second.flattenToString() } }
        val had = state.defaultAppsByUs
        if (want != had) {
            if ("launcher" in targets && "launcher" !in had) {
                state.launcherBefore = homePackage()?.takeIf { it != targets.getValue("launcher").first().second.packageName }
            }
            // The clear call is per package: clear every package we locked before,
            // then lock what is wanted now, so a removed entry is undone.
            val hadPkgs = had.values.flatMap { it.split(';') }.mapNotNull { ComponentName.unflattenFromString(it)?.packageName }.toSet()
            for (pkg in hadPkgs) runCatching { dpm.clearPackagePersistentPreferredActivities(admin, pkg) }
                .onFailure { problems += "default_app_failed" to "clear $pkg: $it" }
            if ("launcher" in had && "launcher" !in targets) restoreLauncher()?.let { problems += "default_app_failed" to it }
            val applied = mutableMapOf<String, String>()
            for ((role, t) in targets) {
                runCatching { t.forEach { (filter, comp) -> dpm.addPersistentPreferredActivity(admin, filter, comp) } }
                    .onSuccess { applied[role] = want.getValue(role) }
                    .onFailure { problems += "default_app_failed" to "$role: $it" }
            }
            state.defaultAppsByUs = applied
            Log.i(TAG, "default apps: cleared $hadPkgs, set $applied")
        }
        for (role in state.defaultAppsByUs.keys) {
            val pkg = roles.first { it.first == role }.second
            for ((_, intent) in roleIntents(role)) {
                val got = pm.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)?.activityInfo
                if (got?.packageName != pkg) {
                    val who = got?.let { if (it.packageName == "android") "the app chooser" else it.packageName } ?: "nothing"
                    problems += "default_app_ineffective" to "$role $pkg: ${describe(intent)} still opens $who"
                }
            }
        }
        for ((kind, msg) in problems) pr.add(kind, msg)
    }

    /** Package HOME resolves to now (null: none, or the chooser). */
    private fun homePackage(): String? =
        pm.resolveActivity(roleIntents("launcher").first().second, PackageManager.MATCH_DEFAULT_ONLY)
            ?.activityInfo?.packageName?.takeIf { it != "android" }

    /**
     * After the launcher lock is removed: Android moved its home role to the
     * locked launcher and clearing does not move it back, so the phone would
     * keep that launcher. Give HOME back to the app that had it before, the
     * same way (lock it, wait until HOME resolves to it, unlock). Returns an
     * error message, or null.
     */
    private fun restoreLauncher(): String? {
        val before = state.launcherBefore ?: return null
        state.launcherBefore = null
        val (t, why) = defaultAppTargets("launcher", before)
        if (t == null) return "restore launcher $before: $why"
        return runCatching {
            t.forEach { (filter, comp) -> dpm.addPersistentPreferredActivity(admin, filter, comp) }
            // The home role moves asynchronously; clearing too early would keep the old one.
            val deadline = SystemClock.elapsedRealtime() + 5_000
            while (homePackage() != before && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(100)
            dpm.clearPackagePersistentPreferredActivities(admin, before)
            Log.i(TAG, "launcher restored to $before")
            if (homePackage() != before) "restore launcher $before: HOME still opens ${homePackage() ?: "the app chooser"}" else null
        }.getOrElse { "restore launcher $before: $it" }
    }

    /**
     * Lock the screen if the policy requires it now and the phone is in use
     * (screen on, keyguard dismissed). Does nothing while the screen is off
     * (it wakes up on the keyguard), while the keyguard is showing (including
     * the emergency dialer or an incoming call displayed over it) or during a
     * phone call, so the emergency-call button stays reachable and a call is
     * never cut short by the screen going dark. Periodic checks ([scheduled]
     * false) also hold off until [holdUntilMs] (see EnforcerService's screen
     * receiver).
     */
    fun enforceScreenLock(p: Policy, now: Long, scheduled: Boolean = false) {
        if (!Evaluator.screenLocked(p, now) || !isDeviceOwner()) return
        if (!scheduled && SystemClock.elapsedRealtime() < holdUntilMs) return
        if (!ctx.getSystemService(PowerManager::class.java).isInteractive) return
        if (ctx.getSystemService(KeyguardManager::class.java).isKeyguardLocked) return
        val mode = ctx.getSystemService(AudioManager::class.java).mode
        if (mode == AudioManager.MODE_IN_CALL || mode == AudioManager.MODE_RINGTONE || mode == AudioManager.MODE_CALL_SCREENING) {
            Log.i(TAG, "screen lock due, postponed: phone call (audio mode $mode)")
            return
        }
        // Due again at every check while the rule applies: a failure is reported once while it lasts.
        if (lockProblems.call("lock_screen_failed", "lockNow") { dpm.lockNow() } != null) Log.i(TAG, "screen locked by policy")
        lockProblems.end()
    }

    companion object {
        const val TAG = "kidctl"
    }
}
