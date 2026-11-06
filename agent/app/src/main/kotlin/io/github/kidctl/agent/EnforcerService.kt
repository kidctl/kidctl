package io.github.kidctl.agent

import android.app.KeyguardManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.SystemClock
import android.util.Log
import java.time.Instant
import java.time.ZoneId

/**
 * Foreground service: every tick, measure today's usage, evaluate the cached
 * policy, suspend/unsuspend apps; sync with the server every sync interval.
 * Works offline with the last policy received.
 */
class EnforcerService : Service() {
    private lateinit var thread: HandlerThread
    private lateinit var handler: Handler
    private lateinit var state: State
    private lateinit var enforcer: Enforcer
    private lateinit var updater: Updater
    private lateinit var notifier: Notifier
    private var lastDeviceVersion = ""

    private val pkgReceiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) {
            // A new/updated app must be evaluated right away (approval, blocked list).
            // Device settings that name packages (default apps, hidden, VPN...) are
            // re-applied too: the package may only now be installed or gone.
            val pkgChange = i.data?.scheme == "package"
            handler.post {
                if (pkgChange) lastDeviceVersion = ""
                tick(forceSync = true)
            }
        }
    }

    /** Screen-lock checks after screen events; own Handler so tick() cannot cancel them. */
    private lateinit var screenHandler: Handler

    /**
     * Screen on / keyguard dismissed: check the screen lock once things settle
     * (periodic checks hold off until then; a hold is never shortened).
     * - SCREEN_ON: after 1.5 s. It arrives before the keyguard is displayed;
     *   locking right away would turn the screen off before the lock screen
     *   (and its emergency-call button) can be reached. A phone that woke up
     *   unlocked is locked then.
     * - USER_PRESENT (the child unlocked): with a PIN / pattern / password,
     *   after 1 s (the dismiss animation: locking during it can leave the phone
     *   asleep without a keyguard); emergency calls go through the bouncer's
     *   button, during which the keyguard still counts as locked. Without one
     *   (Swipe or None) there is no such button and unlocking is a swipe or
     *   nothing at all: wait 15 s, enough to start an emergency call from the
     *   dialer (never locked during a call).
     */
    private val screenReceiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) {
            val at = SystemClock.elapsedRealtime()
            handler.post {
                val wait = when {
                    i.action == Intent.ACTION_SCREEN_ON -> 1_500L
                    getSystemService(KeyguardManager::class.java).isDeviceSecure -> 1_000L
                    else -> INSECURE_UNLOCK_GRACE_MS
                }
                val until = maxOf(enforcer.holdUntilMs, at + wait)
                enforcer.holdUntilMs = until
                screenHandler.removeCallbacksAndMessages(null)
                screenHandler.postDelayed({ checkScreenLock() }, (until - SystemClock.elapsedRealtime()).coerceAtLeast(0))
            }
        }
    }

    private fun checkScreenLock() {
        try {
            state.loadPolicy()?.let { enforcer.enforceScreenLock(it, System.currentTimeMillis() / 1000, scheduled = true) }
        } catch (e: Exception) {
            Log.e(TAG, "screen lock check failed", e)
        }
    }

    override fun onCreate() {
        super.onCreate()
        state = State(this)
        enforcer = Enforcer(this, state)
        updater = Updater(this, state)
        notifier = Notifier(this, state)
        Updater.cleanup(this)
        state.lastVersionCode = updater.installedVersionCode()
        thread = HandlerThread("kidctl").also { it.start() }
        handler = Handler(thread.looper)
        screenHandler = Handler(thread.looper)
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "kidctl", NotificationManager.IMPORTANCE_MIN))
        val n = Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentTitle("Contrôle parental actif")
            .setOngoing(true)
            .build()
        startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        registerReceiver(pkgReceiver, IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addDataScheme("package")
        })
        registerReceiver(pkgReceiver, IntentFilter(Intent.ACTION_TIME_CHANGED).apply {
            addAction(Intent.ACTION_TIMEZONE_CHANGED)
            addAction(Intent.ACTION_DATE_CHANGED)
        })
        registerReceiver(screenReceiver, IntentFilter(Intent.ACTION_USER_PRESENT).apply {
            addAction(Intent.ACTION_SCREEN_ON)
        })
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        handler.removeCallbacksAndMessages(null)
        handler.post { tick(forceSync = true) }
        return START_STICKY
    }

    override fun onDestroy() {
        unregisterReceiver(pkgReceiver)
        unregisterReceiver(screenReceiver)
        thread.quitSafely()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun tick(forceSync: Boolean = false) {
        handler.removeCallbacksAndMessages(null)
        var delayMs = 30_000L
        try {
            val nowMs = System.currentTimeMillis()
            var policy = state.loadPolicy()
            val due = nowMs - state.lastSyncMs >= state.syncIntervalSecs * 1000
            if (policy == null || due || forceSync) {
                val (date, usage, _) = measure(policy, nowMs)
                val apps = enforcer.launchableApps()
                val deviceOwner = enforcer.isDeviceOwner()
                val r = Sync.run(state, versionName(), updater.installedVersionCode(), Build.VERSION.SDK_INT, deviceOwner, date, usage, apps)
                state.lastSyncMs = nowMs
                if (r.error != null) {
                    Log.w(TAG, "sync: ${r.error}")
                    state.lastError = "sync: ${r.error}"
                }
                // Self-update before any policy handling, which must not be able to block it.
                try {
                    updater.maybeStart(deviceOwner)
                } catch (e: Exception) {
                    Log.e(TAG, "update check failed", e)
                    state.lastError = "update: $e"
                }
                if (r.newPolicy) policy = state.loadPolicy()
            }
            if (policy != null) {
                val (_, own, fg) = measure(policy, nowMs)
                val total = HashMap(own)
                if (state.otherUsageDate == Evaluator.localDate(policy, nowMs / 1000)) {
                    state.otherUsage.forEach { (k, v) -> total[k] = (total[k] ?: 0L) + v }
                }
                if (state.policyVersion != lastDeviceVersion) {
                    enforcer.enforceDevice(policy)
                    lastDeviceVersion = state.policyVersion
                }
                enforcer.enforceApps(policy, nowMs / 1000, total)
                enforcer.enforceScreenLock(policy, nowMs / 1000)
                try {
                    notifier.step(policy, nowMs / 1000, total)
                } catch (e: Exception) {
                    Log.e(TAG, "notifications failed", e)
                    state.addEvent("notify_failed", e.toString().take(300))
                }
                // Re-check sooner when the app in front is about to run out,
                // or about to reach a notification threshold.
                if (fg != null) {
                    val rem = Evaluator.remainingFor(policy, nowMs / 1000, total, fg)
                    if (rem < 30) delayMs = (rem * 1000).coerceAtLeast(5_000)
                    Evaluator.secsToNextThreshold(policy, nowMs / 1000, total, fg)?.let {
                        if (it * 1000 < delayMs) delayMs = (it * 1000).coerceAtLeast(1_000)
                    }
                }
                // And when a downtime notice falls due before the next check.
                policy.notify?.beforeDowntimeSecs?.takeIf { it > 0 }?.let { before ->
                    val now = nowMs / 1000
                    Evaluator.upcomingDowntime(policy, now, before + delayMs / 1000)?.let { up ->
                        val due = up.start - before - now
                        if (due > 0 && due * 1000 < delayMs) delayMs = due * 1000
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "tick failed", e)
            state.lastError = "tick: $e"
            state.addEvent("error", e.toString().take(300))
        }
        handler.postDelayed({ tick() }, delayMs)
    }

    private fun versionName(): String = packageManager.getPackageInfo(packageName, 0).versionName ?: "?"

    /** (local date, own usage today, foreground package). */
    private fun measure(policy: Policy?, nowMs: Long): Triple<String, Map<String, Long>, String?> {
        val zone = ZoneId.of(policy?.timezone ?: ZoneId.systemDefault().id)
        val day = Instant.ofEpochMilli(nowMs).atZone(zone).toLocalDate()
        val start = day.atStartOfDay(zone).toInstant().toEpochMilli()
        val ex = enforcer.exempt()
        val u = Usage.today(this, start, nowMs)
        return Triple(day.toString(), u.secs.filterKeys { it !in ex }, u.foreground?.takeIf { it !in ex })
    }

    companion object {
        const val TAG = "kidctl"
        const val CHANNEL = "kidctl"
        /** Unlocked without PIN/pattern/password (no emergency button): time to start an emergency call. */
        const val INSECURE_UNLOCK_GRACE_MS = 15_000L

        fun start(ctx: Context) {
            ctx.startForegroundService(Intent(ctx, EnforcerService::class.java))
        }
    }
}

