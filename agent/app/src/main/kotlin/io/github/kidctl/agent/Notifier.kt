package io.github.kidctl.agent

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.util.Log
import java.time.Instant
import java.time.ZoneId

/**
 * Posts the child's screen-time notifications (policy `notify`): quota
 * thresholds and downtime notices, decided by [Evaluator.notifyStep]. One
 * notification per limit (a higher threshold replaces the previous one) and
 * one for downtime, on the "Temps d'écran" channel (normal importance).
 */
class Notifier(private val ctx: Context, private val state: State) {
    private val nm = ctx.getSystemService(NotificationManager::class.java)
    /** Whether "notifications blocked" was already reported in this process. */
    private var reportedBlocked = false

    fun step(p: Policy, now: Long, usage: Map<String, Long>) {
        val prev = state.notifyState
        val (notices, next) = Evaluator.notifyStep(p, now, usage, prev)
        // Saved (synchronously) before posting: a process killed in between
        // loses one notice rather than repeating it at every restart.
        if (next != prev) state.notifyState = next
        if (notices.isEmpty()) return
        val locale = p.notify?.locale ?: "fr"
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, Texts.channelName(locale), NotificationManager.IMPORTANCE_DEFAULT),
        )
        checkBlocked()
        for (n in notices) {
            val (title, text) = when (n) {
                is Notice.Quota -> Texts.quota(locale, n)
                is Notice.Downtime -> Texts.downtime(locale, n)
            }
            val id = when (n) {
                is Notice.Quota -> quotaId(n.limit)
                is Notice.Downtime -> DOWNTIME_ID
            }
            // Gone once moot: a quota notice at local midnight (new budget),
            // a downtime notice when the downtime starts.
            val expiresInMs = when (n) {
                is Notice.Quota -> Instant.ofEpochSecond(now).atZone(ZoneId.of(p.timezone)).toLocalDate().plusDays(1)
                    .atStartOfDay(ZoneId.of(p.timezone)).toEpochSecond().minus(now) * 1000
                is Notice.Downtime -> n.inSecs * 1000
            }
            val notification = Notification.Builder(ctx, CHANNEL)
                .setSmallIcon(if (n is Notice.Quota) android.R.drawable.ic_lock_idle_alarm else android.R.drawable.ic_lock_idle_lock)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(Notification.BigTextStyle().bigText(text))
                .setCategory(Notification.CATEGORY_REMINDER)
                .setShowWhen(true)
                .setAutoCancel(true)
                .setTimeoutAfter(expiresInMs.coerceAtLeast(1_000))
                .build()
            runCatching { nm.notify(id, notification) }
                .onSuccess {
                    Log.i(TAG, "notified ${n.label()}")
                    state.addEvent("notified", "${n.label()} $title")
                }
                .onFailure { state.addEvent("notify_failed", "${n.label()}: $it") }
        }
    }

    /** The child (or Android) turned the notifications off: tell the parents once per process. */
    private fun checkBlocked() {
        val why = when {
            !nm.areNotificationsEnabled() -> "app notifications off"
            nm.getNotificationChannel(CHANNEL)?.importance == NotificationManager.IMPORTANCE_NONE -> "channel $CHANNEL off"
            else -> null
        }
        if (why != null && !reportedBlocked) {
            Log.w(TAG, "notifications blocked: $why")
            state.addEvent("notify_blocked", why)
        }
        reportedBlocked = why != null
    }

    companion object {
        const val TAG = "kidctl"
        const val CHANNEL = "screen_time"
        /** EnforcerService's foreground notification uses id 1. */
        const val DOWNTIME_ID = 2

        /** Stable per limit name, never 1 or 2. */
        fun quotaId(limit: String): Int = ("quota:$limit".hashCode() and 0x3fffffff) or 0x40000000
    }
}
