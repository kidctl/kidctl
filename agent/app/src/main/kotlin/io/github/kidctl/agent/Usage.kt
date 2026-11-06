package io.github.kidctl.agent

import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context

/** One usage event, decoupled from Android for unit tests. Times in ms. */
data class Ev(val ts: Long, val type: Int, val pkg: String, val cls: String = "")

data class UsageResult(val secs: Map<String, Long>, val foreground: String?)

object Usage {
    // android.app.usage.UsageEvents.Event constants (stable since API 29).
    const val RESUMED = 1
    const val PAUSED = 2
    const val SCREEN_INTERACTIVE = 15
    const val SCREEN_NON_INTERACTIVE = 16
    const val KEYGUARD_SHOWN = 17
    const val STOPPED = 23
    const val DEVICE_SHUTDOWN = 26

    /**
     * Foreground seconds per package inside [startMs, endMs). Events may begin
     * before startMs (to know what was in front at midnight); intervals are
     * clipped. An app still in front at endMs counts until endMs.
     */
    fun foreground(events: List<Ev>, startMs: Long, endMs: Long): UsageResult {
        val acc = HashMap<String, Long>()
        // Resumed (not yet paused) activities per package, counted per class:
        // an app switching between its own activities may report RESUMED(new)
        // before PAUSED(old), also for a new instance of the same class, and
        // usage events carry no public instance id.
        val resumed = HashMap<String, HashMap<String, Int>>()
        var cur: String? = null
        var since = 0L
        fun close(at: Long) {
            val c = cur ?: return
            val a = maxOf(since, startMs)
            val b = minOf(at, endMs)
            if (b > a) acc[c] = (acc[c] ?: 0L) + (b - a)
            cur = null
        }
        for (e in events.sortedBy { it.ts }) {
            if (e.ts >= endMs) break
            when (e.type) {
                RESUMED -> {
                    val m = resumed.getOrPut(e.pkg) { HashMap() }
                    m[e.cls] = (m[e.cls] ?: 0) + 1
                    if (cur != e.pkg) {
                        close(e.ts)
                        cur = e.pkg
                        since = e.ts
                    }
                }
                PAUSED -> {
                    val m = resumed[e.pkg]
                    if (m != null) {
                        val n = (m[e.cls] ?: 0) - 1
                        if (n > 0) m[e.cls] = n else m.remove(e.cls)
                    }
                    if (cur == e.pkg && m.isNullOrEmpty()) close(e.ts)
                }
                // STOPPED is ignored: an activity always reports PAUSED before
                // STOPPED, and the STOPPED of an old instance can arrive after a
                // new instance of the same class was resumed (an app relaunching
                // its main activity after a permission dialog): closing on it
                // stopped counting an app that was in front.
                SCREEN_NON_INTERACTIVE, KEYGUARD_SHOWN, DEVICE_SHUTDOWN -> {
                    close(e.ts)
                    resumed.clear()
                }
            }
        }
        val fg = cur
        close(endMs)
        return UsageResult(acc.mapValues { it.value / 1000 }.filterValues { it > 0 }, fg)
    }

    /** Read today's events from the system (needs the GET_USAGE_STATS appop). */
    fun today(ctx: Context, startMs: Long, nowMs: Long): UsageResult {
        val usm = ctx.getSystemService(UsageStatsManager::class.java)
        // Look back 6 h before midnight to learn what was in front at midnight.
        val it = usm.queryEvents(startMs - 6 * 3600_000L, nowMs)
        val ev = UsageEvents.Event()
        val list = ArrayList<Ev>()
        while (it.hasNextEvent()) {
            it.getNextEvent(ev)
            list += Ev(ev.timeStamp, ev.eventType, ev.packageName ?: "", ev.className ?: "")
        }
        return foreground(list, startMs, nowMs)
    }
}
