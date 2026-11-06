package io.github.kidctl.agent

import org.json.JSONObject
import java.time.Instant
import java.time.ZoneId

/**
 * Same rules, same order as src/eval.rs (checked against spec/vectors.json):
 * blocked > always_allowed > unapproved > unlock > lock > downtime > limits > allowed.
 * Screen lock (device-wide, [screenLocked]): unlock > lock with screen > downtime with lock_screen.
 * Notifications ([notifyStep], same rules as eval::notify_step, vectors in
 * `notify_cases`): quota thresholds per limit, each at most once per day
 * (re-armed above the new percentage when extra time raises the budget), no
 * notice for an exhausted limit nor while unlock/lock/downtime is active; in
 * one step, of the limits due that count a same used app only the one with
 * the least time left notifies (tie: policy order), the others' thresholds
 * are spent; one notice per downtime start (pause and/or screen lock), none when an unlock
 * covers it.
 */
object Evaluator {
    const val ALLOWED = "allowed"

    /** (day of week Monday=0, minute of day) in the policy timezone. */
    fun local(p: Policy, now: Long): Pair<Int, Int> {
        val t = Instant.ofEpochSecond(now).atZone(ZoneId.of(p.timezone))
        return Pair(t.dayOfWeek.value - 1, t.hour * 60 + t.minute)
    }

    fun localDate(p: Policy, now: Long): String =
        Instant.ofEpochSecond(now).atZone(ZoneId.of(p.timezone)).toLocalDate().toString()

    private fun windowActive(w: Downtime, dow: Int, minute: Int): Boolean {
        val prev = (dow + 6) % 7
        return if (w.startMin < w.endMin) w.days[dow] && minute >= w.startMin && minute < w.endMin
        else (w.days[dow] && minute >= w.startMin) || (w.days[prev] && minute < w.endMin)
    }

    fun inDowntime(p: Policy, dow: Int, minute: Int): Boolean = p.downtime.any { windowActive(it, dow, minute) }

    /** Whether the screen itself must be locked now (same rules as eval::screen_locked). */
    fun screenLocked(p: Policy, now: Long): Boolean {
        val active = p.overrides.filter { it.activeAt(now) }
        if (active.any { it.kind == "unlock" }) return false
        if (active.any { it.kind == "lock" && it.screen }) return true
        val (dow, minute) = local(p, now)
        return p.downtime.any { it.lockScreen && windowActive(it, dow, minute) }
    }

    fun limitMatches(p: Policy, l: Limit, pkg: String): Boolean {
        if (pkg in p.alwaysAllowed || pkg in l.exclude) return false
        return l.wildcard || pkg in l.apps
    }

    fun limitUsed(p: Policy, l: Limit, usage: Map<String, Long>): Long =
        usage.entries.filter { limitMatches(p, l, it.key) }.sumOf { it.value }

    fun limitBudget(p: Policy, l: Limit, dow: Int, now: Long): Long =
        l.dailySecs[dow] + p.overrides
            .filter { it.kind == "extra" && it.activeAt(now) && (it.limit == null || it.limit == l.name) }
            .sumOf { it.secs }

    private fun namedInPolicy(p: Policy, pkg: String): Boolean =
        pkg in p.approved || pkg in p.alwaysAllowed || pkg in p.blocked || p.limits.any { pkg in it.apps }

    fun decide(p: Policy, now: Long, usage: Map<String, Long>, pkg: String, userInstalled: Boolean): String {
        if (pkg in p.blocked) return "blocked:blocked"
        if (pkg in p.alwaysAllowed) return ALLOWED
        if (p.approval && userInstalled && !namedInPolicy(p, pkg)) return "blocked:unapproved"
        val active = p.overrides.filter { it.activeAt(now) }
        if (active.any { it.kind == "unlock" }) return ALLOWED
        if (active.any { it.kind == "lock" }) return "blocked:lock"
        val (dow, minute) = local(p, now)
        if (inDowntime(p, dow, minute)) return "blocked:downtime"
        for (l in p.limits) {
            if (limitMatches(p, l, pkg) && limitUsed(p, l, usage) >= limitBudget(p, l, dow, now)) {
                return "blocked:limit:${l.name}"
            }
        }
        return ALLOWED
    }

    /** Highest threshold of [l]'s notifyAt reached by [used] out of [budget] (0: none). */
    fun quotaLevel(l: Limit, used: Long, budget: Long): Int {
        if (budget == 0L) return 0
        return l.notifyAt.filter { used * 100 >= it.toLong() * budget }.maxOrNull() ?: 0
    }

    private fun unlockAt(p: Policy, t: Long) = p.overrides.any { it.kind == "unlock" && it.activeAt(t) }

    /** (apps paused, screen locked by a lock_screen window) at [t]; nothing under an unlock. */
    private fun downtimeEffect(p: Policy, t: Long): Pair<Boolean, Boolean> {
        if (unlockAt(p, t)) return Pair(false, false)
        val (dow, minute) = local(p, t)
        return Pair(inDowntime(p, dow, minute), p.downtime.any { it.lockScreen && windowActive(it, dow, minute) })
    }

    /** A start of downtime: apps get paused ([pause]) and/or the screen locked ([lockScreen]) at [start]. */
    data class Upcoming(val start: Long, val pause: Boolean, val lockScreen: Boolean)

    /**
     * The first instant in (now, now + within] at which downtime starts pausing
     * apps and/or locking the screen. Candidates: minute boundaries and the end
     * of unlock overrides (same as eval::upcoming_downtime).
     */
    fun upcomingDowntime(p: Policy, now: Long, within: Long): Upcoming? {
        val end = now + within
        val candidates = mutableListOf<Long>()
        var m = (Math.floorDiv(now, 60L) + 1) * 60
        while (m <= end) {
            candidates += m
            m += 60
        }
        for (o in p.overrides) if (o.kind == "unlock" && now < o.until && o.until <= end) candidates += o.until
        candidates.sort()
        for (s in candidates) {
            val (paused, locked) = downtimeEffect(p, s)
            val (wasPaused, wasLocked) = downtimeEffect(p, s - 1)
            val pause = paused && !wasPaused
            val lock = locked && !wasLocked
            if (pause || lock) return Upcoming(s, pause, lock)
        }
        return null
    }

    /**
     * One evaluation of the notification rules: the notices due now and the
     * state to keep (persisted) for the next call. Same as eval::notify_step.
     */
    fun notifyStep(p: Policy, now: Long, usage: Map<String, Long>, prev: NotifyState): Pair<List<Notice>, NotifyState> {
        val n = p.notify ?: return Pair(emptyList(), prev)
        val date = localDate(p, now)
        val marks = if (prev.date == date) prev.limits.toMutableMap() else mutableMapOf()
        var downtimeStart = prev.downtimeStart
        val out = mutableListOf<Notice>()
        val (dow, minute) = local(p, now)
        val active = p.overrides.filter { it.activeAt(now) }
        val quiet = active.any { it.kind == "unlock" || it.kind == "lock" } || inDowntime(p, dow, minute)
        if (!quiet) {
            // Quota notices due now, in policy order, with their limit.
            val due = mutableListOf<Pair<Limit, Notice.Quota>>()
            for (l in p.limits) {
                if (l.notifyAt.isEmpty()) continue
                val used = limitUsed(p, l, usage)
                val budget = limitBudget(p, l, dow, now)
                val level = quotaLevel(l, used, budget)
                var mark = marks[l.name] ?: Mark(budget, 0)
                if (budget > mark.budget) mark = mark.copy(level = minOf(mark.level, level))
                mark = mark.copy(budget = budget)
                if (level > mark.level) {
                    if (used < budget) due += Pair(l, Notice.Quota(l.name, level, used, budget, budget - used))
                    mark = mark.copy(level = level)
                }
                marks[l.name] = mark
            }
            // Same tick, same app: only the most constraining limit speaks.
            fun shared(a: Limit, b: Limit) = usage.any { (pkg, s) -> s > 0 && limitMatches(p, a, pkg) && limitMatches(p, b, pkg) }
            for ((i, d) in due.withIndex()) {
                val (l, q) = d
                val dominated = due.withIndex().any { (j, o) ->
                    j != i && (o.second.remainingSecs < q.remainingSecs || (o.second.remainingSecs == q.remainingSecs && j < i)) &&
                        shared(o.first, l)
                }
                if (!dominated) out += q
            }
        }
        if (n.beforeDowntimeSecs > 0) {
            val up = upcomingDowntime(p, now, n.beforeDowntimeSecs)
            if (up != null && downtimeStart != up.start) {
                val t = Instant.ofEpochSecond(up.start).atZone(ZoneId.of(p.timezone))
                val hhmm = "${t.hour.toString().padStart(2, '0')}:${t.minute.toString().padStart(2, '0')}"
                out += Notice.Downtime(up.start, hhmm, up.start - now, up.pause, up.lockScreen)
                downtimeStart = up.start
            }
        }
        return Pair(out, NotifyState(date, marks, downtimeStart))
    }

    /**
     * Seconds until the foreground app [pkg] makes a limit reach its next
     * notification threshold (null: none ahead): to check right then.
     */
    fun secsToNextThreshold(p: Policy, now: Long, usage: Map<String, Long>, pkg: String): Long? {
        if (p.notify == null) return null
        val (dow, _) = local(p, now)
        return p.limits.filter { it.notifyAt.isNotEmpty() && limitMatches(p, it, pkg) }.flatMap { l ->
            val used = limitUsed(p, l, usage)
            val budget = limitBudget(p, l, dow, now)
            if (budget == 0L) emptyList()
            else l.notifyAt.map { (it * budget + 99) / 100 - used }.filter { it > 0 }
        }.minOrNull()
    }

    /**
     * Smallest remaining budget among the limits that apply to [pkg], in
     * seconds (Long.MAX_VALUE if none): used to schedule the next check while
     * that app is in the foreground.
     */
    fun remainingFor(p: Policy, now: Long, usage: Map<String, Long>, pkg: String): Long {
        val (dow, _) = local(p, now)
        return p.limits.filter { limitMatches(p, it, pkg) }
            .minOfOrNull { (limitBudget(p, it, dow, now) - limitUsed(p, it, usage)).coerceAtLeast(0) }
            ?: Long.MAX_VALUE
    }
}

/** A notification due (src/eval.rs `Notice`); [label] is the shared vectors' form. */
sealed class Notice {
    abstract fun label(): String

    data class Quota(val limit: String, val level: Int, val usedSecs: Long, val budgetSecs: Long, val remainingSecs: Long) : Notice() {
        override fun label() = "quota:$limit:$level:$remainingSecs"
    }

    /** [localStart]: HH:MM in the child's timezone; [inSecs]: until [start]. */
    data class Downtime(val start: Long, val localStart: String, val inSecs: Long, val pause: Boolean, val lockScreen: Boolean) : Notice() {
        override fun label() = "downtime:$localStart:$inSecs:" + when {
            pause && lockScreen -> "pause+lock"
            pause -> "pause"
            else -> "lock"
        }
    }
}

/** What was notified for one limit on [NotifyState.date]: budget then, highest threshold notified. */
data class Mark(val budget: Long, val level: Int)

/** Notification bookkeeping between two evaluations (persisted by State). */
data class NotifyState(
    /** Local date (YYYY-MM-DD) the marks belong to. */
    val date: String = "",
    val limits: Map<String, Mark> = emptyMap(),
    /** Start (epoch) of the last downtime noticed. */
    val downtimeStart: Long? = null,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("date", date)
        .put("limits", JSONObject().also { o -> limits.forEach { (k, m) -> o.put(k, JSONObject().put("budget", m.budget).put("level", m.level)) } })
        .put("downtime_start", downtimeStart ?: JSONObject.NULL)

    companion object {
        /** Unreadable or absent: a fresh state (at worst, today's notices again). */
        fun parse(s: String?): NotifyState = try {
            if (s == null) NotifyState() else JSONObject(s).let { o ->
                val l = o.getJSONObject("limits")
                NotifyState(
                    date = o.getString("date"),
                    limits = l.keyList().associateWith { k -> l.getJSONObject(k).let { Mark(it.getLong("budget"), it.getInt("level")) } },
                    downtimeStart = if (o.isNull("downtime_start")) null else o.getLong("downtime_start"),
                )
            }
        } catch (e: Exception) {
            NotifyState()
        }
    }
}
