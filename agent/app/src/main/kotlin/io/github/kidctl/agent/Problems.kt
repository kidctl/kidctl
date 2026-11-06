package io.github.kidctl.agent

/**
 * Enforcement problems of one pass (a device-policy call that threw, returned
 * an error, or whose effect is not there when read back), each reported once
 * while it lasts: a problem found again at the next pass is not reported
 * again, one that went away and comes back is. Passes re-run on every policy
 * change and package change: without this a lasting failure would be
 * reported at each of them. [report] gets (event kind, detail).
 */
class Problems(private val report: (String, String) -> Unit) {
    private var reported: Set<Pair<String, String>> = emptySet()
    private val found = linkedSetOf<Pair<String, String>>()

    fun add(kind: String, detail: String) {
        found += kind to detail.take(MAX_DETAIL)
    }

    /** [block], or null after recording a problem `[kind] "[what]: <exception>"` if it throws. */
    fun <T> call(kind: String, what: String, block: () -> T): T? = try {
        block()
    } catch (e: Exception) {
        add(kind, "$what: $e")
        null
    }

    /**
     * After applying: [read] the setting back; false (or a throw) is a problem
     * `[kind] "[what]: [notApplied]"`. Returns whether it holds.
     */
    fun verify(kind: String, what: String, notApplied: String = "not applied (read back differs)", read: () -> Boolean): Boolean {
        val ok = call(kind, "$what: read back") { read() } ?: return false
        if (!ok) add(kind, "$what: $notApplied")
        return ok
    }

    /** End of the pass: report what is new, forget what went away. */
    fun end() {
        for ((kind, detail) in found - reported) report(kind, detail)
        reported = found.toSet()
        found.clear()
    }

    companion object {
        const val MAX_DETAIL = 300
    }
}
