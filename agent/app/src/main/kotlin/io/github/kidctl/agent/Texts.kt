package io.github.kidctl.agent

/**
 * Texts of the notifications shown to the child (policy `notify.locale`: fr
 * or en; anything else falls back to fr). French typography: no-break space
 * (U+00A0) before ":" and "%", between a number and its unit; typographic
 * apostrophe.
 */
object Texts {
    const val NBSP = " "

    private fun en(locale: String) = locale == "en"

    fun channelName(locale: String) = if (en(locale)) "Screen time" else "Temps d’écran"

    private fun limitName(name: String) = name.replaceFirstChar { it.titlecase() }

    /** Remaining time: "6 min", "1 h 05", "2 h" (fr) / "6 min", "1 h 05 min", "2 h" (en); null under a minute. */
    private fun left(locale: String, secs: Long): String? {
        val min = secs / 60
        if (min < 1) return null
        if (min < 60) return "$min${NBSP}min"
        val h = min / 60
        val m = min % 60
        return when {
            m == 0L -> "$h${NBSP}h"
            en(locale) -> "$h${NBSP}h $m${NBSP}min"
            else -> "$h${NBSP}h$NBSP${m.toString().padStart(2, '0')}"
        }
    }

    /** (title, text) of a quota notice. From 90 % up the text is more pressing. */
    fun quota(locale: String, q: Notice.Quota): Pair<String, String> {
        val name = limitName(q.limit)
        val left = left(locale, q.remainingSecs)
        val urgent = q.level >= 90
        return if (en(locale)) {
            Pair(
                "$name: ${q.level}% used",
                when {
                    left == null -> "Less than 1${NBSP}min left today."
                    urgent -> "Only $left left today."
                    else -> "$left left today."
                },
            )
        } else {
            Pair(
                "$name$NBSP: ${q.level}$NBSP% utilisé",
                when {
                    left == null -> "Il reste moins d’1${NBSP}min aujourd’hui."
                    urgent -> "Plus que $left aujourd’hui."
                    else -> "Il reste $left aujourd’hui."
                },
            )
        }
    }

    /** (title, text) of a downtime notice; minutes rounded up ("dans 5 min" from 4 min 01 s). */
    fun downtime(locale: String, d: Notice.Downtime): Pair<String, String> {
        val inMin = "${maxOf(1L, (d.inSecs + 59) / 60)}${NBSP}min"
        return if (en(locale)) {
            when {
                d.pause && d.lockScreen -> Pair("Downtime at ${d.localStart}", "The phone pauses and the screen locks in $inMin.")
                d.pause -> Pair("Downtime at ${d.localStart}", "The phone pauses in $inMin.")
                else -> Pair("Screen lock at ${d.localStart}", "The screen locks in $inMin.")
            }
        } else {
            when {
                d.pause && d.lockScreen -> Pair("Pause à ${d.localStart}", "Le téléphone se met en pause et l’écran se verrouille dans $inMin.")
                d.pause -> Pair("Pause à ${d.localStart}", "Le téléphone se met en pause dans $inMin.")
                else -> Pair("Verrouillage à ${d.localStart}", "L’écran se verrouille dans $inMin.")
            }
        }
    }
}
