package io.github.kidctl.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TextsTest {
    private val n = " "
    private fun q(level: Int, remaining: Long, limit: String = "social") = Notice.Quota(limit, level, 0, 0, remaining)
    private fun d(inSecs: Long, pause: Boolean, lock: Boolean) = Notice.Downtime(0, "22:00", inSecs, pause, lock)

    @Test
    fun quotaFrench() {
        assertEquals(Pair("Social$n: 50$n% utilisé", "Il reste 15${n}min aujourd’hui."), Texts.quota("fr", q(50, 900)))
        assertEquals(Pair("Social$n: 80$n% utilisé", "Il reste 6${n}min aujourd’hui."), Texts.quota("fr", q(80, 360)))
        assertEquals(Pair("Social$n: 95$n% utilisé", "Plus que 2${n}min aujourd’hui."), Texts.quota("fr", q(95, 150)))
        assertEquals("Il reste moins d’1${n}min aujourd’hui.", Texts.quota("fr", q(95, 59)).second)
        assertEquals("Il reste 1${n}h${n}05 aujourd’hui.", Texts.quota("fr", q(50, 3900)).second)
        assertEquals("Il reste 2${n}h aujourd’hui.", Texts.quota("fr", q(50, 7200)).second)
        assertEquals("General$n: 50$n% utilisé", Texts.quota("fr", q(50, 1800, "general")).first)
        // Unknown locale: French.
        assertEquals(Texts.quota("fr", q(80, 360)), Texts.quota("de", q(80, 360)))
    }

    @Test
    fun quotaEnglish() {
        assertEquals(Pair("Social: 50% used", "15${n}min left today."), Texts.quota("en", q(50, 900)))
        assertEquals(Pair("Social: 95% used", "Only 2${n}min left today."), Texts.quota("en", q(95, 150)))
        assertEquals("Less than 1${n}min left today.", Texts.quota("en", q(80, 30)).second)
        assertEquals("1${n}h 5${n}min left today.", Texts.quota("en", q(50, 3900)).second)
    }

    @Test
    fun downtime() {
        assertEquals(Pair("Pause à 22:00", "Le téléphone se met en pause dans 5${n}min."), Texts.downtime("fr", d(300, true, false)))
        assertEquals(Pair("Pause à 22:00", "Le téléphone se met en pause dans 5${n}min."), Texts.downtime("fr", d(241, true, false)))
        assertEquals("Le téléphone se met en pause dans 1${n}min.", Texts.downtime("fr", d(5, true, false)).second)
        assertEquals(
            Pair("Pause à 22:00", "Le téléphone se met en pause et l’écran se verrouille dans 3${n}min."),
            Texts.downtime("fr", d(180, true, true)),
        )
        assertEquals(Pair("Verrouillage à 22:00", "L’écran se verrouille dans 5${n}min."), Texts.downtime("fr", d(300, false, true)))
        assertEquals(Pair("Downtime at 22:00", "The phone pauses in 5${n}min."), Texts.downtime("en", d(300, true, false)))
        assertEquals(Pair("Downtime at 22:00", "The phone pauses and the screen locks in 3${n}min."), Texts.downtime("en", d(180, true, true)))
        assertEquals(Pair("Screen lock at 22:00", "The screen locks in 5${n}min."), Texts.downtime("en", d(300, false, true)))
    }

    @Test
    fun channelAndIds() {
        assertEquals("Temps d’écran", Texts.channelName("fr"))
        assertEquals("Screen time", Texts.channelName("en"))
        for (name in listOf("social", "general", "video", "audio", "x")) {
            val id = Notifier.quotaId(name)
            assertTrue(name, id != 1 && id != Notifier.DOWNTIME_ID && id > 0 && id == Notifier.quotaId(name))
        }
    }
}
