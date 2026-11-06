package io.github.kidctl.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class UsageTest {
    private val m = 60_000L

    @Test
    fun countsResumedToPaused() {
        val r = Usage.foreground(
            listOf(
                Ev(10 * m, Usage.RESUMED, "a"), Ev(25 * m, Usage.PAUSED, "a"), Ev(25 * m, Usage.STOPPED, "a"),
                Ev(30 * m, Usage.RESUMED, "b"), Ev(31 * m, Usage.PAUSED, "b"), Ev(31 * m, Usage.STOPPED, "b"),
            ),
            0, 100 * m,
        )
        assertEquals(mapOf("a" to 900L, "b" to 60L), r.secs)
        assertNull(r.foreground)
    }

    @Test
    fun switchingAppsClosesPrevious() {
        val r = Usage.foreground(listOf(Ev(0, Usage.RESUMED, "a"), Ev(5 * m, Usage.RESUMED, "b")), 0, 10 * m)
        assertEquals(mapOf("a" to 300L, "b" to 300L), r.secs)
        assertEquals("b", r.foreground)
    }

    @Test
    fun clipsAtMidnightAndNow() {
        // App opened 20 min before "midnight" (start = 60m), still open at now = 70m.
        val r = Usage.foreground(listOf(Ev(40 * m, Usage.RESUMED, "a")), 60 * m, 70 * m)
        assertEquals(mapOf("a" to 600L), r.secs)
    }

    @Test
    fun screenOffStopsCounting() {
        val r = Usage.foreground(
            listOf(Ev(0, Usage.RESUMED, "a"), Ev(2 * m, Usage.SCREEN_NON_INTERACTIVE, "android"), Ev(50 * m, Usage.PAUSED, "a")),
            0, 60 * m,
        )
        assertEquals(mapOf("a" to 120L), r.secs)
    }

    @Test
    fun pauseOfOtherAppIgnored() {
        val r = Usage.foreground(listOf(Ev(0, Usage.RESUMED, "a"), Ev(m, Usage.PAUSED, "b")), 0, 3 * m)
        assertEquals(mapOf("a" to 180L), r.secs)
    }

    @Test
    fun activitySwitchInsideAppKeepsCounting() {
        // Chrome: RESUMED(FirstRun) arrives before PAUSED(Tabbed), same timestamp.
        val r = Usage.foreground(
            listOf(
                Ev(0, Usage.RESUMED, "c", "Tabbed"),
                Ev(0, Usage.RESUMED, "c", "FirstRun"),
                Ev(0, Usage.PAUSED, "c", "Tabbed"),
                Ev(25_000, Usage.PAUSED, "c", "FirstRun"),
            ),
            0, 60_000,
        )
        assertEquals(mapOf("c" to 25L), r.secs)
    }

    @Test
    fun staleStopOfSameClassKeepsCounting() {
        // Contacts' first launch, as recorded on the API 37 emulator (all at the
        // same second): People -> its permission activity -> the permission
        // controller -> a NEW People instance; then the STOPPED events of the
        // old instances arrive. The app is in front from then on.
        val r = Usage.foreground(
            listOf(
                Ev(0, Usage.PAUSED, "launcher", "Nexus"),
                Ev(0, Usage.RESUMED, "contacts", "People"),
                Ev(0, Usage.PAUSED, "contacts", "People"),
                Ev(0, Usage.RESUMED, "contacts", "RequestPermissions"),
                Ev(0, Usage.PAUSED, "contacts", "RequestPermissions"),
                Ev(0, Usage.RESUMED, "permissioncontroller", "GrantPermissions"),
                Ev(0, Usage.PAUSED, "permissioncontroller", "GrantPermissions"),
                Ev(0, Usage.RESUMED, "contacts", "People"),
                Ev(0, Usage.STOPPED, "permissioncontroller", "GrantPermissions"),
                Ev(0, Usage.STOPPED, "contacts", "People"),
                Ev(0, Usage.STOPPED, "launcher", "Nexus"),
                Ev(0, Usage.STOPPED, "contacts", "RequestPermissions"),
            ),
            0, 90_000,
        )
        assertEquals(mapOf("contacts" to 90L), r.secs)
        assertEquals("contacts", r.foreground)
    }

    @Test
    fun newInstanceOfSameClassBeforeOldPauses() {
        // An activity starting a new instance of itself: RESUMED(new) before PAUSED(old).
        val r = Usage.foreground(
            listOf(
                Ev(0, Usage.RESUMED, "a", "Main"),
                Ev(10_000, Usage.RESUMED, "a", "Main"),
                Ev(10_000, Usage.PAUSED, "a", "Main"),
                Ev(10_000, Usage.STOPPED, "a", "Main"),
                Ev(40_000, Usage.PAUSED, "a", "Main"),
            ),
            0, 60_000,
        )
        assertEquals(mapOf("a" to 40L), r.secs)
        assertNull(r.foreground)
    }
}
