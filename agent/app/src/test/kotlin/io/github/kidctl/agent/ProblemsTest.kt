package io.github.kidctl.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProblemsTest {
    private val events = mutableListOf<Pair<String, String>>()
    private val p = Problems { k, d -> events += k to d }

    @Test
    fun eachProblemReportedOnceWhileItLasts() {
        p.add("hide_failed", "a")
        p.add("hide_failed", "a")
        p.add("camera_failed", "x")
        p.end()
        assertEquals(listOf("hide_failed" to "a", "camera_failed" to "x"), events)
        // Still there at the next pass: not again; a new one is.
        p.add("hide_failed", "a")
        p.add("hide_failed", "b")
        p.end()
        assertEquals(listOf("hide_failed" to "a", "camera_failed" to "x", "hide_failed" to "b"), events)
        // Gone for a pass, then back: reported again.
        p.end()
        p.add("hide_failed", "a")
        p.end()
        assertEquals("hide_failed" to "a", events.last())
        assertEquals(4, events.size)
    }

    @Test
    fun callRecordsWhatThrew() {
        assertEquals(3, p.call("vpn_failed", "com.x") { 3 })
        assertNull(p.call<Unit>("vpn_failed", "com.x") { throw IllegalStateException("no such package") })
        // A call returning null is not a failure.
        assertNull(p.call<String?>("vpn_failed", "com.y") { null })
        p.end()
        assertEquals(listOf("vpn_failed" to "com.x: java.lang.IllegalStateException: no such package"), events)
    }

    @Test
    fun verifyReportsWhatIsNotThereWhenReadBack() {
        assertTrue(p.verify("camera_failed", "setCameraDisabled(true)") { true })
        assertFalse(p.verify("camera_failed", "setCameraDisabled(true)") { false })
        assertFalse(p.verify("uninstall_block_failed", "com.x", "isUninstallBlocked is false") { false })
        assertFalse(p.verify("hide_failed", "com.y") { throw SecurityException("nope") })
        p.end()
        assertEquals(
            listOf(
                "camera_failed" to "setCameraDisabled(true): not applied (read back differs)",
                "uninstall_block_failed" to "com.x: isUninstallBlocked is false",
                "hide_failed" to "com.y: read back: java.lang.SecurityException: nope",
            ),
            events,
        )
    }

    @Test
    fun longDetailsAreCut() {
        p.add("error", "x".repeat(1000))
        p.end()
        assertEquals(Problems.MAX_DETAIL, events.single().second.length)
    }
}
