package io.github.kidctl.agent

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UserControlTest {
    private val me = "io.github.kidctl.agent"

    @Test
    fun theAgentIsAlwaysProtected() {
        assertEquals(listOf(me), UserControl.wanted(me, emptyList()))
        assertEquals(listOf(me, "com.tailscale.ipn"), UserControl.wanted(me, listOf("com.tailscale.ipn")))
        // Listing the agent itself (or a package twice) changes nothing.
        assertEquals(listOf(me, "com.tailscale.ipn"), UserControl.wanted(me, listOf("com.tailscale.ipn", me, "com.tailscale.ipn")))
    }

    @Test
    fun readBackDifferences() {
        val want = UserControl.wanted(me, listOf("com.a.b"))
        assertTrue(UserControl.same(want, listOf("com.a.b", me)))
        assertFalse(UserControl.same(want, listOf(me)))
        assertEquals(listOf("com.a.b"), UserControl.missing(want, listOf(me)))
        assertEquals(emptyList<String>(), UserControl.missing(want, listOf("com.a.b", me)))
        // A package dropped from the policy that Android still has.
        assertEquals(listOf("com.old.app"), UserControl.extra(listOf(me), listOf(me, "com.old.app")))
    }

    @Test
    fun parsedFromTheWireFormat() {
        val d = DeviceConfig.parse(JSONObject("""{"user_control_disabled":["com.tailscale.ipn","com.a.b"]}"""))
        assertEquals(listOf("com.tailscale.ipn", "com.a.b"), d.userControlDisabled)
        // Older servers / policies without the field.
        assertEquals(emptyList<String>(), DeviceConfig.parse(JSONObject("{}")).userControlDisabled)
    }
}
