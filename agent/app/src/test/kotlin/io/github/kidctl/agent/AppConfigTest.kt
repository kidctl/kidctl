package io.github.kidctl.agent

import io.github.kidctl.agent.Declared.Type
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppConfigTest {
    private fun ok(d: Declared, v: Any): Any = (AppConfig.coerce(d, v) as AppConfig.Coerced.Ok).value
    private fun bad(d: Declared, v: Any): String = (AppConfig.coerce(d, v) as AppConfig.Coerced.Bad).why

    private val bool = Declared("ForceEnabled", Type.BOOLEAN)
    private val int = Declared("MaxRetries", Type.INTEGER)
    private val str = Declared("Hostname", Type.STRING)
    private val hidden = Declared("Hidden", Type.HIDDEN)
    private val choice = Declared("UseTailscaleDNSSettings", Type.CHOICE, listOf("always", "never", "user-decides"))
    private val multi = Declared("Features", Type.MULTI_SELECT, listOf("a", "b", "c"))

    @Test
    fun coercesToTheDeclaredType() {
        assertEquals(true, ok(bool, true))
        assertEquals(false, ok(bool, "False"))
        assertEquals(3, ok(int, 3))
        assertEquals(-2147483648, ok(int, -2147483648L))
        assertEquals(42, ok(int, " 42 "))
        assertEquals("kid-phone", ok(str, "kid-phone"))
        assertEquals("1234", ok(str, 1234))
        assertEquals("true", ok(str, true))
        assertEquals("x", ok(hidden, "x"))
        assertEquals("always", ok(choice, "always"))
        // No declared values: any scalar.
        assertEquals("7", ok(Declared("C", Type.CHOICE), 7))
        assertArrayEquals(arrayOf("a", "c"), ok(multi, listOf("a", "c")) as Array<*>)
        assertArrayEquals(arrayOf("b"), ok(multi, "b") as Array<*>)
        assertArrayEquals(arrayOf<String>(), ok(multi, emptyList<String>()) as Array<*>)
    }

    @Test
    fun wrongTypesAreRefusedWithTheReason() {
        assertEquals("bool restriction expects true or false, got an integer 1", bad(bool, 1))
        assertEquals("bool restriction expects true or false, got a string \"yes\"", bad(bool, "yes"))
        assertEquals("integer restriction expects a 32-bit integer, got a string \"three\"", bad(int, "three"))
        assertEquals("integer restriction expects a 32-bit integer, got an integer 2147483648", bad(int, 2147483648L))
        assertEquals("integer restriction expects a 32-bit integer, got a boolean true", bad(int, true))
        assertEquals("string restriction expects a string, got a list [a]", bad(str, listOf("a")))
        assertEquals("choice restriction: \"sometimes\" is not one of [always, never, user-decides]", bad(choice, "sometimes"))
        assertEquals("choice restriction: \"true\" is not one of [always, never, user-decides]", bad(choice, true))
        assertEquals("choice restriction expects one of [always, never, user-decides], got a list [always]", bad(choice, listOf("always")))
        assertEquals("multi-select restriction: [d] not among [a, b, c]", bad(multi, listOf("a", "d")))
        assertEquals("bundle restrictions are not supported by kidctl", bad(Declared("B", Type.BUNDLE), "x"))
        assertEquals("bundle_array restrictions are not supported by kidctl", bad(Declared("B", Type.BUNDLE_ARRAY), "x"))
        assertEquals("integer restriction expects a 32-bit integer, got a Double 1.5", bad(int, 1.5))
    }

    @Test
    fun secretValuesAreNeverShown() {
        val key = Declared("AuthKey", Type.INTEGER)
        assertEquals("integer restriction expects a 32-bit integer, got a string <redacted>", bad(key, "tskey-auth-123"))
        assertEquals(
            "AuthKey=<redacted>, Hostname=\"p\", Level=3, List=[a, b], On=true, Password=<redacted>",
            AppConfig.describe(mapOf("On" to true, "Hostname" to "p", "AuthKey" to "tskey", "Level" to 3, "List" to arrayOf("a", "b"), "Password" to "x")),
        )
        assertEquals("(none)", AppConfig.describe(emptyMap()))
    }

    @Test
    fun planSetsWhatItCanAndSaysWhyForTheRest() {
        val declared = listOf(bool, int, str, choice, multi)
        val want = mapOf(
            "ForceEnabled" to true, "Hostname" to "kid-phone", "UseTailscaleDNSSettings" to "always",
            "MaxRetries" to "x", "hostName" to "y", "Nope" to 1,
        )
        val plan = AppConfig.plan(declared, want)
        assertEquals(listOf("ForceEnabled", "Hostname", "UseTailscaleDNSSettings"), plan.values.keys.toList())
        assertEquals(
            mapOf(
                "MaxRetries" to "integer restriction expects a 32-bit integer, got a string \"x\"",
                "Nope" to "not declared by the app",
                "hostName" to "not declared by the app (did you mean Hostname?)",
            ),
            plan.problems,
        )
        // Nothing declared at all: every key refused.
        assertEquals(setOf("A"), AppConfig.plan(emptyList(), mapOf("A" to true)).problems.keys)
    }

    @Test
    fun sameComparesArraysByContent() {
        val want = mapOf<String, Any>("A" to true, "L" to arrayOf("a", "b"), "N" to 3)
        assertTrue(AppConfig.same(mapOf("A" to true, "L" to arrayOf("a", "b"), "N" to 3), want))
        assertFalse(AppConfig.same(mapOf("A" to true, "L" to arrayOf("b", "a"), "N" to 3), want))
        assertFalse(AppConfig.same(mapOf("A" to true, "L" to arrayOf("a", "b")), want))
        assertFalse(AppConfig.same(mapOf("A" to "true", "L" to arrayOf("a", "b"), "N" to 3), want))
        assertFalse(AppConfig.same(mapOf("A" to true, "L" to arrayOf("a", "b"), "N" to 3, "X" to null), want))
        assertTrue(AppConfig.same(emptyMap(), emptyMap()))
    }

    @Test
    fun policyParsesAppConfigAndOlderPoliciesHaveNone() {
        val d = DeviceConfig.parse(JSONObject(
            """{"app_config": {"com.tailscale.ipn": {"ForceEnabled": true, "MaxRetries": 3, "Hostname": "p", "Features": ["a", "b"]}}}""",
        ))
        assertEquals(
            mapOf("com.tailscale.ipn" to mapOf("ForceEnabled" to true, "MaxRetries" to 3, "Hostname" to "p", "Features" to listOf("a", "b"))),
            d.appConfig,
        )
        assertEquals(emptyMap<String, Map<String, Any>>(), DeviceConfig.parse(JSONObject("{}")).appConfig)
    }
}
