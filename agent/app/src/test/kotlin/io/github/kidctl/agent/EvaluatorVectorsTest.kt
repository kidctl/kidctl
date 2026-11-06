package io.github.kidctl.agent

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Runs the shared spec/vectors.json (also run by the Rust evaluator). */
class EvaluatorVectorsTest {
    @Test
    fun sharedVectors() {
        val text = javaClass.classLoader!!.getResource("vectors.json")!!.readText()
        val root = JSONObject(text)
        val policy = Policy.parse(root.getJSONObject("policy"))
        val failures = mutableListOf<String>()
        val cases = root.getJSONArray("cases")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val usageJ = c.getJSONObject("usage")
            val usage = usageJ.keyList().associateWith { usageJ.getLong(it) }
            val userInstalled = c.optJSONArray("user_installed")?.strings()?.toSet() ?: emptySet()
            val expect = c.getJSONObject("expect")
            for (pkg in expect.keyList()) {
                val got = Evaluator.decide(policy, c.getLong("now"), usage, pkg, pkg in userInstalled)
                val want = expect.getString(pkg)
                if (got != want) failures += "${c.getString("name")}: $pkg: want $want, got $got"
            }
            val wantScreen = c.getBoolean("screen_locked")
            val gotScreen = Evaluator.screenLocked(policy, c.getLong("now"))
            if (gotScreen != wantScreen) failures += "${c.getString("name")}: screen_locked: want $wantScreen, got $gotScreen"
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    /** spec/vectors.json `notify_cases`: sequences of notifyStep from a fresh state (also run by eval.rs). */
    @Test
    fun sharedNotifyVectors() {
        val root = JSONObject(javaClass.classLoader!!.getResource("vectors.json")!!.readText())
        val policy = Policy.parse(root.getJSONObject("policy"))
        val failures = mutableListOf<String>()
        val cases = root.getJSONArray("notify_cases")
        assertTrue(cases.length() > 0)
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            var st = NotifyState()
            val steps = c.getJSONArray("steps")
            for (j in 0 until steps.length()) {
                val s = steps.getJSONObject(j)
                val usageJ = s.getJSONObject("usage")
                val usage = usageJ.keyList().associateWith { usageJ.getLong(it) }
                val (notices, next) = Evaluator.notifyStep(policy, s.getLong("now"), usage, st)
                val got = notices.map { it.label() }
                val want = s.getJSONArray("expect").strings()
                if (got != want) failures += "${c.getString("name")} step $j: want $want, got $got"
                // The persisted form gives the same state back.
                if (NotifyState.parse(next.toJson().toString()) != next) failures += "${c.getString("name")} step $j: state round trip"
                st = next
            }
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    /** The notify fields reach Policy; absent (older servers, notify off) = off. */
    @Test
    fun notifyFields() {
        val root = JSONObject(javaClass.classLoader!!.getResource("vectors.json")!!.readText())
        val p = Policy.parse(root.getJSONObject("policy"))
        assertEquals(Notify(300, "fr"), p.notify)
        assertEquals(
            mapOf("social" to listOf(50, 80, 95), "audio" to emptyList(), "video" to listOf(90), "general" to listOf(50, 80, 95)),
            p.limits.associate { it.name to it.notifyAt },
        )
        val o = root.getJSONObject("policy")
        o.remove("notify")
        for (i in 0 until o.getJSONArray("limits").length()) o.getJSONArray("limits").getJSONObject(i).remove("notify_at")
        val off = Policy.parse(o)
        assertNull(off.notify)
        assertTrue(off.limits.all { it.notifyAt.isEmpty() })
        // Mon 21:55, social at 83 %, downtime in 5 min: nothing when off, state untouched.
        val prev = NotifyState("2026-10-19", mapOf("social" to Mark(1800, 50)), null)
        assertEquals(Pair(emptyList<Notice>(), prev), Evaluator.notifyStep(off, 1792439700, mapOf("com.instagram.android" to 1500L), prev))
        assertNull(Evaluator.secsToNextThreshold(off, 1792439700, emptyMap(), "com.instagram.android"))
        // A corrupt or absent saved state reads as a fresh one.
        assertEquals(NotifyState(), NotifyState.parse(null))
        assertEquals(NotifyState(), NotifyState.parse("{not json"))
        assertEquals(prev, NotifyState.parse(prev.toJson().toString()))
    }

    /** When to check again for the app in front: the next threshold of any limit it counts in. */
    @Test
    fun secsToNextThreshold() {
        val p = Policy.parse(JSONObject(javaClass.classLoader!!.getResource("vectors.json")!!.readText()).getJSONObject("policy"))
        val mon = 1792418400L // Mon 16:00: social 1800 s [50,80,95], general 3600 s [50,80,95]
        val ig = "com.instagram.android"
        assertEquals(900L, Evaluator.secsToNextThreshold(p, mon, emptyMap(), ig))
        assertEquals(1L, Evaluator.secsToNextThreshold(p, mon, mapOf(ig to 899L), ig))
        assertEquals(540L, Evaluator.secsToNextThreshold(p, mon, mapOf(ig to 900L), ig))
        // At social's 95 %: general's 50 % (1800 s) is next.
        assertEquals(90L, Evaluator.secsToNextThreshold(p, mon, mapOf(ig to 1710L), ig))
        assertEquals(89L, Evaluator.secsToNextThreshold(p, mon, mapOf(ig to 1711L), ig))
        // Audio has no thresholds; video's budget is 0 on Monday; nothing left above general's 95 %.
        assertNull(Evaluator.secsToNextThreshold(p, mon, emptyMap(), "com.spotify.music"))
        assertNull(Evaluator.secsToNextThreshold(p, mon, emptyMap(), "com.netflix.mediaclient"))
        assertNull(Evaluator.secsToNextThreshold(p, mon, mapOf("com.android.chrome" to 3600L), "com.android.chrome"))
    }

    /** The device fields of the shared policy reach DeviceConfig (wire format, opt* parsing). */
    @Test
    fun deviceFields() {
        val text = javaClass.classLoader!!.getResource("vectors.json")!!.readText()
        val d = Policy.parse(JSONObject(text).getJSONObject("policy")).device
        assertEquals(listOf("HomeNet", "École du Centre"), d.wifiSsidsAllow)
        assertNull(d.wifiSsidsDeny)
        assertEquals("com.android.chrome", d.defaultBrowser)
        assertEquals("com.google.android.apps.nexuslauncher", d.defaultLauncher)
        assertEquals("kidctl", d.organizationName)
        assertEquals(listOf("com.tailscale.ipn"), d.userControlDisabled)
        // Absent fields (older servers / unused features) parse to "not set".
        val bare = DeviceConfig.parse(JSONObject("{}"))
        assertNull(bare.wifiSsidsAllow)
        assertNull(bare.wifiSsidsDeny)
        assertNull(bare.defaultBrowser)
        assertNull(bare.defaultLauncher)
        assertNull(bare.organizationName)
        assertNull(bare.lockScreenInfo)
        assertNull(bare.supportMessage)
        assertEquals(emptyList<String>(), bare.userControlDisabled)
        val launcherOnly = DeviceConfig.parse(JSONObject("""{"default_apps":{"launcher":"a.b"},"wifi_ssids":{"deny":["x"]}}"""))
        assertNull(launcherOnly.defaultBrowser)
        assertEquals("a.b", launcherOnly.defaultLauncher)
        assertEquals(listOf("x"), launcherOnly.wifiSsidsDeny)
        assertNull(launcherOnly.wifiSsidsAllow)
    }
}
