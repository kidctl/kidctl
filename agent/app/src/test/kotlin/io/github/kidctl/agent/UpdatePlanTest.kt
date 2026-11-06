package io.github.kidctl.agent

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdatePlanTest {
    private val sha = "ab".repeat(32)
    private val offer = Release(5, "0.1.0", sha, 1000, "/api/v1/agent/5")
    private val min = 60_000L

    private fun json(vararg kv: Pair<String, Any>) = JSONObject().apply { kv.forEach { (k, v) -> put(k, v) } }

    @Test
    fun parsesTheServerOffer() {
        val o = json("version_code" to 5, "version_name" to "0.1.0", "sha256" to sha.uppercase(), "size" to 1000, "url" to "/api/v1/agent/5")
        assertEquals(offer, Release.parse(o))
        assertEquals(offer, Release.parse(offer.toJson()))
        assertNull("absent", Release.parse(null))
    }

    @Test
    fun rejectsUnusableOffers() {
        val good = offer.toJson()
        fun with(k: String, v: Any) = Release.parse(JSONObject(good.toString()).put(k, v))
        assertNull(with("version_code", 0))
        assertNull(with("sha256", "abc"))
        assertNull(with("sha256", "zz".repeat(32)))
        assertNull(with("size", 0))
        assertNull(with("size", UpdatePlan.MAX_APK_BYTES + 1))
        // The token goes with the download: only paths on the configured server.
        assertNull(with("url", "https://evil.example/agent.apk"))
        assertNull(with("url", "//evil.example/agent.apk"))
        assertNull(with("url", "/api/../../x"))
        assertNull(with("url", ""))
    }

    @Test
    fun onlyAStrictlyHigherVersionIsDownloaded() {
        assertTrue(UpdatePlan.shouldDownload(offer, 4, null, 0))
        assertFalse("same version", UpdatePlan.shouldDownload(offer, 5, null, 0))
        assertFalse("downgrade", UpdatePlan.shouldDownload(offer, 6, null, 0))
        assertFalse("nothing offered", UpdatePlan.shouldDownload(null, 4, null, 0))
    }

    @Test
    fun failedReleaseBacksOffExponentiallyNoRetryLoop() {
        val t0 = 1_000_000_000L
        val a1 = UpdatePlan.nextAttempt(offer, null, t0)
        assertEquals(Attempt(5, sha, 1, t0 + 15 * min), a1)
        assertFalse("retried at the next sync", UpdatePlan.shouldDownload(offer, 4, a1, t0 + min))
        assertFalse(UpdatePlan.shouldDownload(offer, 4, a1, t0 + 15 * min - 1))
        assertTrue(UpdatePlan.shouldDownload(offer, 4, a1, t0 + 15 * min))
        val a2 = UpdatePlan.nextAttempt(offer, a1, t0 + 15 * min)
        assertEquals(2, a2.count)
        assertEquals(t0 + 15 * min + 30 * min, a2.nextMs)
        var a = a2
        repeat(30) { a = UpdatePlan.nextAttempt(offer, a, 0) }
        assertEquals("capped at 24 h", UpdatePlan.MAX_BACKOFF_MS, a.nextMs)
    }

    @Test
    fun aNewReleaseIsTriedAtOnceDespiteAFailedOne() {
        val failed = UpdatePlan.nextAttempt(offer, null, 0)
        val fixed = offer.copy(versionCode = 6, url = "/api/v1/agent/6")
        assertTrue(UpdatePlan.shouldDownload(fixed, 4, failed, 1))
        assertEquals(1, UpdatePlan.nextAttempt(fixed, failed, 1).count)
        // Same code re-published with other bytes counts as a new release too.
        val rebuilt = offer.copy(sha256 = "cd".repeat(32))
        assertTrue(UpdatePlan.shouldDownload(rebuilt, 4, failed, 1))
    }

    @Test
    fun clockSetBackDoesNotFreezeUpdates() {
        val a = Attempt(5, sha, 1, 10 * UpdatePlan.MAX_BACKOFF_MS)
        assertTrue(UpdatePlan.shouldDownload(offer, 4, a, 0))
    }

    @Test
    fun shaOrSizeMismatchRejected() {
        val bytes = "PK\u0003\u0004 an apk".toByteArray()
        val realSha = UpdatePlan.sha256Hex(bytes.inputStream())
        val o = offer.copy(sha256 = realSha, size = bytes.size.toLong())
        assertNull(UpdatePlan.checkDownload(o, bytes.size.toLong(), realSha))
        assertNull("hex case", UpdatePlan.checkDownload(o, bytes.size.toLong(), realSha.uppercase()))
        val tampered = bytes.copyOf().also { it[5] = 'X'.code.toByte() }
        val bad = UpdatePlan.checkDownload(o, tampered.size.toLong(), UpdatePlan.sha256Hex(tampered.inputStream()))
        assertNotNull(bad)
        assertTrue(bad!!, bad.startsWith("sha256 mismatch"))
        assertTrue(UpdatePlan.checkDownload(o, bytes.size + 1L, realSha)!!.startsWith("size mismatch"))
        // Known vector: SHA-256("abc").
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", UpdatePlan.sha256Hex("abc".byteInputStream()))
    }

    @Test
    fun archiveMustBeThisAppAtTheOfferedVersion() {
        assertNull(UpdatePlan.checkArchive(offer, "io.github.kidctl.agent", "io.github.kidctl.agent", 5))
        assertNotNull(UpdatePlan.checkArchive(offer, "io.github.kidctl.agent", null, null))
        assertNotNull(UpdatePlan.checkArchive(offer, "io.github.kidctl.agent", "com.evil", 5))
        assertNotNull(UpdatePlan.checkArchive(offer, "io.github.kidctl.agent", "io.github.kidctl.agent", 4))
    }

    @Test
    fun attemptRoundTripsAndBadStateIsIgnored() {
        val a = Attempt(5, sha, 3, 42)
        assertEquals(a, Attempt.parse(a.toJson().toString()))
        assertNull(Attempt.parse(null))
        assertNull(Attempt.parse("{broken"))
    }

    @Test
    fun installFailureReportsDeveloperVerification() {
        // Our constants are Android's (API 37 PackageInstaller).
        assertEquals(android.content.pm.PackageInstaller.DEVELOPER_VERIFICATION_FAILED_REASON_UNKNOWN, UpdatePlan.DEV_VERIFICATION_UNKNOWN)
        assertEquals(
            android.content.pm.PackageInstaller.DEVELOPER_VERIFICATION_FAILED_REASON_NETWORK_UNAVAILABLE,
            UpdatePlan.DEV_VERIFICATION_NETWORK_UNAVAILABLE,
        )
        assertEquals(
            android.content.pm.PackageInstaller.DEVELOPER_VERIFICATION_FAILED_REASON_DEVELOPER_BLOCKED,
            UpdatePlan.DEV_VERIFICATION_DEVELOPER_BLOCKED,
        )
        assertEquals(
            "install status 3: INSTALL_FAILED_VERIFICATION_FAILURE",
            UpdatePlan.installFailure(3, "INSTALL_FAILED_VERIFICATION_FAILURE", null),
        )
        assertEquals(
            "install status 2: blocked; developer verification failed: developer blocked",
            UpdatePlan.installFailure(2, "blocked", 2),
        )
        assertEquals("install status 1: x; developer verification failed: network unavailable", UpdatePlan.installFailure(1, "x", 1))
        assertEquals("install status 1: x; developer verification failed: unknown", UpdatePlan.installFailure(1, "x", 0))
        assertEquals("install status 1: x; developer verification failed: reason 9", UpdatePlan.installFailure(1, "x", 9))
    }
}
