package io.github.kidctl.agent

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.DigestOutputStream
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Over-the-air self-update. After each sync, if the server offers a higher
 * versionCode: download it into app-private storage, check its size, SHA-256,
 * package name and versionCode, then install it silently with a
 * PackageInstaller session (a device owner needs no user confirmation).
 * Android checks the signature: only an APK signed with the release key
 * installs over the running agent. The installer kills this process; the new
 * version is restarted by BootReceiver on MY_PACKAGE_REPLACED.
 *
 * Runs on its own thread, independent of policy handling, so a policy bug
 * cannot block the update that fixes it. Each attempt is recorded before it
 * starts and a failed release waits for a growing backoff (no retry loop);
 * failures are reported as `agent_update_failed` events.
 */
class Updater(private val ctx: Context, private val state: State) {
    fun installedVersionCode(): Long = ctx.packageManager.getPackageInfo(ctx.packageName, 0).longVersionCode

    /** Called after every sync; returns at once. */
    fun maybeStart(deviceOwner: Boolean) {
        val offer = state.agentOffer ?: return
        val now = System.currentTimeMillis()
        if (!UpdatePlan.shouldDownload(offer, installedVersionCode(), state.updateAttempt, now)) return
        if (!running.compareAndSet(false, true)) return
        state.updateAttempt = UpdatePlan.nextAttempt(offer, state.updateAttempt, now)
        if (!deviceOwner) {
            fail(ctx, state, offer.versionCode, "not device owner: cannot install silently")
            running.set(false)
            return
        }
        Thread({
            try {
                run(offer)
            } catch (e: Exception) {
                fail(ctx, state, offer.versionCode, e.toString())
            } finally {
                running.set(false)
            }
        }, "kidctl-update").start()
    }

    private fun run(offer: Release) {
        val base = state.serverUrl ?: throw IllegalStateException("not configured")
        val dir = updateDir(ctx).apply { mkdirs() }
        dir.listFiles()?.forEach { it.delete() }
        val apk = File(dir, "agent-${offer.versionCode}.apk")
        Log.i(TAG, "downloading agent version_code ${offer.versionCode}")
        val c = (URL(base.trimEnd('/') + offer.url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 30_000
            setRequestProperty("authorization", "Bearer ${state.token}")
            setRequestProperty("x-device-id", state.deviceId)
        }
        val md = MessageDigest.getInstance("SHA-256")
        var size = 0L
        try {
            if (c.responseCode != 200) {
                val text = c.errorStream?.bufferedReader()?.use { it.readText() } ?: ""
                return fail(ctx, state, offer.versionCode, "download: HTTP ${c.responseCode} ${text.take(200)}")
            }
            if (c.contentLengthLong > offer.size) {
                return fail(ctx, state, offer.versionCode, "download: ${c.contentLengthLong} bytes, offered ${offer.size}")
            }
            c.inputStream.use { input ->
                DigestOutputStream(apk.outputStream(), md).use { out ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        size += n
                        // Never store more than offered (a hostile or broken server cannot fill the disk).
                        if (size > offer.size) break
                        out.write(buf, 0, n)
                    }
                }
            }
        } finally {
            c.disconnect()
        }
        val sha = md.digest().joinToString("") { "%02x".format(it) }
        UpdatePlan.checkDownload(offer, size, sha)?.let { return fail(ctx, state, offer.versionCode, it) }
        val info = ctx.packageManager.getPackageArchiveInfo(apk.path, 0)
        UpdatePlan.checkArchive(offer, ctx.packageName, info?.packageName, info?.longVersionCode)
            ?.let { return fail(ctx, state, offer.versionCode, it) }
        state.addEvent("agent_update_installing", "version_code ${offer.versionCode}")
        Log.i(TAG, "installing agent version_code ${offer.versionCode} (sha256 $sha)")
        install(apk, offer.versionCode)
    }

    private fun install(apk: File, versionCode: Long) {
        val pi = ctx.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(ctx.packageName)
            setSize(apk.length())
            setInstallReason(PackageManager.INSTALL_REASON_POLICY)
            if (Build.VERSION.SDK_INT >= 31) setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
        }
        val id = pi.createSession(params)
        try {
            pi.openSession(id).use { s ->
                s.openWrite("base.apk", 0, apk.length()).use { out ->
                    apk.inputStream().use { it.copyTo(out) }
                    s.fsync(out)
                }
                val intent = Intent(ctx, InstallResultReceiver::class.java)
                    .putExtra(EXTRA_VERSION_CODE, versionCode)
                // Mutable: the installer adds the status extras. Explicit intent, so allowed.
                val pending = PendingIntent.getBroadcast(ctx, id, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE)
                s.commit(pending.intentSender)
            }
        } catch (e: Exception) {
            runCatching { pi.abandonSession(id) }
            throw e
        }
    }

    companion object {
        const val TAG = "kidctl"
        const val EXTRA_VERSION_CODE = "io.github.kidctl.agent.VERSION_CODE"
        private val running = AtomicBoolean(false)

        fun updateDir(ctx: Context) = File(ctx.filesDir, "update")

        /** Downloaded APKs are only needed until the session is committed. */
        fun cleanup(ctx: Context) {
            if (!running.get()) updateDir(ctx).listFiles()?.forEach { it.delete() }
        }

        fun fail(ctx: Context, state: State, versionCode: Long, why: String) {
            Log.w(TAG, "agent update to version_code $versionCode failed: $why")
            state.addEvent("agent_update_failed", "version_code $versionCode: ${why.take(300)}")
            state.lastError = "update: ${why.take(200)}"
            updateDir(ctx).listFiles()?.forEach { it.delete() }
        }
    }
}

/** PackageInstaller session result (a successful self-update usually kills us before it arrives). */
class InstallResultReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val state = State(context)
        val vc = intent.getLongExtra(Updater.EXTRA_VERSION_CODE, 0)
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        val msg = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: ""
        Log.i(Updater.TAG, "install session result for version_code $vc: status $status $msg extras ${intent.extras?.keySet()}")
        when (status) {
            PackageInstaller.STATUS_SUCCESS -> {
                state.addEvent("agent_update_installed", "version_code $vc")
                Updater.cleanup(context)
            }
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                // The agent has no UI and must not ask the child: give up on this session.
                val id = intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -1)
                if (id >= 0) runCatching { context.packageManager.packageInstaller.abandonSession(id) }
                Updater.fail(context, state, vc, "installer asks for user confirmation (not device owner?)")
            }
            else -> {
                val devReason = PackageInstaller.EXTRA_DEVELOPER_VERIFICATION_FAILURE_REASON
                    .takeIf { intent.hasExtra(it) }?.let { intent.getIntExtra(it, UpdatePlan.DEV_VERIFICATION_UNKNOWN) }
                Updater.fail(context, state, vc, UpdatePlan.installFailure(status, msg, devReason))
            }
        }
    }
}
