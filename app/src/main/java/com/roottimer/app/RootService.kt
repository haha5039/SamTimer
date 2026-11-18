package com.roottimer.app

import android.content.Context
import android.os.Process
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Shizuku UserService: runs the CVE-2026-98260 timer exploit as the shell user.
 *
 * Chain for the A56 Android 15-based 6.6 kernel:
 *  1. stage ksud from the APK (jniLibs/libksud.so) to /data/local/tmp/samtimer/ksud
 *  2. raise the tracefs buffer (the leak needs headroom)
 *  3. run libtimer.so in "umhpipe" mode: pipe_buffer kernel r/w primitive ->
 *     system_unbound_wq usermodehelper -> bind-mount ksud over
 *     /system/bin/logcat (KDP bypass) -> KernelSU late-load -> KSU_LOADED
 *  4. failed-plant zombies are made reap-safe (their posix-cpu-timer queue
 *     leftmost pointers are zeroed through the write primitive) and reaped
 *     immediately, so the exploit exits cleanly with no zombie left and
 *     nothing for init to reap later. Parking is only a last-resort fallback
 *     when a repair plant cannot land. KSU keeps root either way.
 */
class RootService(private val context: Context) : IRootService.Stub() {

    private val running = AtomicBoolean(false)

    companion object {
        private const val WORK_DIR = "/data/local/tmp/samtimer"
        // The exploit hardcodes the bind-mount source to WORK_DIR/ksud, and
        // the Samsung-patched ksud late-load expects a staged copy at
        // /data/local/tmp/.ksud-stage (it renames that file onto the same
        // /data filesystem before loading the module -- RootMyGalaxy stages
        // both paths the same way).
        private const val KSUD_STAGE_PATH = "/data/local/tmp/.ksud-stage"
        private const val TRACE_BUF = "/sys/kernel/tracing/buffer_size_kb"
        private const val INJECT_TIMEOUT_SEC = 420L
        private const val MANAGER_WAIT_SEC = 20L
    }

    override fun isReady(): Boolean {
        val uid = Process.myUid()
        return uid == 2000 || uid == 0
    }

    /** True when the KernelSU module is live in /proc/modules (shell can read it). */
    override fun isRooted(): Boolean = try {
        java.io.File("/proc/modules").useLines { lines ->
            lines.any { it.startsWith("kernelsu ") }
        }
    } catch (_: Exception) {
        false
    }

    override fun destroy() {}

    override fun runExploit(callback: IRootCallback?) {
        if (callback == null) return
        if (!running.compareAndSet(false, true)) {
            callback.onLog("error: another run is already in progress")
            callback.onComplete(1, false)
            return
        }
        Thread({
            val ksuLoaded = java.util.concurrent.atomic.AtomicBoolean(false)
            var exitCode = 1
            try {
                exitCode = runChain(callback, ksuLoaded)
            } catch (e: Exception) {
                runCatching { callback.onLog("error: ${e.message}") }
            } finally {
                runCatching { callback.onComplete(exitCode, ksuLoaded.get()) }
                running.set(false)
            }
        }, "rt-runner").start()
    }

    private fun log(callback: IRootCallback, line: String) {
        runCatching { callback.onLog(line) }
    }

    private fun exploitAlreadyRunning(): Boolean = runCatching {
        val check = ProcessBuilder("/system/bin/pidof", "-x", "libtimer.so")
            .redirectErrorStream(true).start()
        if (!check.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)) {
            check.destroyForcibly()
            return@runCatching false
        }
        check.exitValue() == 0 && check.inputStream.bufferedReader().readText().isNotBlank()
    }.getOrDefault(false)

    private fun managerRegistered(callback: IRootCallback, timerBin: File): Boolean {
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS
            .toNanos(MANAGER_WAIT_SEC)
        var lastMessage = "Manager registration timed out"
        do {
            val result = runCatching {
                val check = ProcessBuilder(
                    "/system/bin/su", "-c", "${timerBin.absolutePath} managercheck"
                ).redirectErrorStream(true).start()
                if (!check.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)) {
                    check.destroyForcibly()
                    return@runCatching null
                }
                check.exitValue() to check.inputStream.bufferedReader().readText()
            }.getOrNull()
            if (result != null) {
                lastMessage = result.second.trim().ifEmpty { "Manager check failed" }
                if (result.first == 0) {
                    log(callback, lastMessage)
                    return true
                }
            }
            if (System.nanoTime() >= deadline) break
            try {
                Thread.sleep(500)
            } catch (_: InterruptedException) {
                break
            }
        } while (true)
        log(callback, lastMessage)
        return false
    }

    private fun runChain(callback: IRootCallback, ksuLoaded: java.util.concurrent.atomic.AtomicBoolean): Int {
        val uid = Process.myUid()
        if (uid != 2000 && uid != 0) {
            log(callback, "error: not running as shell/root (uid=$uid)")
            return 1
        }
        if (exploitAlreadyRunning()) {
            log(callback, "error: earlier exploit process is still running; reboot before retrying")
            return 6
        }
        log(callback, "shell context ok (uid=$uid)")

        val nativeDir = File(context.applicationInfo.nativeLibraryDir)
        val timerBin = File(nativeDir, "libtimer.so")
        val ksudSrc = File(nativeDir, "libksud.so")
        if (!timerBin.isFile) {
            log(callback, "error: exploit binary missing: ${timerBin.absolutePath}")
            return 1
        }
        if (!ksudSrc.isFile) {
            log(callback, "error: matching KernelSU daemon missing")
            return 1
        }

        // 1. workdir + ksud staging (the exploit hardcodes /data/local/tmp/samtimer/ksud)
        val workDir = File(WORK_DIR)
        if (!(workDir.isDirectory || workDir.mkdirs())) {
            log(callback, "error: cannot create $WORK_DIR")
            return 1
        }
        val ksud = File(workDir, "ksud")
        try {
            ksudSrc.copyTo(ksud, overwrite = true)
            if (!ksud.setExecutable(true, false)) {
                log(callback, "warn: chmod +x ksud failed")
            }
            log(callback, "staged ksud (${ksud.length()} bytes)")
            // Second staged copy the patched late-load looks for.
            val stage = File(KSUD_STAGE_PATH)
            try {
                ksudSrc.copyTo(stage, overwrite = true)
                stage.setExecutable(true, false)
                log(callback, "staged ksud at $KSUD_STAGE_PATH")
            } catch (e: IOException) {
                log(callback, "warn: .ksud-stage copy failed (${e.message})")
            }
        } catch (e: IOException) {
            log(callback, "error: KernelSU staging failed (${e.message})")
            return 1
        }

        // 1c. UMH helper: the same payload binary under the path the fake
        // usermodehelper execs (ROOT_UMH_PATH); --umh runs setksu_main.
        try {
            val uhexec = File(workDir, "uhexec")
            timerBin.copyTo(uhexec, overwrite = true)
            if (!uhexec.setExecutable(true, false)) {
                log(callback, "warn: chmod +x uhexec failed")
            }
            log(callback, "staged uhexec (${uhexec.length()} bytes)")
        } catch (e: IOException) {
            log(callback, "warn: uhexec staging failed (${e.message}); KSU load will fail")
        }

        // 2. tracefs buffer headroom (root-only write as shell is allowed here)
        runCatching {
            File(TRACE_BUF).writeText("8192\n")
            log(callback, "trace buffer set to 8192kB")
        }.onFailure {
            log(callback, "warn: trace buffer write failed (${it.message})")
        }

        // 3. run the exploit (umhpipe: pipe r/w primitive -> fake workqueue
        // item -> kernel-issued root usermodehelper -> ksud late-load)
        log(callback, "starting exploit (umhpipe mode)...")
        val capture = try {
            FileOutputStream(File(workDir, "last-run.log"), false)
        } catch (e: IOException) {
            log(callback, "error: cannot open diagnostic log (${e.message})")
            return 1
        }
        val proc = try {
            ProcessBuilder(timerBin.absolutePath, "umhpipe")
                .directory(workDir)
                .redirectErrorStream(true)
                .start()
        } catch (e: IOException) {
            capture.close()
            throw e
        }
        val parkedReason = AtomicReference<String?>(null)

        val reader = Thread({
            try {
                capture.bufferedWriter().use { writer ->
                    proc.inputStream.bufferedReader().useLines { lines ->
                        for (line in lines) {
                            writer.appendLine(line)
                            writer.flush()
                            if (line.contains("-- parking without reap") ||
                                line.contains("KSU_LOADED") || line.contains("KSU_MISSING")) {
                                runCatching { capture.fd.sync() }
                            }
                            log(callback, line)
                            if (line.contains("KSU_LOADED")) ksuLoaded.set(true)
                            if (line.contains("-- parking without reap")) parkedReason.set(line)
                        }
                    }
                    writer.flush()
                    runCatching { capture.fd.sync() }
                }
            } catch (_: Exception) {
                runCatching { capture.close() }
            }
        }, "rt-tailer")
        reader.isDaemon = true
        reader.start()

        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS
            .toNanos(INJECT_TIMEOUT_SEC)
        var finished = false
        while (System.nanoTime() < deadline) {
            if (proc.waitFor(1, java.util.concurrent.TimeUnit.SECONDS)) {
                finished = true
                break
            }
            val reason = parkedReason.get()
            if (reason != null) {
                if (ksuLoaded.get() && managerRegistered(callback, timerBin)) {
                    log(callback, "success; exploit parked holding zombies until reboot (do not force-stop it)")
                    return 0
                }
                ksuLoaded.set(false)
                log(callback, "error: exploit parked; reboot before retrying")
                return 4
            }
        }
        if (!finished) {
            // Do NOT SIGKILL: the exploit may hold the reclaimed page; a kill
            // can panic the kernel. Leave it parked and report timeout.
            if (ksuLoaded.get() && managerRegistered(callback, timerBin)) {
                // Success path: the exploit drained its pools and parked as
                // the holder for failed-plant zombies (reaping those from a
                // dead parent corrupts kernel memory). It must stay alive
                // until reboot -- never force-stop it.
                log(callback, "success; exploit parked holding zombies until reboot (do not force-stop it)")
                return 0
            }
            ksuLoaded.set(false)
            log(callback, "error: exploit did not finish in ${INJECT_TIMEOUT_SEC}s (left running)")
            return 4
        }
        reader.join(2000)
        val rc = proc.exitValue()
        log(callback, "exploit finished rc=$rc")
        if (ksuLoaded.get()) {
            if (!managerRegistered(callback, timerBin)) {
                ksuLoaded.set(false)
                log(callback, "error: KernelSU module loaded, but Manager is not registered")
                return 5
            }
        }
        return rc
    }
}
