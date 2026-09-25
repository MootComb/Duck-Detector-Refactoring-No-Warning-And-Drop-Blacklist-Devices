/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.eltavine.duckdetector.features.dangerousapps.data.repository

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Scene 9.3.0 Alpha13 mounts debugfs at /dev/<random>/debug
 * and creates a marker file /dev/<random>/scene_mode_category.
 *
 * Detection:
 *   1. Parse /proc/self/mountinfo → extract hash dir from mount_point
 *   2. Verify /dev/<hash>/scene_mode_category exists
 *      - access(F_OK) → 0 (permission allows existence check)
 *      - mkdir(path)  → EEXIST (path already exists as non-dir)
 *      - stat(path)   → EACCES (file exists but metadata denied)
 *   3. Fallback: /proc/self/mounts → mount command
 *
 * Returns the marker path if detected, null otherwise.
 */
internal fun detectSceneDebugfsMount(): String? {
    // Hash dir regex: 8 characters consisting of lowercase letters and underscores
    val hashRegex = Regex("^/([a-z_]{8})/debug$")

    // 1. Find the hash directory from mountinfo (preferred)
    val hashDir = try {
        File("/proc/self/mountinfo").useLines { lines ->
            lines.firstNotNullOfOrNull { line ->
                val fields = line.split(" ")
                val fstypeIdx = fields.indexOf("-")
                if (fstypeIdx >= 0 && fstypeIdx + 2 < fields.size &&
                    fields[fstypeIdx + 1] == "debugfs") {
                    val match = hashRegex.matchEntire(fields[4].removePrefix("/dev"))
                    match?.groupValues?.getOrNull(1)
                } else null
            }
        }
    } catch (_: Exception) {
        null
    }

    // 2. Fallback: /proc/self/mounts (format: device mount_point fstype options ...)
    val hashDir2 = hashDir ?: try {
        File("/proc/self/mounts").useLines { lines ->
            lines.firstNotNullOfOrNull { line ->
                val parts = line.split(" ").filter { it.isNotEmpty() }
                if (parts.size >= 3 && parts[2] == "debugfs") {
                    val mountPoint = parts[1].removePrefix("/dev")
                    val match = hashRegex.matchEntire(mountPoint)
                    match?.groupValues?.getOrNull(1)
                } else null
            }
        }
    } catch (_: Exception) {
        null
    }

    // 3. Fallback: mount command (format: "debugfs on /dev/<hash>/debug type debugfs ...")
    val hashDir3 = hashDir2 ?: run {
        var process: Process? = null
        try {
            val mountRegex = Regex("debugfs on /dev/([a-z_]{8})/debug")
            process = ProcessBuilder("mount").redirectErrorStream(true).start()
            var matchedHash: String? = null
            process.inputStream.bufferedReader().useLines { lines ->
                matchedHash = lines.firstNotNullOfOrNull { line ->
                    mountRegex.find(line)?.groupValues?.getOrNull(1)
                }
            }
            process.waitFor(2, TimeUnit.SECONDS)
            matchedHash
        } catch (_: Exception) {
            null
        } finally {
            process?.destroy()
        }
    }

    val finalHash = hashDir3 ?: return null

    // Verify marker using kernel-level syscall evidence chain:
    //   access(F_OK) → 0        (File exists)
    //   mkdir(path)  → EEXIST   (Path already exists as non-directory)
    //   stat(path)   → EACCES   (File exists but metadata denied)
    val markerPath = "/dev/$finalHash/scene_mode_category"

    // 1. Precise existence check: distinguish ENOENT from EACCES
    try {
        Os.access(markerPath, OsConstants.F_OK)
    } catch (e: ErrnoException) {
        if (e.errno == OsConstants.ENOENT) {
            // File truly does not exist — must short-circuit to avoid
            // creating a spurious directory via mkdir below.
            return null
        }
        // EACCES or other: file may exist but access denied.
        // Do NOT short-circuit — fall through to mkdir side-channel.
    }

    // 2. mkdir side-channel: kernel prioritises EEXIST over EACCES
    val mkdirEexist = try {
        Os.mkdir(markerPath, 0)
        // mkdir succeeded → file did not exist, we just created a
        // spurious directory. Clean it up immediately.
        runCatching { Os.remove(markerPath) }
        false
    } catch (e: ErrnoException) {
        e.errno == OsConstants.EEXIST
    }
    if (!mkdirEexist) return null

    // 3. stat metadata denial
    val statDenied = try {
        Os.stat(markerPath)
        false // stat succeeded → regular accessible file
    } catch (e: ErrnoException) {
        e.errno == OsConstants.EACCES
    }
    return if (statDenied) markerPath else null
}

internal fun waitForScenePocFile(path: String): Boolean {
    repeat(SCENE_BROADCAST_POLL_ATTEMPTS) { attempt ->
        if (verifyPocFile(path)) {
            return true
        }
        if (attempt + 1 < SCENE_BROADCAST_POLL_ATTEMPTS) {
            Thread.sleep(SCENE_BROADCAST_POLL_INTERVAL_MS)
        }
    }
    return false
}

private fun verifyPocFile(path: String): Boolean {
    val accessOutcome = probeAccess(path)
    val statOutcome = probeStat(path)
    val openOutcome = probeOpen(path)
    val createOutcome = probeCreate(path)

    if (listOf(accessOutcome, statOutcome, openOutcome).any { it == PathProbeOutcome.MISSING }) {
        return false
    }

    runCatching { Os.getxattr(path, "security.selinux") }

    return createOutcome == CreateProbeOutcome.ALREADY_EXISTS ||
        listOf(accessOutcome, statOutcome, openOutcome).any { it == PathProbeOutcome.EXISTS }
}

private fun probeAccess(path: String): PathProbeOutcome {
    return try {
        Os.access(path, OsConstants.F_OK)
        PathProbeOutcome.EXISTS
    } catch (e: ErrnoException) {
        when (e.errno) {
            OsConstants.ENOENT -> PathProbeOutcome.MISSING
            OsConstants.EACCES, OsConstants.EPERM -> PathProbeOutcome.UNKNOWN
            else -> PathProbeOutcome.UNKNOWN
        }
    }
}

private fun probeStat(path: String): PathProbeOutcome {
    return try {
        Os.stat(path)
        PathProbeOutcome.EXISTS
    } catch (e: ErrnoException) {
        when (e.errno) {
            OsConstants.ENOENT -> PathProbeOutcome.MISSING
            OsConstants.EACCES, OsConstants.EPERM -> PathProbeOutcome.UNKNOWN
            else -> PathProbeOutcome.UNKNOWN
        }
    }
}

private fun probeOpen(path: String): PathProbeOutcome {
    return try {
        val fd = Os.open(path, OsConstants.O_RDONLY, 0)
        Os.close(fd)
        PathProbeOutcome.EXISTS
    } catch (e: ErrnoException) {
        when (e.errno) {
            OsConstants.ENOENT -> PathProbeOutcome.MISSING
            OsConstants.EACCES, OsConstants.EPERM -> PathProbeOutcome.UNKNOWN
            OsConstants.EISDIR -> PathProbeOutcome.EXISTS
            else -> PathProbeOutcome.UNKNOWN
        }
    }
}

private fun probeCreate(path: String): CreateProbeOutcome {
    return try {
        val fd = Os.open(path, OsConstants.O_CREAT or OsConstants.O_EXCL or OsConstants.O_WRONLY, 0)
        Os.close(fd)
        runCatching { Os.remove(path) }
        CreateProbeOutcome.CREATED_BY_US
    } catch (e: ErrnoException) {
        when (e.errno) {
            OsConstants.EEXIST -> CreateProbeOutcome.ALREADY_EXISTS
            OsConstants.EACCES, OsConstants.EPERM -> CreateProbeOutcome.BLOCKED
            OsConstants.ENOENT -> CreateProbeOutcome.MISSING
            else -> CreateProbeOutcome.UNKNOWN
        }
    }
}

private const val SCENE_BROADCAST_POLL_ATTEMPTS = 8
private const val SCENE_BROADCAST_POLL_INTERVAL_MS = 150L

private enum class PathProbeOutcome {
    EXISTS,
    MISSING,
    UNKNOWN,
}

private enum class CreateProbeOutcome {
    ALREADY_EXISTS,
    CREATED_BY_US,
    MISSING,
    BLOCKED,
    UNKNOWN,
}
