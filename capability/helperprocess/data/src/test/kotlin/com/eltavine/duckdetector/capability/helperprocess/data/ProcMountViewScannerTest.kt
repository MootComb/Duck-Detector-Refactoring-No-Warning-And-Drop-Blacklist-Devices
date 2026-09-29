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

package com.eltavine.duckdetector.capability.helperprocess.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProcMountViewScannerTest {

    private val scanner = ProcMountViewScanner()

    private val cleanMountInfo = listOf(
        "22 25 8:1 / / rw,relatime - ext4 /dev/block/dm-2 rw,seclabel",
        "30 22 0:28 / /system rw,seclabel - overlay overlay ro,seclabel,lowerdir=/system",
    )

    @Test
    fun `identical mount tables across processes stay clean`() {
        val result = scanner.evaluate(
            pids = listOf("1000", "2000"),
            lineReader = { cleanMountInfo },
        )

        assertTrue(result.available)
        assertEquals(1, result.distinctViewCount)
        assertEquals(1, result.expectedViewCount)
        assertEquals(2, result.scannedPidCount)
        assertFalse(result.divergent)
        assertFalse(result.tokenHit)
    }

    @Test
    fun `divergent mount tables surface hidden mount divergence`() {
        val hiddenView = cleanMountInfo + listOf(
            "55 22 0:29 / /hidden/modules rw,seclabel - overlay overlay ro,seclabel,lowerdir=/hidden/modules",
        )
        val result = scanner.evaluate(
            pids = listOf("1000", "2000"),
            lineReader = { pid -> if (pid == "2000") hiddenView else cleanMountInfo },
        )

        assertTrue(result.available)
        assertEquals(2, result.distinctViewCount)
        assertTrue(result.divergent)
        assertFalse(result.tokenHit)
    }

    @Test
    fun `direct root token in any view is flagged`() {
        val magiskView = listOf(
            "22 25 8:1 / / rw,relatime - ext4 /dev/block/dm-2 rw,seclabel",
            "40 22 8:1 /magisk /system rw,seclabel - overlay overlay ro,seclabel",
        )
        var reads = 0
        val result = scanner.evaluate(
            pids = listOf("1000", "2000", "3000"),
            lineReader = { pid ->
                reads += 1
                if (pid == "2000") magiskView else cleanMountInfo
            },
        )

        assertTrue(result.available)
        assertTrue(result.tokenHit)
        assertEquals(ProcMountViewRootToken.MAGISK, result.token)
        assertEquals(magiskView[1], result.tokenHitDetail)
        assertEquals(2, reads)
        assertEquals(2, result.scannedPidCount)
    }

    @Test
    fun `shared propagation group raises expected view count`() {
        val sharedView = listOf(
            "31 26 8:1 / /mnt/foo rw,relatime shared:1 - tmpfs tmpfs rw",
        ) + cleanMountInfo
        val result = scanner.evaluate(
            pids = listOf("1000", "2000"),
            lineReader = { pid -> if (pid == "2000") sharedView else cleanMountInfo },
        )

        assertTrue(result.available)
        assertEquals(2, result.expectedViewCount)
        assertEquals(2, result.distinctViewCount)
        assertFalse(result.divergent)
    }

    @Test
    fun `tmpfs capacity printed against an older RAM total stays one view`() {
        val appDataPoints = listOf(
            "/data/data",
            "/data/user",
            "/data/user_de",
            "/data/misc/profiles/cur",
            "/data/misc/profiles/ref",
        )
        val bootTimeView = cleanMountInfo + appDataPoints.mapIndexed { index, point ->
            "${120 + index} 22 0:${40 + index} / $point rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs " +
                "rw,seclabel,size=2878476k,nr_inodes=719619,mode=751"
        }
        val laterView = cleanMountInfo + appDataPoints.mapIndexed { index, point ->
            "${980 + index} 22 0:${212 + index} / $point rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs " +
                "rw,seclabel,mode=751"
        }
        val result = scanner.evaluate(
            pids = listOf("1000", "2000"),
            lineReader = { pid -> if (pid == "2000") laterView else bootTimeView },
        )

        assertTrue(result.available)
        assertEquals(1, result.distinctViewCount)
        assertFalse(result.divergent)
    }

    @Test
    fun `tmpfs mounts that differ beyond capacity stay distinct views`() {
        val stockView = cleanMountInfo + listOf(
            "120 22 0:40 / /data/data rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs " +
                "rw,seclabel,size=2878476k,nr_inodes=719619,mode=751",
        )
        val changedView = cleanMountInfo + listOf(
            "980 22 0:212 / /data/data rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,mode=755",
        )
        val result = scanner.evaluate(
            pids = listOf("1000", "2000"),
            lineReader = { pid -> if (pid == "2000") changedView else stockView },
        )

        assertEquals(2, result.distinctViewCount)
        assertTrue(result.divergent)
    }

    @Test
    fun `size option outside shmem filesystems still separates views`() {
        val sizedView = cleanMountInfo + listOf(
            "60 22 0:50 / /dev/hugepages rw,relatime - hugetlbfs hugetlbfs rw,seclabel,pagesize=2M,size=1073741824",
        )
        val unsizedView = cleanMountInfo + listOf(
            "60 22 0:50 / /dev/hugepages rw,relatime - hugetlbfs hugetlbfs rw,seclabel,pagesize=2M",
        )
        val result = scanner.evaluate(
            pids = listOf("1000", "2000"),
            lineReader = { pid -> if (pid == "2000") unsizedView else sizedView },
        )

        assertEquals(2, result.distinctViewCount)
        assertTrue(result.divergent)
    }

    @Test
    fun `devtmpfs and rootfs capacity is ignored like tmpfs`() {
        listOf("devtmpfs" to "/dev", "rootfs" to "/").forEach { (type, point) ->
            val result = scanner.evaluate(
                pids = listOf("1000", "2000"),
                lineReader = { pid ->
                    val capacity = if (pid == "1000") "size=2878476k,nr_inodes=719619," else ""
                    listOf("2 1 0:2 / $point rw,relatime - $type $type rw,seclabel,${capacity}mode=755")
                },
            )

            assertEquals(type, 1, result.distinctViewCount)
        }
    }

    @Test
    fun `unreadable processes are skipped`() {
        val result = scanner.evaluate(
            pids = listOf("1000", "3000", "2000"),
            lineReader = { pid -> if (pid == "3000") emptyList() else cleanMountInfo },
        )

        assertTrue(result.available)
        assertEquals(3, result.scannedPidCount)
        assertEquals(1, result.distinctViewCount)
        assertFalse(result.divergent)
    }

    @Test
    fun `all unreadable mount tables are reported unavailable not divergent`() {
        val result = scanner.evaluate(
            pids = listOf("1000", "2000", "3000"),
            lineReader = { emptyList() },
        )

        assertFalse(result.available)
        assertFalse(result.divergent)
        assertTrue(result.detail.contains("no process mount table was readable"))
    }

    @Test
    fun `unavailable scanner when proc directory missing`() {
        val result = ProcMountViewScanner(
            procDirectoryProvider = { java.io.File("/nonexistent-proc-dir") },
        ).scan()

        assertFalse(result.available)
        assertFalse(result.divergent)
    }
}
