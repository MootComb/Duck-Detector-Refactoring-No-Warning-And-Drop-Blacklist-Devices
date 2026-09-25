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

package com.eltavine.duckdetector.features.update.ui

import com.eltavine.duckdetector.features.update.domain.AvailableNightlyUpdate
import com.eltavine.duckdetector.features.update.domain.NightlyUpdateApk
import com.eltavine.duckdetector.features.update.domain.NightlyUpdateChecker
import com.eltavine.duckdetector.features.update.domain.NightlyUpdateCommit
import com.eltavine.duckdetector.features.update.domain.NightlyUpdateManifest
import com.eltavine.duckdetector.features.update.domain.UpdateChangelogEntry
import com.eltavine.duckdetector.features.update.domain.UpdateCheckResult
import com.eltavine.duckdetector.features.update.presentation.UpdateCheckStatus
import com.eltavine.duckdetector.features.update.presentation.UpdateDownloadResolution
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class UpdateViewModelTest {
    private val dispatcher: TestDispatcher = StandardTestDispatcher()
    private val manifest = NightlyUpdateManifest(
        schemaVersion = 1,
        channel = "nightly",
        branch = "master",
        versionName = "2026.08.08-${TEST_HEAD_SHA.take(12)}",
        versionCode = 500,
        commit = NightlyUpdateCommit(
            sha = TEST_HEAD_SHA,
            subject = "feat(update): publish Nightly metadata",
            body = "Publish metadata after the APK is available.",
            authorName = "Duck Contributor",
            authoredAt = "2026-08-08T12:20:00Z",
        ),
        builtAtUtc = "2026-08-08T12:30:00Z",
        apk = NightlyUpdateApk(
            name = "Duck.Detector-test.apk",
            downloadUrl = "https://github.com/eltavine/Duck-Detector-Refactoring/releases/download/nightly/Duck.Detector-test.apk",
            sizeBytes = 12_345_678L,
            sha256 = "c".repeat(64),
        ),
    )

    @Before
    fun setUp() {
        Dispatchers.setMain(dispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `automatic check runs once while manual check can run again`() = runTest(dispatcher) {
        var calls = 0
        val viewModel = viewModel(
            checker = NightlyUpdateChecker { _, _ ->
                calls += 1
                UpdateCheckResult.Current(manifest)
            },
        )

        viewModel.checkAutomatically()
        viewModel.checkAutomatically()
        advanceUntilIdle()
        assertEquals(1, calls)
        assertEquals(UpdateCheckStatus.CURRENT, viewModel.uiState.value.status)

        viewModel.onSettingsUpdateAction()
        advanceUntilIdle()
        assertEquals(2, calls)
    }

    @Test
    fun `automatic failure is silent while manual failure is visible`() = runTest(dispatcher) {
        val viewModel = viewModel(
            checker = NightlyUpdateChecker { _, _ -> error("offline") },
        )

        viewModel.checkAutomatically()
        advanceUntilIdle()
        assertEquals(UpdateCheckStatus.IDLE, viewModel.uiState.value.status)

        viewModel.onSettingsUpdateAction()
        advanceUntilIdle()
        assertEquals(UpdateCheckStatus.FAILED, viewModel.uiState.value.status)
    }

    @Test
    fun `dismissal lasts for the current state and settings can reopen details`() = runTest(dispatcher) {
        var calls = 0
        val available = availableUpdate()
        val viewModel = viewModel(
            checker = NightlyUpdateChecker { _, _ ->
                calls += 1
                UpdateCheckResult.Available(available)
            },
        )

        viewModel.checkAutomatically()
        advanceUntilIdle()
        assertTrue(viewModel.uiState.value.isDialogVisible)

        viewModel.dismissUpdate()
        assertFalse(viewModel.uiState.value.isDialogVisible)

        viewModel.onSettingsUpdateAction()
        assertTrue(viewModel.uiState.value.isDialogVisible)
        assertEquals(1, calls)

        val nextProcessViewModel = viewModel(
            checker = NightlyUpdateChecker { _, _ -> UpdateCheckResult.Available(available) },
        )
        nextProcessViewModel.checkAutomatically()
        advanceUntilIdle()
        assertTrue(nextProcessViewModel.uiState.value.isDialogVisible)
    }

    @Test
    fun `single run gate only grants its first acquisition`() {
        val gate = SingleRunUpdateCheckGate()

        assertTrue(gate.tryAcquire())
        assertFalse(gate.tryAcquire())
    }

    @Test
    fun `download resolution rechecks an unchanged manifest before opening`() = runTest(dispatcher) {
        val available = availableUpdate()
        val viewModel = viewModel(
            checker = NightlyUpdateChecker { _, _ -> UpdateCheckResult.Available(available) },
        )
        viewModel.checkAutomatically()
        advanceUntilIdle()

        val resolution = viewModel.resolveDownload()

        assertEquals(
            UpdateDownloadResolution.Ready(manifest.apk.downloadUrl),
            resolution,
        )
    }

    @Test
    fun `download resolution refreshes a superseded Nightly instead of opening its stale URL`() =
        runTest(dispatcher) {
            val newerManifest = manifest.copy(
                versionName = "2026.08.09-${NEWER_HEAD_SHA.take(12)}",
                versionCode = 501,
                commit = manifest.commit.copy(sha = NEWER_HEAD_SHA),
                apk = manifest.apk.copy(
                    name = "Duck.Detector-newer.apk",
                    downloadUrl =
                        "https://github.com/eltavine/Duck-Detector-Refactoring/releases/download/nightly/Duck.Detector-newer.apk",
                ),
            )
            var calls = 0
            val viewModel = viewModel(
                checker = NightlyUpdateChecker { _, _ ->
                    calls += 1
                    UpdateCheckResult.Available(
                        if (calls == 1) availableUpdate() else availableUpdate(newerManifest),
                    )
                },
            )
            viewModel.checkAutomatically()
            advanceUntilIdle()

            val resolution = viewModel.resolveDownload()

            assertEquals(UpdateDownloadResolution.Refreshed, resolution)
            assertEquals(newerManifest, viewModel.uiState.value.availableUpdate?.manifest)
            assertTrue(viewModel.uiState.value.isDialogVisible)
        }

    private fun viewModel(checker: NightlyUpdateChecker): UpdateViewModel {
        return UpdateViewModel(
            repository = checker,
            currentVersionCode = 400,
            currentCommitSha = TEST_BASE_SHA,
            automaticCheckGate = SingleRunUpdateCheckGate(),
        )
    }

    private fun availableUpdate(
        updateManifest: NightlyUpdateManifest = manifest,
    ): AvailableNightlyUpdate {
        return AvailableNightlyUpdate(
            manifest = updateManifest,
            changelog = listOf(
                UpdateChangelogEntry(
                    sha = updateManifest.commit.sha,
                    subject = updateManifest.commit.subject,
                    authorName = updateManifest.commit.authorName,
                ),
            ),
            remainingCommitCount = 0,
            compareUrl =
                "https://github.com/eltavine/Duck-Detector-Refactoring/compare/$TEST_BASE_SHA...${updateManifest.commit.sha}",
        )
    }

    private companion object {
        private const val NEWER_HEAD_SHA = "cccccccccccccccccccccccccccccccccccccccc"
    }
}

private const val TEST_HEAD_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
private const val TEST_BASE_SHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
