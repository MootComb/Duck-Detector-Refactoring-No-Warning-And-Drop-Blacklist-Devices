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

package com.eltavine.duckdetector.features.tee.data.report

import com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationErrorPathResult
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import org.junit.Assert.assertEquals
import org.junit.Test

class TeeReportReducerOperationPathTest {

    private val reducer = TeeReportReducer()

    private fun completed(
        updateAadRejected: Boolean? = true,
        updateAadAcceptanceExpected: Boolean = false,
        oversizedUpdateRejected: Boolean? = true,
        abortInvalidatedHandle: Boolean? = true,
    ) = OperationErrorPathResult(
        executed = true,
        createOperationSucceeded = true,
        updateAadRejected = updateAadRejected,
        updateAadAcceptanceExpected = updateAadAcceptanceExpected,
        oversizedUpdateRejected = oversizedUpdateRejected,
        abortInvalidatedHandle = abortInvalidatedHandle,
        detail = "probe",
    )

    private fun assertRow(result: OperationErrorPathResult, level: TeeSignalLevel, indicators: Int) {
        val artifacts = baseArtifacts(operationErrorPath = result)
        val row = reducer.reduce(artifacts).sections.flatMap { it.items }.single { it.title == ROW_TITLE }
        assertEquals(row.body, level, row.level)
        assertEquals(indicators, collectSupplementaryIndicators(artifacts).count { it.title == ROW_TITLE })
    }

    @Test
    fun `keystore2 enforced divergence stays a fail`() {
        assertRow(completed(oversizedUpdateRejected = false), TeeSignalLevel.FAIL, indicators = 1)
        assertRow(completed(abortInvalidatedHandle = false), TeeSignalLevel.FAIL, indicators = 1)
    }

    @Test
    fun `updateAad accepted outside known vendors is a review, not a fail`() {
        assertRow(completed(updateAadRejected = false), TeeSignalLevel.WARN, indicators = 1)
    }

    @Test
    fun `updateAad accepted on a known vendor is expected`() {
        assertRow(
            completed(updateAadRejected = false, updateAadAcceptanceExpected = true),
            TeeSignalLevel.PASS,
            indicators = 0,
        )
    }

    @Test
    fun `sub-checks that could not run leave the row partially evaluated`() {
        assertRow(completed(updateAadRejected = null), TeeSignalLevel.INFO, indicators = 0)
    }

    @Test
    fun `a probe that did not complete is not a divergence`() {
        val result = OperationErrorPathResult.notCompleted("IKeystoreSecurityLevel binder was unavailable.")
        assertRow(result, TeeSignalLevel.INFO, indicators = 0)
        val row = reducer.reduce(baseArtifacts(operationErrorPath = result))
            .sections.flatMap { it.items }.single { it.title == ROW_TITLE }
        assertEquals("Did not complete • IKeystoreSecurityLevel binder was unavailable.", row.body)
    }

    private companion object {
        const val ROW_TITLE = "Operation path"
    }
}
