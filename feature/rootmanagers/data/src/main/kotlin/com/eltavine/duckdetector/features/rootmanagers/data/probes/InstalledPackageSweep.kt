/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

package com.eltavine.duckdetector.features.rootmanagers.data.probes

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import com.eltavine.duckdetector.core.evidence.FailureName
import com.eltavine.duckdetector.features.rootmanagers.domain.CertificateFingerprint
import com.eltavine.duckdetector.features.rootmanagers.domain.ObservationSource
import com.eltavine.duckdetector.features.rootmanagers.domain.ObservedApp

internal data class PackageSweepResult(
    val observations: List<ObservedApp>,
    val visibility: InstalledPackageVisibility,
    val certificatesRead: Int,
    val certificateReadFailures: Int,
    val issue: String? = null,
) {
    companion object {
        fun unavailable(issue: String): PackageSweepResult = PackageSweepResult(
            observations = emptyList(),
            visibility = InstalledPackageVisibility.UNKNOWN,
            certificatesRead = 0,
            certificateReadFailures = 0,
            issue = issue,
        )
    }
}

/**
 * Reads the caller's own profile through PackageManager, the only path that reports signing
 * certificates. One `getInstalledPackages(GET_SIGNING_CERTIFICATES)` call carries the certificate of
 * every visible app, so a manager renamed past its package, label and class names is still caught
 * by the key its own kernel was built to trust, without a round trip per app.
 */
internal class InstalledPackageSweep(
    private val context: Context,
    private val profileUserId: Int,
    private val inspector: AppIdentityInspector,
    /** Maps "the caller saw its own package" to a visibility verdict through the shared policy. */
    private val visibilityFor: (callerObserved: Boolean) -> InstalledPackageVisibility,
) {

    @Suppress("DEPRECATION")
    fun sweep(): PackageSweepResult {
        val packageManager = context.packageManager
        val flags = PackageManager.GET_SIGNING_CERTIFICATES
        val packages = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                packageManager.getInstalledPackages(flags)
            }
        } catch (failure: Exception) {
            return PackageSweepResult.unavailable(
                "The installed-package sweep was unavailable: ${FailureName.messageOrName(failure)}",
            )
        }

        var certificatesRead = 0
        var certificateReadFailures = 0
        val observations = packages.map { packageInfo ->
            val certificates = SigningCertificates.of(packageInfo)
            if (certificates == null) certificateReadFailures++ else certificatesRead++
            packageInfo.toObservation(certificates.orEmpty())
        }
        val callerObserved = packages.any { packageInfo -> packageInfo.packageName == context.packageName }
        return PackageSweepResult(
            observations = observations,
            visibility = visibilityFor(callerObserved),
            certificatesRead = certificatesRead,
            certificateReadFailures = certificateReadFailures,
        )
    }

    private fun PackageInfo.toObservation(certificates: List<CertificateFingerprint>): ObservedApp {
        val info = applicationInfo
        return ObservedApp(
            profileUserId = profileUserId,
            packageName = packageName,
            source = ObservationSource.PACKAGE_MANAGER,
            applicationClassName = info?.className,
            zygotePreloadName = inspector.zygotePreloadName(info),
            signingCertificates = certificates,
            nativePayloads = inspector.nativePayloads(info),
            sourceDir = info?.sourceDir,
            uid = info?.uid,
            firstInstallTime = firstInstallTime,
        )
    }
}
