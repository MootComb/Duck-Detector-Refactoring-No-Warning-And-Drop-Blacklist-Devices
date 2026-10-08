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
import android.content.pm.LauncherActivityInfo
import android.content.pm.LauncherApps
import android.os.UserHandle
import com.eltavine.duckdetector.core.evidence.FailureName
import com.eltavine.duckdetector.features.rootmanagers.domain.ObservationSource
import com.eltavine.duckdetector.features.rootmanagers.domain.ObservedApp
import com.eltavine.duckdetector.features.rootmanagers.domain.ProfileScanState

/**
 * `PackageManager.APP_DETAILS_ACTIVITY_CLASS_NAME` is `@hide`. `LauncherAppsService` injects a
 * launcher entry with this component for a non-system app that requests permissions and declares a
 * launcher activity enabled by default but disabled at runtime, i.e. an app that hid its icon.
 */
internal const val APP_DETAILS_ACTIVITY = "android.app.AppDetailsActivity"

internal data class ProfileObservation(
    val profileUserId: Int,
    val state: ProfileScanState,
    val launcherActivitiesSeen: Int,
    val apps: List<ObservedApp>,
)

internal sealed interface LauncherEnumerationResult {

    data class Enumerated(
        val profiles: List<ProfileObservation>,
        val issues: List<String>,
    ) : LauncherEnumerationResult

    data class Unavailable(val reason: String) : LauncherEnumerationResult

    data class Undecidable(val reason: String) : LauncherEnumerationResult
}

/**
 * Enumerates every launcher activity the caller can see, in each profile `LauncherApps` exposes.
 *
 * For a normal caller `getProfiles()` returns the caller's profile group minus hidden profiles, so
 * Android 15's Private Space is left out unless the caller holds `ACCESS_HIDDEN_PROFILES`; a caller
 * inside a managed profile sees only itself. `getActivityList` returns an empty list both for a
 * profile with nothing to launch and for one the service refuses, so an empty profile is recorded as
 * not observed. Only an unrelated profile makes the service throw `SecurityException`.
 */
internal class LauncherProfileEnumerator(
    private val context: Context,
    private val inspector: AppIdentityInspector,
) {

    fun enumerate(): LauncherEnumerationResult {
        val launcherApps = context.getSystemService(LauncherApps::class.java)
            ?: return LauncherEnumerationResult.Unavailable("This device exposes no LauncherApps service.")

        val profiles = try {
            launcherApps.profiles
        } catch (denied: SecurityException) {
            return LauncherEnumerationResult.Unavailable(
                "The platform denied the profile list: ${FailureName.messageOrName(denied)}",
            )
        }
        if (profiles.isEmpty()) {
            return LauncherEnumerationResult.Undecidable("The platform returned no accessible profiles.")
        }

        val issues = mutableListOf<String>()
        val observations = profiles.map { user -> observe(launcherApps, user, issues) }
        if (observations.none { observation -> observation.state == ProfileScanState.SEARCHED }) {
            return LauncherEnumerationResult.Unavailable("No accessible profile returned a launcher activity.")
        }
        return LauncherEnumerationResult.Enumerated(observations, issues)
    }

    private fun observe(launcherApps: LauncherApps, user: UserHandle, issues: MutableList<String>): ProfileObservation {
        val profileUserId = user.profileId()
        val activities = try {
            launcherApps.getActivityList(null, user)
        } catch (denied: SecurityException) {
            issues += "Profile $profileUserId was denied: ${FailureName.messageOrName(denied)}"
            return ProfileObservation(profileUserId, ProfileScanState.DENIED, 0, emptyList())
        }
        if (activities.isEmpty()) {
            issues += "Profile $profileUserId returned no launcher activity, so it was not observed."
            return ProfileObservation(profileUserId, ProfileScanState.EMPTY, 0, emptyList())
        }
        return ProfileObservation(
            profileUserId = profileUserId,
            state = ProfileScanState.SEARCHED,
            launcherActivitiesSeen = activities.size,
            apps = activities.map { activity -> activity.toObservedApp(profileUserId) },
        )
    }

    private fun LauncherActivityInfo.toObservedApp(profileUserId: Int): ObservedApp {
        val info = applicationInfo
        val component = componentName
        return ObservedApp(
            profileUserId = profileUserId,
            packageName = component.packageName,
            source = ObservationSource.LAUNCHER_APPS,
            componentClassName = component.className,
            applicationClassName = info?.className,
            label = label?.toString(),
            zygotePreloadName = inspector.zygotePreloadName(info),
            nativePayloads = inspector.nativePayloads(info),
            hidesLauncherIcon = component.className == APP_DETAILS_ACTIVITY,
            sourceDir = info?.sourceDir,
            uid = info?.uid,
            firstInstallTime = firstInstallTime,
        )
    }
}

// UserHandle.getIdentifier() is @SystemApi and invisible to a normal app, while the public
// hashCode() returns the same user id (AOSP UserHandle.hashCode() == mHandle). It only labels and
// groups profiles, never matches a manager.
internal fun UserHandle.profileId(): Int = hashCode()
