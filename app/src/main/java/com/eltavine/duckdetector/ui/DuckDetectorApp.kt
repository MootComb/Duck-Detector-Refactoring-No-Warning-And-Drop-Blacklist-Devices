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

package com.eltavine.duckdetector.ui

import android.Manifest
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import com.eltavine.duckdetector.BuildConfig
import com.eltavine.duckdetector.notifications.ScanNotificationPermissions
import com.eltavine.duckdetector.notifications.preferences.ScanNotificationConsentStore
import com.eltavine.duckdetector.notifications.preferences.ScanNotificationPrefs
import com.eltavine.duckdetector.capability.packageinventory.data.InstalledPackageVisibilityChecker
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageInventoryResult
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import com.eltavine.duckdetector.packagevisibility.preferences.PackageVisibilityReviewPrefs
import com.eltavine.duckdetector.packagevisibility.preferences.PackageVisibilityReviewStore
import com.eltavine.duckdetector.startup.legal.AgreementAcceptancePrefs
import com.eltavine.duckdetector.startup.legal.AgreementAcceptanceStore
import com.eltavine.duckdetector.startup.legal.AgreementScreen
import com.eltavine.duckdetector.core.ui.components.AlphaBuildBanner
import com.eltavine.duckdetector.core.ui.components.AlphaBuildWarningOverlay
import com.eltavine.duckdetector.core.ui.components.ScreenshotWatermarkOverlay
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkConsentStore
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefs
import com.eltavine.duckdetector.ui.shell.AppDestination
import com.eltavine.duckdetector.ui.shell.ScreenCaptureNoticeDialog
import com.eltavine.duckdetector.ui.shell.ScreenCaptureNoticeEffect
import com.eltavine.duckdetector.ui.shell.StartupPackageVisibilityState
import com.eltavine.duckdetector.ui.shell.StartupPolicyScreen
import com.eltavine.duckdetector.ui.shell.resolveStartupGateState
import com.eltavine.duckdetector.ui.shell.shouldCreateDetectorViewModels
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun DuckDetectorApp() {
    val blacklistMatch = remember { DeviceBlacklist.matchCurrentDevice() }
    if (blacklistMatch != null) {
        Surface {
            BlockedDeviceScreen(
                match = blacklistMatch,
                modifier = Modifier.fillMaxSize(),
            )
        }
        return
    }

    val context = LocalContext.current
    val appContext = context.applicationContext
    val agreementStore = remember(appContext) { AgreementAcceptanceStore.getInstance(appContext) }
    val consentStore = remember(appContext) { TeeNetworkConsentStore.getInstance(appContext) }
    val notificationConsentStore = remember(appContext) {
        ScanNotificationConsentStore.getInstance(appContext)
    }
    val packageVisibilityReviewStore = remember(appContext) {
        PackageVisibilityReviewStore.getInstance(appContext)
    }
    val agreementPrefs by produceState<AgreementAcceptancePrefs?>(
        initialValue = null,
        key1 = agreementStore,
    ) {
        agreementStore.prefs.collect { currentPrefs ->
            value = currentPrefs
        }
    }
    val agreementAccepted = agreementPrefs?.accepted == true
    val teePrefs by produceState<TeeNetworkPrefs?>(
        initialValue = null,
        key1 = consentStore,
        key2 = agreementAccepted,
    ) {
        if (!agreementAccepted) {
            value = null
            return@produceState
        }
        consentStore.prefs.collect { currentPrefs ->
            value = currentPrefs
        }
    }
    val notificationPrefs by produceState<ScanNotificationPrefs?>(
        initialValue = null,
        key1 = notificationConsentStore,
        key2 = agreementAccepted,
    ) {
        if (!agreementAccepted) {
            value = null
            return@produceState
        }
        notificationConsentStore.prefs.collect { currentPrefs ->
            value = currentPrefs
        }
    }
    val packageVisibilityReviewPrefs by produceState<PackageVisibilityReviewPrefs?>(
        initialValue = null,
        key1 = packageVisibilityReviewStore,
        key2 = agreementAccepted,
    ) {
        if (!agreementAccepted) {
            value = null
            return@produceState
        }
        packageVisibilityReviewStore.prefs.collect { currentPrefs ->
            value = currentPrefs
        }
    }
    val packageVisibilityState by produceState<StartupPackageVisibilityState?>(
        initialValue = null,
        key1 = appContext,
        key2 = agreementAccepted,
    ) {
        if (!agreementAccepted) {
            value = null
            return@produceState
        }
        value = withContext(Dispatchers.IO) {
            val inventoryResult = InstalledPackageVisibilityChecker.inspect(appContext)
            val inventory = (inventoryResult as? InstalledPackageInventoryResult.Available)
                ?.inventory
            StartupPackageVisibilityState(
                visibility = inventory?.visibility ?: InstalledPackageVisibility.UNKNOWN,
                visiblePackageCount = inventory?.visiblePackageCount ?: 0,
                suspiciouslyLowInventory = inventory?.suspiciouslyLowInventory ?: false,
            )
        }
    }
    var notificationPermissionState by remember {
        mutableStateOf(ScanNotificationPermissions.read(appContext))
    }
    val gateState = remember(
        teePrefs,
        notificationPrefs,
        notificationPermissionState,
        packageVisibilityState,
        packageVisibilityReviewPrefs,
    ) {
        resolveStartupGateState(
            teePrefs = teePrefs,
            notificationPrefs = notificationPrefs,
            notificationPermissionState = notificationPermissionState,
            packageVisibilityLoaded = packageVisibilityState != null &&
                    packageVisibilityReviewPrefs != null,
            packageVisibility = packageVisibilityState?.visibility
                ?: InstalledPackageVisibility.UNKNOWN,
            packageVisibilityReviewAcknowledged =
                packageVisibilityReviewPrefs?.restrictedInventoryAcknowledged == true,
        )
    }
    val startupPoliciesReady = shouldCreateDetectorViewModels(gateState)
    val requiresAlphaAcknowledgement = BuildConfig.isAlphaVersion
    var alphaAcknowledged by rememberSaveable(BuildConfig.VERSION_NAME) {
        mutableStateOf(false)
    }
    var destination by rememberSaveable { mutableStateOf(AppDestination.MAIN) }
    var screenCaptureNoticeEventId by remember { mutableLongStateOf(0L) }
    val scope = rememberCoroutineScope()
    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
    ) {
        notificationPermissionState = ScanNotificationPermissions.read(appContext)
        scope.launch {
            notificationConsentStore.markNotificationsPrompted()
        }
    }
    val liveUpdateSettingsLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult(),
    ) {
        notificationPermissionState = ScanNotificationPermissions.read(appContext)
        if (notificationPermissionState.liveUpdatesGranted) {
            scope.launch {
                notificationConsentStore.markLiveUpdatesPrompted()
            }
        }
    }

    LaunchedEffect(notificationPrefs, notificationPermissionState) {
        val prefs = notificationPrefs ?: return@LaunchedEffect
        if (notificationPermissionState.notificationsGranted && !prefs.notificationsPrompted) {
            notificationConsentStore.markNotificationsPrompted()
        }
        if (notificationPermissionState.liveUpdatesGranted && !prefs.liveUpdatesPrompted) {
            notificationConsentStore.markLiveUpdatesPrompted()
        }
    }

    Surface {
        Box(modifier = Modifier.fillMaxSize()) {
            ScreenCaptureNoticeEffect(
                onScreenCaptured = {
                    screenCaptureNoticeEventId += 1L
                },
            )

            when {
                agreementPrefs == null -> {
                    StartupBootstrapLoadingScreen(modifier = Modifier.fillMaxSize())
                }

                !agreementAccepted -> {
                    AgreementScreen(
                        onAgree = {
                            scope.launch {
                                agreementStore.accept()
                            }
                        },
                        modifier = Modifier.fillMaxSize(),
                    )
                }

                startupPoliciesReady -> {
                    AppReadyShell(
                        destination = destination,
                        onSelectDestination = { selected -> destination = selected },
                        networkPrefs = requireNotNull(teePrefs),
                        consentStore = consentStore,
                        notificationPermissionState = notificationPermissionState,
                        canShowUpdateDialog = (!requiresAlphaAcknowledgement || alphaAcknowledged) &&
                                screenCaptureNoticeEventId == 0L,
                    )
                }

                else -> {
                    StartupPolicyScreen(
                        gateState = gateState,
                        notificationPrefs = notificationPrefs,
                        notificationPermissionState = notificationPermissionState,
                        teePrefs = teePrefs,
                        packageVisibilityState = packageVisibilityState,
                        packageVisibilityReviewAcknowledged =
                            packageVisibilityReviewPrefs?.restrictedInventoryAcknowledged == true,
                        onAllowNotifications = {
                            if (Build.VERSION.SDK_INT >= 33) {
                                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                            } else {
                                scope.launch {
                                    notificationConsentStore.markNotificationsPrompted()
                                }
                            }
                        },
                        onSkipNotifications = {
                            scope.launch {
                                notificationConsentStore.markNotificationsPrompted()
                            }
                        },
                        onOpenLiveUpdateSettings = {
                            val intent = ScanNotificationPermissions
                                .appNotificationPromotionSettingsIntent(appContext)
                            val canOpenSettings =
                                intent.resolveActivity(appContext.packageManager) != null
                            if (canOpenSettings) {
                                liveUpdateSettingsLauncher.launch(intent)
                            } else {
                                scope.launch {
                                    notificationConsentStore.markLiveUpdatesPrompted()
                                }
                            }
                        },
                        onUseRegularNotifications = {
                            scope.launch {
                                notificationConsentStore.markLiveUpdatesPrompted()
                            }
                        },
                        onAllowCrlNetwork = {
                            scope.launch {
                                consentStore.setConsent(true)
                            }
                        },
                        onUseLocalCrlOnly = {
                            scope.launch {
                                consentStore.setConsent(false)
                            }
                        },
                        onAcknowledgePackageVisibility = {
                            scope.launch {
                                packageVisibilityReviewStore.acknowledgeRestrictedInventory()
                            }
                        },
                        modifier = Modifier.fillMaxSize(),
                    )
                }
            }

            ScreenshotWatermarkOverlay()

            if (agreementAccepted && startupPoliciesReady) {
                AlphaBuildBanner()
            }

            AlphaBuildWarningOverlay(
                forceVisible = agreementAccepted &&
                        requiresAlphaAcknowledgement &&
                        !alphaAcknowledged,
                onDismissed = {
                    alphaAcknowledged = true
                },
            )

            if (screenCaptureNoticeEventId > 0L) {
                ScreenCaptureNoticeDialog(
                    noticeInstanceKey = screenCaptureNoticeEventId,
                    onDismiss = {
                        screenCaptureNoticeEventId = 0L
                    },
                )
            }
        }
    }
}
