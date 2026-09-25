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
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.eltavine.duckdetector.BuildConfig
import com.eltavine.duckdetector.R
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.CompositionLocalProvider
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.notifications.ScanNotificationPermissions
import com.eltavine.duckdetector.core.notifications.ScanProgressNotificationSnapshot
import com.eltavine.duckdetector.core.notifications.ScanProgressNotifier
import com.eltavine.duckdetector.core.notifications.preferences.ScanNotificationConsentStore
import com.eltavine.duckdetector.core.notifications.preferences.ScanNotificationPrefs
import com.eltavine.duckdetector.capability.packageinventory.data.InstalledPackageVisibilityChecker
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageInventoryResult
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import com.eltavine.duckdetector.core.packagevisibility.preferences.PackageVisibilityReviewPrefs
import com.eltavine.duckdetector.core.packagevisibility.preferences.PackageVisibilityReviewStore
import com.eltavine.duckdetector.core.startup.legal.AgreementAcceptancePrefs
import com.eltavine.duckdetector.core.startup.legal.AgreementAcceptanceStore
import com.eltavine.duckdetector.core.startup.legal.AgreementScreen
import com.eltavine.duckdetector.core.ui.components.AlphaBuildBanner
import com.eltavine.duckdetector.core.ui.components.AlphaBuildWarningOverlay
import com.eltavine.duckdetector.core.ui.components.DetectorAutoExpansionDirective
import com.eltavine.duckdetector.core.ui.components.LocalDetectorAutoExpansionDirective
import com.eltavine.duckdetector.core.ui.components.ScreenshotWatermarkOverlay
import com.eltavine.duckdetector.core.ui.openExternalUri
import com.eltavine.duckdetector.features.dashboard.ui.DashboardScreen
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardUiState
import com.eltavine.duckdetector.features.dashboard.ui.model.buildDashboardFindings
import com.eltavine.duckdetector.features.dashboard.ui.model.buildDashboardOverview
import com.eltavine.duckdetector.features.dashboard.ui.model.dashboardCardOrder
import com.eltavine.duckdetector.features.settings.ui.SettingsScreen
import com.eltavine.duckdetector.features.settings.presentation.model.SettingsUiState
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkConsentStore
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefs
import com.eltavine.duckdetector.features.update.presentation.UpdateDownloadResolution
import com.eltavine.duckdetector.features.update.ui.UpdateViewModel
import com.eltavine.duckdetector.features.update.ui.NightlyUpdateDialog
import com.eltavine.duckdetector.ui.shell.AppDestination
import com.eltavine.duckdetector.ui.shell.DetectorResultNoticeDialog
import com.eltavine.duckdetector.ui.shell.ScreenCaptureNoticeDialog
import com.eltavine.duckdetector.ui.shell.ScreenCaptureNoticeEffect
import com.eltavine.duckdetector.ui.shell.attentionDetectorIds
import com.eltavine.duckdetector.ui.shell.detectorResultNoticeKey
import com.eltavine.duckdetector.ui.shell.FloatingAppTabSwitcher
import com.eltavine.duckdetector.ui.shell.StartupGateState
import com.eltavine.duckdetector.ui.shell.StartupPackageVisibilityState
import com.eltavine.duckdetector.ui.shell.StartupPolicyScreen
import com.eltavine.duckdetector.ui.scan.DetectorScanViewModel
import com.eltavine.duckdetector.ui.shell.resolveStartupGateState
import com.eltavine.duckdetector.ui.shell.shouldShowDetectorResultNotice
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

@Composable
private fun AppReadyShell(
    destination: AppDestination,
    onSelectDestination: (AppDestination) -> Unit,
    networkPrefs: TeeNetworkPrefs,
    consentStore: TeeNetworkConsentStore,
    notificationPermissionState: com.eltavine.duckdetector.core.notifications.ScanNotificationPermissionState,
    canShowUpdateDialog: Boolean,
) {
    val context = LocalContext.current
    val appContext = context.applicationContext
    val updateOpenFailedMessage = stringResource(R.string.update_open_failed)
    val scope = rememberCoroutineScope()
    var isResolvingUpdateDownload by remember { mutableStateOf(false) }
    val notifier = remember(appContext) { ScanProgressNotifier(appContext) }
    val updateFactory = remember(context) { updateViewModelFactory(context) }
    val updateViewModel: UpdateViewModel = viewModel(factory = updateFactory)
    // Every detector view model starts scanning when it is created, so this order is the order in
    // which detector scans begin; it is kept exactly as it was when the shell created them itself.
    val bootloader = DetectorFeatures.bootloader.rememberSession()
    val tee = DetectorFeatures.tee.rememberSession()
    val customRom = DetectorFeatures.customRom.rememberSession()
    val dangerousApps = DetectorFeatures.dangerousApps.rememberSession()
    val deviceProfile = DetectorFeatures.deviceProfile.rememberSession()
    val kernelCheck = DetectorFeatures.kernelCheck.rememberSession()
    val lsposed = DetectorFeatures.lsposed.rememberSession()
    val memory = DetectorFeatures.memory.rememberSession()
    val mount = DetectorFeatures.mount.rememberSession()
    val nativeRoot = DetectorFeatures.nativeRoot.rememberSession()
    val playIntegrityFix = DetectorFeatures.playIntegrityFix.rememberSession()
    val selinux = DetectorFeatures.selinux.rememberSession()
    val su = DetectorFeatures.su.rememberSession()
    val systemProperties = DetectorFeatures.systemProperties.rememberSession()
    val virtualization = DetectorFeatures.virtualization.rememberSession()
    val zygisk = DetectorFeatures.zygisk.rememberSession()
    val detectors = remember(bootloader, customRom, dangerousApps, kernelCheck, lsposed, memory, mount, nativeRoot, playIntegrityFix, selinux, su, systemProperties, tee, virtualization, zygisk) {
        listOf(bootloader, customRom, dangerousApps, kernelCheck, lsposed, memory, mount, nativeRoot, playIntegrityFix, selinux, su, systemProperties, tee, virtualization, zygisk)
    }
    val updateUiState by updateViewModel.uiState.collectAsState()

    LaunchedEffect(updateViewModel) {
        updateViewModel.checkAutomatically()
    }
    val scanViewModel: DetectorScanViewModel = viewModel(
        factory = remember { DetectorScanViewModel.factory(detectors.map { it.summary }) },
    )
    val scanState by scanViewModel.coordinator.state.collectAsState()
    val detectorSummaries = scanState.detectors
    val isDashboardLoading = scanState.isLoading
    val dashboardScanDurationMillis = scanState.timeline.durationMillis
    val dashboardScanCompletedAtEpochMillis = scanState.timeline.completedAtEpochMillis

    val dashboardState = remember(
        detectorSummaries,
        dashboardScanDurationMillis,
        dashboardScanCompletedAtEpochMillis,
        isDashboardLoading,
    ) {
        DashboardUiState(
            overview = buildDashboardOverview(
                contributions = detectorSummaries,
                scanDurationMillis = dashboardScanDurationMillis,
                scanCompletedAtEpochMillis = dashboardScanCompletedAtEpochMillis,
            ),
            topFindings = buildDashboardFindings(detectorSummaries),
            cardOrder = dashboardCardOrder(detectorSummaries),
            isLoading = isDashboardLoading,
        )
    }
    val settingsState = remember(networkPrefs.consentGranted, updateUiState.status) {
        SettingsUiState(
            isCrlNetworkingEnabled = networkPrefs.consentGranted,
            versionName = BuildConfig.VERSION_NAME,
            versionCode = BuildConfig.VERSION_CODE,
            buildTimeUtc = BuildConfig.BUILD_TIME_UTC,
            buildHash = BuildConfig.BUILD_HASH,
            updateStatus = updateUiState.status.toSettingsUpdateStatus(),
        )
    }
    val detectorResultNoticeKey = remember(isDashboardLoading, dashboardState.overview) {
        if (!shouldShowDetectorResultNotice(isDashboardLoading, dashboardState.overview.status)) {
            null
        } else {
            detectorResultNoticeKey(dashboardState.overview)
        }
    }
    var dismissedDetectorResultNoticeKey by rememberSaveable { mutableStateOf<String?>(null) }
    val detectorsNeedingAttention = remember(detectorSummaries) {
        attentionDetectorIds(detectorSummaries)
    }
    var pendingAttentionExpansionIds by rememberSaveable { mutableStateOf(emptyList<String>()) }

    LaunchedEffect(detectorResultNoticeKey, detectorsNeedingAttention) {
        if (detectorResultNoticeKey == null) {
            dismissedDetectorResultNoticeKey = null
            pendingAttentionExpansionIds = emptyList()
        } else {
            pendingAttentionExpansionIds = detectorsNeedingAttention.map { it.value }
        }
    }

    val notificationSnapshot = remember(
        detectorSummaries.size,
        detectorSummaries.count { it.ready },
        dashboardState.overview,
        isDashboardLoading,
    ) {
        ScanProgressNotificationSnapshot(
            totalDetectorCount = detectorSummaries.size,
            readyDetectorCount = detectorSummaries.count { it.ready },
            dashboardOverview = dashboardState.overview,
            scanning = isDashboardLoading,
        )
    }

    LaunchedEffect(notificationPermissionState, notificationSnapshot) {
        notifier.update(
            permissionState = notificationPermissionState,
            snapshot = notificationSnapshot,
        )
    }

    Box(modifier = Modifier.fillMaxSize()) {
        when (destination) {
            AppDestination.MAIN -> {
                CompositionLocalProvider(
                    LocalDetectorAutoExpansionDirective provides DetectorAutoExpansionDirective(
                        detectorIds = pendingAttentionExpansionIds.mapTo(linkedSetOf(), ::DetectorId),
                        onConsumed = { detectorId ->
                            pendingAttentionExpansionIds =
                                pendingAttentionExpansionIds.filterNot { it == detectorId.value }
                        },
                    ),
                ) {
                    DashboardScreen(
                        uiState = dashboardState,
                        detectors = detectors,
                        deviceProfile = deviceProfile,
                    )
                }
            }

            AppDestination.SETTINGS -> {
                SettingsScreen(
                    uiState = settingsState,
                    onCrlNetworkingChange = { enabled ->
                        scope.launch {
                            consentStore.setConsent(enabled)
                            tee.rescan()
                        }
                    },
                    onCheckForUpdates = updateViewModel::onSettingsUpdateAction,
                    modifier = Modifier.fillMaxSize(),
                )
            }
        }

        FloatingAppTabSwitcher(
            selectedDestination = destination,
            onSelectDestination = onSelectDestination,
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .padding(end = 20.dp, bottom = 28.dp),
        )

        if (
            detectorResultNoticeKey != null &&
            detectorResultNoticeKey != dismissedDetectorResultNoticeKey
        ) {
            DetectorResultNoticeDialog(
                onDismiss = {
                    dismissedDetectorResultNoticeKey = detectorResultNoticeKey
                },
            )
        } else if (
            canShowUpdateDialog &&
            updateUiState.isDialogVisible &&
            updateUiState.availableUpdate != null
        ) {
            val availableUpdate = requireNotNull(updateUiState.availableUpdate)
            NightlyUpdateDialog(
                currentVersionName = BuildConfig.VERSION_NAME,
                update = availableUpdate,
                downloadEnabled = !isResolvingUpdateDownload,
                onDismiss = updateViewModel::dismissUpdate,
                onViewChanges = {
                    if (!openExternalUri(context, availableUpdate.compareUrl)) {
                        Toast.makeText(
                            context,
                            updateOpenFailedMessage,
                            Toast.LENGTH_SHORT,
                        ).show()
                    }
                },
                onDownload = {
                    if (!isResolvingUpdateDownload) {
                        isResolvingUpdateDownload = true
                        scope.launch {
                            try {
                                when (val resolution = updateViewModel.resolveDownload()) {
                                    is UpdateDownloadResolution.Ready -> {
                                        if (openExternalUri(context, resolution.url)) {
                                            updateViewModel.dismissUpdate()
                                        } else {
                                            Toast.makeText(
                                                context,
                                                updateOpenFailedMessage,
                                                Toast.LENGTH_SHORT,
                                            ).show()
                                        }
                                    }

                                    UpdateDownloadResolution.Failed -> {
                                        Toast.makeText(
                                            context,
                                            updateOpenFailedMessage,
                                            Toast.LENGTH_SHORT,
                                        ).show()
                                    }

                                    UpdateDownloadResolution.Current,
                                    UpdateDownloadResolution.Refreshed -> Unit
                                }
                            } finally {
                                isResolvingUpdateDownload = false
                            }
                        }
                    }
                },
            )
        }
    }
}

@Composable
private fun StartupBootstrapLoadingScreen(
    modifier: Modifier = Modifier,
) {
    Box(
        modifier = modifier,
        contentAlignment = Alignment.Center,
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            CircularProgressIndicator()
            Text(
                text = "Preparing startup",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = "Loading agreement state before startup policy review.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
