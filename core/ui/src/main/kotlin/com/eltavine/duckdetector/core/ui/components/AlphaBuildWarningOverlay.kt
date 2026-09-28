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

package com.eltavine.duckdetector.core.ui.components

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.eltavine.duckdetector.core.ui.LocalAppBuildInfo
import com.eltavine.duckdetector.core.ui.openExternalUri
import kotlinx.coroutines.delay

private const val APP_ERRORS_TRACKING_GITHUB =
    "https://github.com/KitsunePie/AppErrorsTracking/actions"
private const val APP_ERRORS_TRACKING_TELEGRAM =
    "https://t.me/AppErrorsTracking_CI"
private const val DISMISS_LOCK_SECONDS = 3

/**
 * Warns that this is an alpha build. It can be dismissed only after [DISMISS_LOCK_SECONDS], so the
 * warning is read rather than tapped away.
 */
@Composable
public fun AlphaBuildWarningOverlay(
    versionName: String = LocalAppBuildInfo.current.versionName,
    isAlphaBuild: Boolean = LocalAppBuildInfo.current.isAlphaVersion,
    forceVisible: Boolean? = null,
    onDismissed: (() -> Unit)? = null,
) {
    var internalVisible by rememberSaveable(versionName, isAlphaBuild) { mutableStateOf(isAlphaBuild) }
    var remainingSeconds by rememberSaveable(versionName, isAlphaBuild) {
        mutableIntStateOf(if (isAlphaBuild) DISMISS_LOCK_SECONDS else 0)
    }
    val visible = forceVisible ?: internalVisible

    LaunchedEffect(visible, isAlphaBuild) {
        if (!visible || !isAlphaBuild) {
            return@LaunchedEffect
        }
        remainingSeconds = DISMISS_LOCK_SECONDS
        while (remainingSeconds > 0) {
            delay(1_000L)
            remainingSeconds -= 1
        }
    }

    if (!visible || !isAlphaBuild) {
        return
    }

    val context = LocalContext.current
    val canDismiss = remainingSeconds == 0
    val dismiss = {
        if (canDismiss) {
            if (forceVisible == null) {
                internalVisible = false
            }
            onDismissed?.invoke()
        }
    }

    Dialog(
        onDismissRequest = dismiss,
        properties = DialogProperties(
            dismissOnBackPress = canDismiss,
            dismissOnClickOutside = canDismiss,
            usePlatformDefaultWidth = false,
        ),
    ) {
        AlphaBuildWarningCard(
            versionName = versionName,
            remainingSeconds = remainingSeconds,
            onOpenGitHub = { openExternalUri(context, APP_ERRORS_TRACKING_GITHUB) },
            onOpenTelegram = { openExternalUri(context, APP_ERRORS_TRACKING_TELEGRAM) },
            onContinue = dismiss,
        )
    }
}
