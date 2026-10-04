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

package com.eltavine.duckdetector.features.update.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import com.eltavine.duckdetector.core.ui.components.WrapSafeText

/** [onDecline] is the user's answer; [onDismiss] only closes the dialog and leaves the choice open. */
@Composable
fun GitHubAccelerationDialog(
    onEnable: () -> Unit,
    onDecline: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        shape = ShapeTokens.CornerExtraLarge,
        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
        icon = {
            Icon(imageVector = Icons.Rounded.Speed, contentDescription = null)
        },
        title = {
            WrapSafeText(text = stringResource(R.string.github_acceleration_dialog_title))
        },
        text = {
            WrapSafeText(text = stringResource(R.string.github_acceleration_dialog_message))
        },
        confirmButton = {
            Button(onClick = onEnable) {
                WrapSafeText(text = stringResource(R.string.github_acceleration_dialog_enable))
            }
        },
        dismissButton = {
            TextButton(onClick = onDecline) {
                WrapSafeText(text = stringResource(R.string.github_acceleration_dialog_decline))
            }
        },
    )
}
