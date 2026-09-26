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

package com.eltavine.duckdetector.features.settings.ui.licenses

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.openExternalUri
import com.eltavine.duckdetector.core.ui.theme.ShapeTokens
import com.eltavine.duckdetector.features.settings.ui.R
import com.mikepenz.aboutlibraries.entity.Library

/** The details of one library: its project link, its version and every license it declares. */
@Composable
internal fun LicenseDetailsDialog(
    library: Library,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val projectUrl = library.website?.takeIf { it.isNotBlank() } ?: library.scm?.url?.takeIf { it.isNotBlank() }
    val projectLabel = if (!library.website.isNullOrBlank()) {
        stringResource(R.string.licenses_dialog_home_page)
    } else {
        stringResource(R.string.licenses_dialog_source_repo)
    }
    AlertDialog(
        onDismissRequest = { onDismiss() },
        confirmButton = {
            Button(onClick = { onDismiss() }) {
                WrapSafeText(text = stringResource(R.string.licenses_dialog_close))
            }
        },
        dismissButton = {
            if (!projectUrl.isNullOrBlank()) {
                OutlinedButton(
                    onClick = { openExternalUri(context, projectUrl) },
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Language,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    WrapSafeText(
                        text = projectLabel,
                        modifier = Modifier.padding(start = 8.dp),
                    )
                }
            }
        },
        title = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                WrapSafeText(
                    text = library.name,
                    style = MaterialTheme.typography.headlineSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                if (!library.artifactVersion.isNullOrBlank()) {
                    WrapSafeText(
                        text = stringResource(
                            R.string.licenses_dialog_version,
                            library.artifactVersion!!,
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            }
        },
        text = {
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 520.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                item {
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = ShapeTokens.CornerLarge,
                        color = MaterialTheme.colorScheme.tertiaryContainer,
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 14.dp, vertical = 14.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            WrapSafeText(
                                text = stringResource(
                                    R.string.licenses_dialog_licenses,
                                    library.licenses.joinToString(separator = ", ") { it.name },
                                ),
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.onTertiaryContainer,
                            )

                            if (!library.description.isNullOrBlank()) {
                                WrapSafeText(
                                    text = library.description!!,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onTertiaryContainer,
                                )
                            }

                            val coordinates = buildList<String> {
                                if (library.uniqueId.isNotBlank()) {
                                    add(library.uniqueId)
                                }
                                projectUrl?.takeIf { it.isNotBlank() }?.let(::add)
                            }

                            if (coordinates.isNotEmpty()) {
                                FlowRow(
                                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                                    verticalArrangement = Arrangement.spacedBy(8.dp),
                                ) {
                                    coordinates.forEach { item ->
                                        Surface(
                                            shape = ShapeTokens.CornerLarge,
                                            color = MaterialTheme.colorScheme.tertiary.copy(alpha = 0.12f),
                                        ) {
                                            WrapSafeText(
                                                text = item,
                                                modifier = Modifier.padding(
                                                    horizontal = 10.dp,
                                                    vertical = 8.dp,
                                                ),
                                                style = MaterialTheme.typography.labelMedium,
                                                color = MaterialTheme.colorScheme.onTertiaryContainer,
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                items(library.licenses.toList()) { license ->
                    OutlinedCard(
                        modifier = Modifier.fillMaxWidth(),
                        shape = ShapeTokens.CornerExtraLarge,
                        colors = CardDefaults.outlinedCardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                        ),
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 16.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            WrapSafeText(
                                text = license.name,
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.primary,
                            )

                            license.url?.let { url ->
                                Surface(
                                    shape = ShapeTokens.CornerLarge,
                                    color = MaterialTheme.colorScheme.surfaceContainerHighest,
                                ) {
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(horizontal = 12.dp, vertical = 10.dp),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                    ) {
                                        Icon(
                                            imageVector = Icons.Rounded.Language,
                                            contentDescription = null,
                                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                            modifier = Modifier.size(16.dp),
                                        )
                                        WrapSafeText(
                                            text = url,
                                            modifier = Modifier.weight(1f),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                        OutlinedButton(onClick = { openExternalUri(context, url) }) {
                                            WrapSafeText(text = stringResource(R.string.licenses_dialog_open))
                                        }
                                    }
                                }
                            }

                            SelectionContainer {
                                WrapSafeText(
                                    text = license.licenseContent
                                        ?: stringResource(R.string.licenses_dialog_no_license_text),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
            }
        },
        properties = DialogProperties(usePlatformDefaultWidth = false),
        modifier = Modifier.padding(horizontal = 24.dp, vertical = 32.dp),
    )
}
