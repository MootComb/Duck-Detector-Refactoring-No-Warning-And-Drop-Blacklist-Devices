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

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.OpenInNew
import androidx.compose.material.icons.rounded.Code
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.Gavel
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.Hyphens
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.eltavine.duckdetector.core.designsystem.components.DuckButtonDefaults
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import com.eltavine.duckdetector.core.ui.components.DetectorHairline
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.openExternalUri
import com.eltavine.duckdetector.features.settings.ui.R
import com.mikepenz.aboutlibraries.entity.Library
import com.mikepenz.aboutlibraries.entity.License
import com.mikepenz.aboutlibraries.ui.compose.util.author

private val DialogInset = 20.dp
private val GroupInset = 16.dp

/**
 * The details of one library: who publishes it, where its project lives and the full text of every
 * license it declares. The identity stays pinned above the scrolling license text, so a long
 * license never scrolls the library's name out of view.
 */
@Composable
internal fun LicenseDetailsDialog(
    library: Library,
    onDismiss: () -> Unit,
) {
    val scrollState = rememberScrollState()

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Column(
            modifier = Modifier
                .padding(horizontal = DialogInset, vertical = 32.dp)
                .widthIn(max = 560.dp)
                .fillMaxWidth()
                .background(
                    color = DuckTheme.palette.groupedSurface,
                    shape = ShapeTokens.CornerExtraLargeIncreased,
                )
                .padding(top = 24.dp, bottom = DialogInset),
        ) {
            LicenseDialogHeader(
                library = library,
                modifier = Modifier.padding(horizontal = DialogInset),
            )
            DetectorHairline(
                modifier = Modifier
                    .padding(top = 18.dp)
                    .alpha(if (scrollState.canScrollBackward) 1f else 0f),
            )
            Column(
                modifier = Modifier
                    .weight(1f, fill = false)
                    .verticalScroll(scrollState)
                    .padding(horizontal = GroupInset, vertical = 16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                library.description?.takeIf { it.isNotBlank() }?.let { description ->
                    WrapSafeText(
                        text = description,
                        modifier = Modifier.padding(horizontal = 4.dp),
                        style = DuckTypography.Callout,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                LibraryProjectLink(library = library)
                library.licenses.forEach { license ->
                    LicenseTextGroup(license = license)
                }
            }
            DetectorHairline(
                modifier = Modifier.alpha(if (scrollState.canScrollForward) 1f else 0f),
            )
            Button(
                onClick = onDismiss,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = DialogInset, end = DialogInset, top = 16.dp),
                colors = DuckButtonDefaults.filledColors(),
                contentPadding = DuckButtonDefaults.LargeContentPadding,
            ) {
                WrapSafeText(
                    text = stringResource(R.string.licenses_dialog_close),
                    style = DuckTypography.Headline,
                )
            }
        }
    }
}

@Composable
private fun LicenseDialogHeader(
    library: Library,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Box(
            modifier = Modifier
                .padding(bottom = 6.dp)
                .size(56.dp)
                .background(color = DuckTheme.palette.groupedInset, shape = ShapeTokens.CornerLarge),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = Icons.Rounded.Description,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.size(28.dp),
            )
        }
        // A library's name is a proper name: it may wrap between words but is never hyphenated.
        Text(
            text = library.name,
            style = DuckTypography.Title3.copy(hyphens = Hyphens.None),
            color = MaterialTheme.colorScheme.onSurface,
            textAlign = TextAlign.Center,
        )
        library.author.takeIf { it.isNotBlank() }?.let { author ->
            WrapSafeText(
                text = author,
                style = DuckTypography.Callout,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
        if (library.uniqueId.isNotBlank()) {
            WrapSafeText(
                text = library.uniqueId,
                style = DuckTypography.Footnote.copy(fontFamily = FontFamily.Monospace),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
        library.artifactVersion?.takeIf { it.isNotBlank() }?.let { version ->
            LicensePill(
                text = stringResource(R.string.licenses_dialog_version, version),
                modifier = Modifier.padding(top = 4.dp),
            )
        }
    }
}

@Composable
private fun LibraryProjectLink(library: Library) {
    val context = LocalContext.current
    val website = library.website?.takeIf { it.isNotBlank() }
    val url = website ?: library.scm?.url?.takeIf { it.isNotBlank() } ?: return
    LinkRow(
        icon = if (website != null) Icons.Rounded.Language else Icons.Rounded.Code,
        label = stringResource(
            if (website != null) R.string.licenses_dialog_home_page else R.string.licenses_dialog_source_repo,
        ),
        url = url,
        onClick = { openExternalUri(context, url) },
        modifier = Modifier
            .clip(ShapeTokens.CornerLarge)
            .background(color = DuckTheme.palette.groupedInset),
    )
}

@Composable
private fun LicenseTextGroup(license: License) {
    val context = LocalContext.current
    val url = license.url?.takeIf { it.isNotBlank() }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(ShapeTokens.CornerLarge)
            .background(color = DuckTheme.palette.groupedInset),
    ) {
        if (url != null) {
            LinkRow(
                icon = Icons.Rounded.Gavel,
                label = license.name,
                url = url,
                onClick = { openExternalUri(context, url) },
            )
        } else {
            LicenseNameRow(name = license.name)
        }
        DetectorHairline(startInset = GroupInset)
        SelectionContainer {
            WrapSafeText(
                text = license.licenseContent?.trim()?.takeIf { it.isNotEmpty() }
                    ?: stringResource(R.string.licenses_dialog_no_license_text),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = GroupInset, vertical = 14.dp),
                style = DuckTypography.Footnote,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun LinkRow(
    icon: ImageVector,
    label: String,
    url: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = GroupInset, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(20.dp),
        )
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            WrapSafeText(
                text = label,
                style = DuckTypography.CalloutEmphasized,
                color = MaterialTheme.colorScheme.onSurface,
            )
            WrapSafeText(
                text = url,
                style = DuckTypography.Footnote,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Icon(
            imageVector = Icons.AutoMirrored.Rounded.OpenInNew,
            contentDescription = stringResource(R.string.licenses_dialog_open),
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(18.dp),
        )
    }
}

@Composable
private fun LicenseNameRow(name: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = GroupInset, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(
            imageVector = Icons.Rounded.Gavel,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(20.dp),
        )
        WrapSafeText(
            text = name,
            style = DuckTypography.CalloutEmphasized,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}
