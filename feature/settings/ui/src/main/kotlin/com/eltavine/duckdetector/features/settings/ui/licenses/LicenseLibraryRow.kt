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

package com.eltavine.duckdetector.features.settings.ui.licenses

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyItemScope
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.style.Hyphens
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.mikepenz.aboutlibraries.entity.Library
import com.mikepenz.aboutlibraries.ui.compose.util.author

private const val DESCRIPTION_MAX_LINES = 2

@Composable
internal fun LazyItemScope.LicenseLibraryRow(
    library: Library,
    onClick: () -> Unit,
) {
    Column(
        modifier = Modifier
            .animateItem()
            .padding(vertical = 4.dp)
            .fillMaxWidth()
            .clip(ShapeTokens.CornerLargeIncreased)
            .background(color = DuckTheme.palette.groupedSurface)
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.Top,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                // A library's name is a proper name: it may wrap between words but is never hyphenated.
                Text(
                    text = library.name,
                    style = DuckTypography.Headline.copy(hyphens = Hyphens.None),
                    color = MaterialTheme.colorScheme.onSurface,
                )
                library.author
                    .takeIf { it.isNotBlank() }
                    ?.let { author ->
                        WrapSafeText(
                            text = author,
                            style = DuckTypography.Footnote,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
            }

            library.artifactVersion
                ?.takeIf { it.isNotBlank() }
                ?.let { version -> LicensePill(text = version) }
        }

        library.description
            ?.takeIf { it.isNotBlank() }
            ?.let { description ->
                WrapSafeText(
                    text = description,
                    style = DuckTypography.Footnote,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = DESCRIPTION_MAX_LINES,
                    overflow = TextOverflow.Ellipsis,
                )
            }

        if (library.licenses.isNotEmpty()) {
            FlowRow(
                modifier = Modifier.padding(top = 2.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                library.licenses.forEach { license ->
                    LicensePill(text = license.name)
                }
            }
        }
    }
}

/** A short label, such as a version or a license name, in a capsule on the inset fill. */
@Composable
internal fun LicensePill(
    text: String,
    modifier: Modifier = Modifier,
) {
    WrapSafeText(
        text = text,
        modifier = modifier
            .background(color = DuckTheme.palette.groupedInset, shape = ShapeTokens.CornerFull)
            .padding(horizontal = 10.dp, vertical = 3.dp),
        style = DuckTypography.Caption,
        color = MaterialTheme.colorScheme.onSurface,
    )
}
