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

package com.eltavine.duckdetector.startup.legal

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@Composable
internal fun AgreementSection(
    icon: ImageVector,
    title: String,
    content: String,
    tone: AgreementSectionTone = AgreementSectionTone.Standard,
) {
    val sectionColors = tone.colors()
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = sectionColors.container,
        ),
        shape = RoundedCornerShape(20.dp),
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(sectionColors.iconContainer),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = icon,
                        contentDescription = null,
                        modifier = Modifier.size(22.dp),
                        tint = sectionColors.iconTint,
                    )
                }
                Spacer(modifier = Modifier.width(14.dp))
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = sectionColors.title,
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            AgreementSectionContent(
                content = content,
                tone = tone,
            )
        }
    }
}

@Composable
private fun AgreementSectionContent(
    content: String,
    tone: AgreementSectionTone,
) {
    val lines = remember(content) { content.lines() }
    val firstContentIndex = remember(lines) { lines.indexOfFirst { it.isNotBlank() } }

    Column(
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        lines.forEachIndexed { index, rawLine ->
            val line = rawLine.trim()
            if (line.isEmpty()) {
                Spacer(modifier = Modifier.height(6.dp))
            } else {
                val lineStyle = when {
                    index == firstContentIndex && tone == AgreementSectionTone.Warning ->
                        AgreementLineStyle.Callout

                    NumberedHeadingRegex.matches(line) ->
                        AgreementLineStyle.SectionHeading

                    else -> AgreementLineStyle.Body
                }
                AgreementStyledLine(
                    text = line,
                    lineStyle = lineStyle,
                    tone = tone,
                )
            }
        }
    }
}

@Composable
private fun AgreementStyledLine(
    text: String,
    lineStyle: AgreementLineStyle,
    tone: AgreementSectionTone,
) {
    val bodyColor = when (tone) {
        AgreementSectionTone.Warning -> MaterialTheme.colorScheme.onSurface
        AgreementSectionTone.Notice -> MaterialTheme.colorScheme.onSurfaceVariant
        AgreementSectionTone.Standard -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    val headingColor = when (tone) {
        AgreementSectionTone.Warning -> MaterialTheme.colorScheme.error
        AgreementSectionTone.Notice -> MaterialTheme.colorScheme.primary
        AgreementSectionTone.Standard -> MaterialTheme.colorScheme.onSurface
    }

    val (style, color, fontWeight) = when (lineStyle) {
        AgreementLineStyle.Callout -> Triple(
            MaterialTheme.typography.titleSmall,
            MaterialTheme.colorScheme.error,
            FontWeight.Bold,
        )

        AgreementLineStyle.SectionHeading -> Triple(
            MaterialTheme.typography.titleSmall,
            headingColor,
            FontWeight.Bold,
        )

        AgreementLineStyle.Body -> Triple(
            MaterialTheme.typography.bodyMedium,
            bodyColor,
            FontWeight.Normal,
        )
    }

    Text(
        text = text,
        style = style,
        color = color,
        fontWeight = fontWeight,
        lineHeight = style.lineHeight * 1.28,
    )
}

private val NumberedHeadingRegex = Regex("""^\d+\.\s.*""")

internal enum class AgreementSectionTone {
    Standard,
    Warning,
    Notice,
}

private enum class AgreementLineStyle {
    Callout,
    SectionHeading,
    Body,
}

internal data class AgreementSectionColors(
    val container: Color,
    val iconContainer: Color,
    val iconTint: Color,
    val title: Color,
)

@Composable
internal fun AgreementSectionTone.colors(): AgreementSectionColors {
    return when (this) {
        AgreementSectionTone.Standard -> AgreementSectionColors(
            container = MaterialTheme.colorScheme.surfaceContainerLow,
            iconContainer = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.5f),
            iconTint = MaterialTheme.colorScheme.primary,
            title = MaterialTheme.colorScheme.onSurface,
        )

        AgreementSectionTone.Warning -> AgreementSectionColors(
            container = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.42f),
            iconContainer = MaterialTheme.colorScheme.errorContainer,
            iconTint = MaterialTheme.colorScheme.error,
            title = MaterialTheme.colorScheme.error,
        )

        AgreementSectionTone.Notice -> AgreementSectionColors(
            container = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.28f),
            iconContainer = MaterialTheme.colorScheme.secondaryContainer,
            iconTint = MaterialTheme.colorScheme.primary,
            title = MaterialTheme.colorScheme.onSurface,
        )
    }
}
