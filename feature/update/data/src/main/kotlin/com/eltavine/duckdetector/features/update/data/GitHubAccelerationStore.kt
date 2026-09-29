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

package com.eltavine.duckdetector.features.update.data

import android.content.Context
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.preferencesDataStoreFile
import com.eltavine.duckdetector.features.update.domain.GitHubAcceleration
import java.io.IOException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map

class GitHubAccelerationStore private constructor(context: Context) {

    private val dataStore = PreferenceDataStoreFactory.create(
        produceFile = { context.preferencesDataStoreFile("github_acceleration_prefs") },
    )

    val acceleration: Flow<GitHubAcceleration> = dataStore.data
        .catch { throwable ->
            if (throwable is IOException) {
                emit(emptyPreferences())
            } else {
                throw throwable
            }
        }
        .map { prefs ->
            when (prefs[KEY_ENABLED]) {
                null -> GitHubAcceleration.UNDECIDED
                true -> GitHubAcceleration.ENABLED
                false -> GitHubAcceleration.DISABLED
            }
        }

    suspend fun setEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[KEY_ENABLED] = enabled
        }
    }

    companion object {
        @Volatile
        private var instance: GitHubAccelerationStore? = null

        private val KEY_ENABLED = booleanPreferencesKey("enabled")

        fun getInstance(context: Context): GitHubAccelerationStore {
            return instance ?: synchronized(this) {
                instance ?: GitHubAccelerationStore(context.applicationContext).also { created ->
                    instance = created
                }
            }
        }
    }
}
