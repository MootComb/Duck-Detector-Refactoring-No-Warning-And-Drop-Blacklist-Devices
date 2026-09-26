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

package com.eltavine.duckdetector.capability.helperprocess.data

import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Build
import android.os.IBinder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asExecutor
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume

public open class HelperProbeManager(
    private val context: Context? = null,
    private val serviceClass: Class<out Service> = HelperProbeService::class.java,
    private val expectedProfile: HelperProcessProfile = HelperProcessProfile.REGULAR,
    private val nativeBridge: VirtualizationNativeBridge = VirtualizationNativeBridge(),
) {

    public open suspend fun collect(): HelperProcessSnapshot = collectRemote(
        timeoutMs = DETECTION_TIMEOUT_MS,
        payloadCollector = HelperProbeProxy::collectSnapshot,
    )

    public open suspend fun collectProcMountView(): HelperProcessSnapshot = collectRemote(
        timeoutMs = PROC_MOUNT_VIEW_TIMEOUT_MS,
        payloadCollector = HelperProbeProxy::collectProcMountView,
    )

    private suspend fun collectRemote(
        timeoutMs: Long,
        payloadCollector: (HelperProbeProxy) -> String,
    ): HelperProcessSnapshot {
        val appContext = context?.applicationContext ?: return HelperProcessSnapshot()
        // Match PrivIsolated's named isolated instance. The manifest flag supplies the isolated
        // UID, while bindIsolatedService gives ActivityManager a stable instance identity and
        // mirrors the reference app's lifecycle.
        // 对齐 PrivIsolated 的 named isolated instance：manifest flag 提供 isolated UID，
        // bindIsolatedService 提供稳定 instance identity，并复用原版 lifecycle。
        // https://developer.android.com/reference/android/content/Context#bindIsolatedService(android.content.Intent,%20int,%20java.lang.String,java.util.concurrent.Executor,android.content.ServiceConnection)
        return withTimeoutOrNull(timeoutMs) {
            performRemoteCollection(appContext, payloadCollector)
        } ?: HelperProcessSnapshot(
            available = false,
            errorDetail = "Virtualization helper process timed out.",
        )
    }

    public open suspend fun runSacrificialSyscallPack(): SacrificialSyscallPackResult {
        val appContext = context?.applicationContext ?: return SacrificialSyscallPackResult()
        return withTimeoutOrNull(DETECTION_TIMEOUT_MS) {
            performRemoteCall(
                context = appContext,
                onConnected = { proxy ->
                    nativeBridge.parseSacrificialSyscallPack(proxy.runSacrificialSyscallPack())
                },
                onNullBinder = {
                    SacrificialSyscallPackResult(
                        available = true,
                        supported = false,
                        detail = "Detector service returned a null binder.",
                    )
                },
                onError = { error ->
                    SacrificialSyscallPackResult(
                        available = true,
                        supported = false,
                        detail = error,
                    )
                },
            )
        } ?: SacrificialSyscallPackResult(
            available = true,
            supported = false,
            detail = "Sacrificial syscall pack timed out.",
        )
    }

    private suspend fun performRemoteCollection(
        context: Context,
        payloadCollector: (HelperProbeProxy) -> String,
    ): HelperProcessSnapshot {
        val snapshot = performRemoteCall(
            context = context,
            onConnected = { proxy ->
                HelperProcessSnapshot.parse(payloadCollector(proxy))
            },
            onNullBinder = {
                HelperProcessSnapshot(
                    available = false,
                    profile = expectedProfile,
                    errorDetail = "Detector service returned a null binder.",
                )
            },
            onError = { error ->
                HelperProcessSnapshot(
                    available = false,
                    profile = expectedProfile,
                    errorDetail = error,
                )
            },
        )
        return if (snapshot.available && snapshot.profile != expectedProfile) {
            snapshot.copy(
                available = false,
                errorDetail = "Helper profile mismatch. expected=$expectedProfile actual=${snapshot.profile}",
            )
        } else {
            snapshot
        }
    }

    private suspend fun <T> performRemoteCall(
        context: Context,
        onConnected: (HelperProbeProxy) -> T,
        onNullBinder: () -> T,
        onError: (String) -> T,
    ): T = suspendCancellableCoroutine { continuation ->
        val bindAttemptFinished = AtomicBoolean(false)
        val cleanupRequested = AtomicBoolean(false)
        val unbindAttempted = AtomicBoolean(false)
        val completionAttempted = AtomicBoolean(false)
        lateinit var connection: ServiceConnection

        fun requestCleanup() {
            cleanupRequested.set(true)
            if (bindAttemptFinished.get() && unbindAttempted.compareAndSet(false, true)) {
                runCatching { context.unbindService(connection) }
            }
        }

        fun finish(result: T) {
            requestCleanup()
            if (completionAttempted.compareAndSet(false, true)) {
                continuation.resume(result)
            }
        }

        connection = object : ServiceConnection {
            override fun onServiceConnected(
                name: ComponentName?,
                service: IBinder?,
            ) {
                if (service == null) {
                    finish(onNullBinder())
                    return
                }
                try {
                    val proxy = HelperProbeProxy(service)
                    finish(onConnected(proxy))
                } catch (throwable: Throwable) {
                    finish(onError(throwable.message ?: "Binder call failed."))
                }
            }

            override fun onNullBinding(name: ComponentName?) {
                finish(onNullBinder())
            }

            override fun onServiceDisconnected(name: ComponentName?) = Unit
        }

        continuation.invokeOnCancellation {
            requestCleanup()
        }
        if (!continuation.isActive) {
            return@suspendCancellableCoroutine
        }

        val intent = Intent(context, serviceClass)
        // AUTO_CREATE keeps the helper alive for this snapshot; finish/cancellation unbind it so
        // a failed Binder call cannot leave an isolated process retained.
        // onServiceConnected below makes a blocking Binder call, so it must not run on the
        // main thread's executor - that previously froze the UI (and could trigger an ANR)
        // for as long as the remote process took to answer.
        val bound = runCatching {
            if (expectedProfile == HelperProcessProfile.ISOLATED &&
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
            ) {
                context.bindIsolatedService(
                    intent,
                    Context.BIND_AUTO_CREATE,
                    ISOLATED_INSTANCE_NAME,
                    REMOTE_CALLBACK_EXECUTOR,
                    connection,
                )
            } else {
                context.bindService(intent, Context.BIND_AUTO_CREATE, REMOTE_CALLBACK_EXECUTOR, connection)
            }
        }.getOrDefault(false)

        // ActivityManager may publish an already-running service before bindService() returns.
        // The executor callback can therefore request cleanup before the bind attempt finishes.
        bindAttemptFinished.set(true)
        if (cleanupRequested.get()) {
            requestCleanup()
        }

        if (!bound) {
            finish(onError("The dedicated virtualization probe process could not be bound."))
            return@suspendCancellableCoroutine
        }
    }

    public companion object {
        private const val ISOLATED_INSTANCE_NAME = "duck_mount_view"
        private const val DETECTION_TIMEOUT_MS = 6_000L
        private const val PROC_MOUNT_VIEW_TIMEOUT_MS = 15_000L
        private val REMOTE_CALLBACK_EXECUTOR = Dispatchers.IO.asExecutor()
    }
}
