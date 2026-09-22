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

package com.eltavine.duckdetector.features.nativeroot.data.binder

import android.os.Build
import android.os.IBinder
import org.lsposed.hiddenapibypass.HiddenApiBypass
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Executable

enum class PackageManagerPrivateCallStatus {
    SUCCESS,
    BINDER_UNAVAILABLE,
    HIDDEN_API_UNAVAILABLE,
    METHOD_UNAVAILABLE,
    INVOCATION_FAILED,
}

data class PackageManagerPrivateCallResult<T>(
    val status: PackageManagerPrivateCallStatus,
    val value: T? = null,
    val detail: String = "",
) {
    val isSuccess: Boolean
        get() = status == PackageManagerPrivateCallStatus.SUCCESS
}

/**
 * A private binder adapter for the hidden `android.content.pm.IPackageManager`.
 * 与公开 `PackageManager` 不同，这里不在客户端套一层 ArrayList，也不要求调用方持有
 * `ApplicationPackageManager`；这让后续探针能直接观察服务端的 wire 语义。
 * Unlike the public `PackageManager`, this adapter does not wrap values in a client-side
 * ArrayList and does not require an `ApplicationPackageManager`, so later probes can observe
 * the server-side wire semantics directly.
 */
class PackageManagerPrivateBinderClient internal constructor(
    private val transport: Transport = Transport.Default,
    private val sdkProvider: () -> Int = { Build.VERSION.SDK_INT },
    private val methodGateway: MethodGateway = MethodGateway.HiddenApiBypass,
) {

    fun getMimeGroup(packageName: String, group: String): PackageManagerPrivateCallResult<List<String>?> {
        return execute("getMimeGroup") { service ->
            val value = try {
                methodGateway.invoke(
                    service.javaClass,
                    service,
                    "getMimeGroup",
                    packageName,
                    group,
                )
            } catch (throwable: NoSuchMethodException) {
                return@execute methodUnavailable(
                    operation = "getMimeGroup",
                    service = service,
                    method = "getMimeGroup",
                )
            }
            PackageManagerPrivateCallResult(
                status = PackageManagerPrivateCallStatus.SUCCESS,
                value = value as? List<String>?,
            )
        }
    }

    fun setMimeGroup(
        packageName: String,
        group: String,
        mimeTypes: List<String>?,
    ): PackageManagerPrivateCallResult<Unit> {
        return execute("setMimeGroup") { service ->
            try {
                methodGateway.invoke(
                    service.javaClass,
                    service,
                    "setMimeGroup",
                    packageName,
                    group,
                    mimeTypes,
                )
            } catch (throwable: NoSuchMethodException) {
                return@execute methodUnavailable(
                    operation = "setMimeGroup",
                    service = service,
                    method = "setMimeGroup",
                )
            }
            PackageManagerPrivateCallResult(
                status = PackageManagerPrivateCallStatus.SUCCESS,
                value = Unit,
            )
        }
    }

    private fun <T> methodUnavailable(
        operation: String,
        service: Any,
        method: String,
    ): PackageManagerPrivateCallResult<T> {
        // Hidden API filtering can make a method absent from javaClass.methods while generated
        // Stub$Proxy still carries it. Reporting the service class and same-named declarations
        // distinguishes a vendor signature change from ordinary reflection filtering.
        // Hidden API 过滤会让 javaClass.methods 看不到方法，但生成的 Stub$Proxy 仍携带它。
        // 输出 service 类和同名声明可以区分厂商签名变化与普通反射过滤。
        val candidates = methodGateway.declaredMethods(service.javaClass)
            .filter { it.name == method }
            .joinToString { executable ->
                "${executable.name}(${executable.parameterTypes.joinToString { it.simpleName }})"
            }
        return unavailable(
            PackageManagerPrivateCallStatus.METHOD_UNAVAILABLE,
            "$operation is unavailable on ${service.javaClass.name}; " +
                "same-named methods: ${candidates.ifBlank { "(none)" }}.",
        )
    }

    internal interface MethodGateway {
        fun invoke(
            targetClass: Class<*>,
            target: Any?,
            methodName: String,
            vararg arguments: Any?,
        ): Any?

        fun declaredMethods(targetClass: Class<*>): List<Executable>

        object HiddenApiBypass : MethodGateway {
            override fun invoke(
                targetClass: Class<*>,
                target: Any?,
                methodName: String,
                vararg arguments: Any?,
            ): Any? = org.lsposed.hiddenapibypass.HiddenApiBypass.invoke(
                targetClass,
                target,
                methodName,
                *arguments,
            )

            override fun declaredMethods(targetClass: Class<*>): List<Executable> =
                org.lsposed.hiddenapibypass.HiddenApiBypass.getDeclaredMethods(targetClass)
        }
    }

    private inline fun <T> execute(
        operation: String,
        block: (Any) -> PackageManagerPrivateCallResult<T>,
    ): PackageManagerPrivateCallResult<T> {
        if (sdkProvider() < Build.VERSION_CODES.R) {
            return unavailable(
                PackageManagerPrivateCallStatus.HIDDEN_API_UNAVAILABLE,
                "$operation requires Android 11 or newer.",
            )
        }

        return when (val resolution = transport.resolveService()) {
            is Transport.ServiceResolution.Service -> {
                try {
                    block(resolution.service)
                } catch (throwable: InvocationTargetException) {
                    failed(operation, throwable.cause ?: throwable)
                } catch (throwable: Throwable) {
                    failed(operation, throwable)
                }
            }

            Transport.ServiceResolution.BinderUnavailable -> unavailable(
                PackageManagerPrivateCallStatus.BINDER_UNAVAILABLE,
                "$operation could not resolve the package service binder.",
            )

            Transport.ServiceResolution.HiddenApiUnavailable -> unavailable(
                PackageManagerPrivateCallStatus.HIDDEN_API_UNAVAILABLE,
                "$operation could not load the hidden package manager interface.",
            )

            Transport.ServiceResolution.MethodUnavailable -> unavailable(
                PackageManagerPrivateCallStatus.METHOD_UNAVAILABLE,
                "$operation is missing a hidden package manager method.",
            )
        }
    }

    private fun <T> unavailable(
        status: PackageManagerPrivateCallStatus,
        detail: String,
    ): PackageManagerPrivateCallResult<T> {
        return PackageManagerPrivateCallResult(status = status, detail = detail)
    }

    private fun <T> failed(
        operation: String,
        cause: Throwable,
    ): PackageManagerPrivateCallResult<T> {
        val message = cause.message?.takeIf(String::isNotBlank)
        return unavailable(
            PackageManagerPrivateCallStatus.INVOCATION_FAILED,
            "$operation failed: ${cause::class.java.simpleName}${message?.let { ": $it" }.orEmpty()}",
        )
    }

    internal interface Transport {
        fun resolveService(): ServiceResolution

        sealed interface ServiceResolution {
            data class Service(val service: Any) : ServiceResolution
            object BinderUnavailable : ServiceResolution
            object HiddenApiUnavailable : ServiceResolution
            object MethodUnavailable : ServiceResolution
        }

        object Default : Transport {
            override fun resolveService(): ServiceResolution {
                // The service manager and the generated stub are both hidden API surfaces, so the
                // resolution deliberately records why it failed before any probe interprets it.
                // ServiceManager 和生成的 Stub 都是隐藏 API 面，解析过程必须先记录失败原因，
                // 之后探针才能解释结果。
                val serviceManager = try {
                    HiddenApiBypass.invoke(
                        Class::class.java,
                        null,
                        "forName",
                        "android.os.ServiceManager",
                    ) as Class<*>
                } catch (throwable: Throwable) {
                    return ServiceResolution.HiddenApiUnavailable
                }

                val binder = try {
                    serviceManager.getMethod("getService", String::class.java)
                        .invoke(null, SERVICE_NAME) as? IBinder
                } catch (throwable: Throwable) {
                    return ServiceResolution.HiddenApiUnavailable
                } ?: return ServiceResolution.BinderUnavailable

                val stubClass = try {
                    HiddenApiBypass.invoke(
                        Class::class.java,
                        null,
                        "forName",
                        IPACKAGE_MANAGER_STUB,
                    ) as Class<*>
                } catch (throwable: Throwable) {
                    return ServiceResolution.HiddenApiUnavailable
                }

                val asInterface = try {
                    stubClass.getMethod("asInterface", IBinder::class.java)
                } catch (throwable: Throwable) {
                    return ServiceResolution.MethodUnavailable
                }

                val service = try {
                    asInterface.invoke(null, binder)
                } catch (throwable: Throwable) {
                    return ServiceResolution.HiddenApiUnavailable
                } ?: return ServiceResolution.MethodUnavailable

                return ServiceResolution.Service(service)
            }
        }
    }

    private companion object {
        private const val SERVICE_NAME = "package"
        private const val IPACKAGE_MANAGER = "android.content.pm.IPackageManager"
        private const val IPACKAGE_MANAGER_STUB = "android.content.pm.IPackageManager\$Stub"
    }
}
