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

#include "virtualization/egl_probe.h"

#include <EGL/egl.h>
#include <GLES2/gl2.h>

namespace duckdetector::virtualization {

    RendererSnapshot collect_renderer_snapshot() {
        RendererSnapshot snapshot;

        // EGL_DEFAULT_DISPLAY is a single, process-wide connection that hwui's RenderThread also
        // uses (frameworks/base libs/hwui renderthread/EglManager.cpp calls the same
        // eglGetDisplay(EGL_DEFAULT_DISPLAY)). This probe runs in the main app process from the
        // startup NativeActivity, so it must treat that display as borrowed: never eglTerminate it.
        // Terminating the shared display destroys hwui's EGLDisplay-scoped resources, and the next
        // frame then renders against a null SkSurface and crashes RenderThread inside
        // SkiaPipeline::renderFrame. eglInitialize is reference counted, so initializing here is
        // safe; we only release the surface and context this probe itself created.
        EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
        if (display == EGL_NO_DISPLAY) {
            return snapshot;
        }
        if (eglInitialize(display, nullptr, nullptr) != EGL_TRUE) {
            return snapshot;
        }

        constexpr EGLint configAttributes[] = {
                EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
                EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
                EGL_RED_SIZE, 8,
                EGL_GREEN_SIZE, 8,
                EGL_BLUE_SIZE, 8,
                EGL_NONE,
        };
        EGLConfig config = nullptr;
        EGLint numConfigs = 0;
        if (eglChooseConfig(display, configAttributes, &config, 1, &numConfigs) != EGL_TRUE ||
            numConfigs <= 0 || config == nullptr) {
            return snapshot;
        }

        constexpr EGLint pbufferAttributes[] = {
                EGL_WIDTH, 1,
                EGL_HEIGHT, 1,
                EGL_NONE,
        };
        EGLSurface surface = eglCreatePbufferSurface(display, config, pbufferAttributes);
        if (surface == EGL_NO_SURFACE) {
            return snapshot;
        }

        constexpr EGLint contextAttributes[] = {
                EGL_CONTEXT_CLIENT_VERSION, 2,
                EGL_NONE,
        };
        EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, contextAttributes);
        if (context == EGL_NO_CONTEXT) {
            eglDestroySurface(display, surface);
            return snapshot;
        }

        if (eglMakeCurrent(display, surface, surface, context) != EGL_TRUE) {
            eglDestroyContext(display, context);
            eglDestroySurface(display, surface);
            return snapshot;
        }

        snapshot.available = true;
        const auto *vendor = reinterpret_cast<const char *>(glGetString(GL_VENDOR));
        const auto *renderer = reinterpret_cast<const char *>(glGetString(GL_RENDERER));
        const auto *version = reinterpret_cast<const char *>(glGetString(GL_VERSION));
        if (vendor != nullptr) snapshot.vendor = vendor;
        if (renderer != nullptr) snapshot.renderer = renderer;
        if (version != nullptr) snapshot.version = version;

        // Release only what this probe created. The current binding is per-thread, so unbinding
        // here affects only the startup thread, not hwui's RenderThread. The shared display is
        // deliberately left initialized (no eglTerminate).
        eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
        eglDestroyContext(display, context);
        eglDestroySurface(display, surface);
        return snapshot;
    }

}  // namespace duckdetector::virtualization
