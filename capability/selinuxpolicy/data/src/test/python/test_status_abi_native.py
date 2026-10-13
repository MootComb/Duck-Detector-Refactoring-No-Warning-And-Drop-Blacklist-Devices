#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Status ABI request flow and actual JNI payload tests, without an Android kernel."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[6]
NATIVE = ROOT / "capability/selinuxpolicy/data/src/main/cpp"
COMMON = ROOT / "core/native/src/main/cpp"
FIXTURES = ROOT / "capability/selinuxpolicy/data/src/test/resources"
JNI = r"""
#include <string>
#define JNIEXPORT
#define JNICALL
using jstring = const char *;
using jobject = void *;
struct JNIEnv {
    std::string storage;
    jstring NewStringUTF(const char *value) { storage = value; return storage.c_str(); }
};
"""
HARNESS = r"""
#include "selinuxpolicy/selinux_status_abi_probe.h"
#include "common/disposable_child.h"
#include "jni.h"
#include <array>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <span>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
static std::string mode, ending;
static long page;
static int mmap_calls, munmap_calls, close_calls, protect_calls;
static bool baseline_maywrite;
static void *address(int index) { return reinterpret_cast<void *>(0x100000u + index * 0x10000u); }
long test_sysconf(int name) { assert(name == _SC_PAGESIZE); return page; }
int test_open(const char *path, int flags) {
    assert(!strcmp(path, "/sys/fs/selinux/status") && flags == (O_RDONLY | O_CLOEXEC));
    if (mode == "open_failed") { errno = EACCES; return -1; }
    return 42;
}
void *test_mmap(void *hint, size_t size, int prot, int flags, int fd, off_t offset) {
    assert(!hint && fd == 42);
    const int call = ++mmap_calls;
    if (call == 1) {
        assert(size == static_cast<size_t>(page) && prot == PROT_READ && offset == 0);
        if (mode == "baseline_failed") { errno = ENOMEM; return MAP_FAILED; }
        // ACK mmap.c clears VM_MAYWRITE for O_RDONLY + MAP_SHARED before calling the handler.
        baseline_maywrite = flags == MAP_PRIVATE && mode != "stock" && mode != "two_page" &&
            mode != "offset" && mode != "writable";
        return address(call);
    }
    assert(call <= 4);
    if (call == 2) assert(size == static_cast<size_t>(2 * page) && prot == PROT_READ && flags == MAP_SHARED && offset == 0);
    if (call == 3) assert(size == static_cast<size_t>(page) && prot == PROT_READ && flags == MAP_SHARED && offset == page);
    if (call == 4) assert(size == static_cast<size_t>(page) && prot == (PROT_READ | PROT_WRITE) && flags == MAP_PRIVATE && offset == 0);
    const bool grant = mode == "all" || (call == 2 && mode == "two_page") ||
        (call == 3 && mode == "offset") || (call == 4 && mode == "writable");
    if (grant) return address(call);
    errno = call == 4 ? EPERM : EIO;
    return MAP_FAILED;
}
int test_mprotect(void *mapping, size_t size, int prot) {
    assert(mmap_calls == 4 && mapping == address(1) && size == static_cast<size_t>(page) && prot == (PROT_READ | PROT_WRITE));
    ++protect_calls;
    if (baseline_maywrite) return 0;
    errno = EACCES;
    return -1;
}
int test_munmap(void *mapping, size_t size) {
    assert(mapping >= address(1) && mapping <= address(4));
    assert(size == static_cast<size_t>(mapping == address(2) ? 2 * page : page));
    ++munmap_calls;
    return 0;
}
int test_close(int fd) { assert(fd == 42); ++close_calls; return 0; }
#define sysconf test_sysconf
#define open test_open
#define mmap test_mmap
#define mprotect test_mprotect
#define munmap test_munmap
#define close test_close
#include "selinuxpolicy/selinux_status_abi_probe.cpp"
#undef sysconf
#undef open
#undef mmap
#undef mprotect
#undef munmap
#undef close
namespace duckdetector::common::detail {
ChildOutcome run_disposable_child(std::span<unsigned char> report, ChildDeadlines deadlines,
                                 ChildBody body, const void *context) {
    assert(deadlines.run.count() == 1000 && deadlines.reap.count() == 250);
    if (ending == "not_started") return {.end = ChildEnd::kNotStarted, .error = EAGAIN};
    if (ending == "setup_failed") return {.end = ChildEnd::kSetupFailed};
    // Execute the real request body synchronously; inject reports and lifecycle failures only.
    FILE *file = tmpfile();
    assert(file);
    const int status = body(context, fileno(file));
    const long length = lseek(fileno(file), 0, SEEK_CUR);
    assert(length > 0 && static_cast<size_t>(length) <= report.size());
    lseek(fileno(file), 0, SEEK_SET);
    assert(read(fileno(file), report.data(), length) == length);
    fclose(file);
    ChildOutcome result{.end = ChildEnd::kExited, .exit_status = status, .report_length = static_cast<size_t>(length)};
    if (ending != "complete") {
        const size_t report_count = mode == "offset" ? 3 : mode == "writable" ? 4 : mode == "mprotect_only" ? 5 : 2;
        result.report_length = report_count * sizeof(duckdetector::selinux::ChildReport);
        if (ending == "timeout") result.end = ChildEnd::kTimedOut;
        if (ending == "signal") { result.end = ChildEnd::kSignaled; result.signal = SIGSEGV; }
        if (ending == "seccomp") result.end = ChildEnd::kSeccompTrapped;
        if (ending == "unreaped") result.end = ChildEnd::kNotReaped;
        if (ending == "wait_failed") { result.end = ChildEnd::kWaitFailed; result.error = ECHILD; }
        if (ending == "empty") result.report_length = 0;
        if (ending == "truncated") result.report_length = sizeof(duckdetector::selinux::ChildReport) - 1;
    }
    return result;
}
}
extern "C" jstring Java_com_eltavine_duckdetector_capability_selinuxpolicy_data_SelinuxStatusAbiProbe_nativeProbeStatusAbi(JNIEnv *, jobject);
int main(int argc, char **argv) {
    assert(argc == 4);
    mode = argv[1]; ending = argv[2]; page = std::stol(argv[3]);
    JNIEnv env;
    const std::string payload = Java_com_eltavine_duckdetector_capability_selinuxpolicy_data_SelinuxStatusAbiProbe_nativeProbeStatusAbi(&env, nullptr);
    if (mmap_calls == 4) {
        assert(protect_calls == 1 && close_calls == 1);
        assert(munmap_calls == (mode == "all" ? 4 : mode == "two_page" || mode == "offset" || mode == "writable" ? 2 : 1));
    }
    std::cout << payload;
}
"""


class StatusAbiNativeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = os.environ.get("CXX") or shutil.which("clang++") or shutil.which("g++")
        if not compiler:
            raise RuntimeError("Host C++20 compiler required")
        cls.directory = tempfile.TemporaryDirectory(prefix="duck-status-abi-native-")
        cls.addClassCleanup(cls.directory.cleanup)
        path = Path(cls.directory.name)
        (path / "test.cpp").write_text(HARNESS)
        (path / "jni.h").write_text(JNI)
        cls.binary = path / "test"
        subprocess.run([compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(path),
                        "-I", str(NATIVE), "-I", str(COMMON), str(path / "test.cpp"),
                        str(NATIVE / "selinuxpolicy/selinux_status_abi_native_bridge.cpp"),
                        str(COMMON / "common/payload_codec.cpp"), "-o", str(cls.binary)],
                       check=True, timeout=60)

    def payload(self, mode="stock", ending="complete", page=4096):
        return subprocess.run([str(self.binary), mode, ending, str(page)], check=True,
                              capture_output=True, text=True, timeout=10).stdout

    def test_stock_rejects_every_request_on_both_page_sizes(self):
        for page in (4096, 16384):
            with self.subTest(page=page):
                raw = self.payload(page=page)
                self.assertIn("OUTCOME=NO_VIOLATION\n", raw)
                self.assertNotIn("VIOLATED=", raw)
                self.assertEqual(raw.count("was rejected (errno="), 4)
                self.assertIn(f"PAGE_SIZE={page}\n", raw)

    def test_each_missing_check_is_reported_by_its_native_key(self):
        for mode, request in (("two_page", "TWO_PAGE_SHARED"), ("offset", "OFFSET_SHARED"),
                              ("writable", "WRITABLE_PRIVATE"), ("mprotect_only", "MPROTECT_WRITE")):
            for page in (4096, 16384):
                with self.subTest(mode=mode, page=page):
                    raw = self.payload(mode, page=page)
                    self.assertIn("OUTCOME=VIOLATION\n", raw)
                    self.assertIn(f"VIOLATED={request}\n", raw)

    def test_later_child_failure_preserves_already_granted_request(self):
        for mode, request, unreported in (("two_page", "TWO_PAGE_SHARED", 3), ("offset", "OFFSET_SHARED", 2),
                                         ("writable", "WRITABLE_PRIVATE", 1), ("mprotect_only", "MPROTECT_WRITE", 0)):
            for ending in ("timeout", "signal", "seccomp", "unreaped", "wait_failed", "partial_exit"):
                with self.subTest(mode=mode, ending=ending):
                    raw = self.payload(mode, ending)
                    self.assertIn("OUTCOME=VIOLATION\n", raw)
                    self.assertIn(f"VIOLATED={request}\n", raw)
                    self.assertIn("FAILURE_REASON=", raw)
                    self.assertEqual(raw.count("has no reported outcome"), unreported)

    def test_incomplete_negative_report_never_becomes_no_violation(self):
        for ending in ("timeout", "signal", "seccomp", "unreaped", "wait_failed", "partial_exit",
                       "not_started", "setup_failed", "empty", "truncated"):
            with self.subTest(ending=ending):
                raw = self.payload(ending=ending)
                self.assertIn("OUTCOME=INCONCLUSIVE\n", raw)
                self.assertNotIn("VIOLATED=", raw)
                self.assertIn("FAILURE_REASON=", raw)

    def test_open_and_baseline_failures_stay_unavailable(self):
        for mode in ("open_failed", "baseline_failed"):
            with self.subTest(mode=mode):
                raw = self.payload(mode)
                self.assertIn("OUTCOME=UNAVAILABLE\n", raw)
                self.assertNotIn("VIOLATED=", raw)

    def test_invalid_page_size_does_not_attempt_probe(self):
        raw = self.payload(page=-1)
        self.assertIn("ATTEMPTED=0\nOUTCOME=INCONCLUSIVE\n", raw)

    def test_actual_jni_payload_matches_kotlin_round_trip_fixtures(self):
        for mode, ending, fixture in (("all", "complete", "selinux-status-abi-violation.txt"),
                                      ("two_page", "timeout", "selinux-status-abi-partial.txt")):
            with self.subTest(fixture=fixture):
                self.assertEqual((FIXTURES / fixture).read_text(), self.payload(mode, ending))


if __name__ == "__main__":
    unittest.main()
