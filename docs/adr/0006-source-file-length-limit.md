# ADR 0006: Fail CI when a source file reaches 600 lines

- Status: Accepted
- Date: 2026-09-25

## Context

Several files had grown to own many independent reasons to change. The TEE report reducer had 3,251 lines and its test 2,631. The KeyMint probe, the Keystore2 binder clients and several native probes and honeypot traps each mixed unrelated checks. Files of this size hide coupling that module boundaries cannot see, because everything inside one file can reach everything else. Issue #142 asks CI to fail on any source file of 600 lines or more.

## Decision

1. `check-source-file-length.py` fails when any source file reaches 600 lines. The check covers C, C++ and assembly; Java and Kotlin; Gradle scripts; and Python and shell. It skips build outputs and tool directories, and ignores Markdown, XML and other resources. It runs in the CI `contracts` job with a fixture-based self-test.
2. There is no baseline. During the migration a shrink-only baseline let oversized files land incrementally: a baselined file could not grow, and it had to leave the baseline as soon as it complied. The baseline was deleted when the last file complied. The self-test proves that a leftover baseline file grants no exemption.
3. Files are split along semantic ownership, not at arbitrary line counts. Kotlin files split by role; the TEE reducer, for example, became indicator, section, summary and value files, and its tests became one class per concern with shared fixtures. Helpers shared by the resulting files were widened from `private` to `internal` only.
4. C++ files split without changing linkage semantics. The anonymous namespace becomes `<namespace>::detail`, declared in an internal header. Namespace-scope mutable state becomes C++17 `inline` variables so every translation unit shares one instance. Conditional `#if` regions move whole, with their functions made `inline`. Code whose timing is measured stays in one translation unit.

## Consequences

- No file in the repository reaches 600 lines, and the check has no exemptions.
- Each split was a verbatim move verified by the full unit test suite, the export golden test, the lint issue set, the JNI bindings and a native build for all four ABIs.
- The limit is a review trigger for splitting by ownership. Compressing code or padding it to sit just under the limit defeats its purpose.
- A split can widen visibility from `private` to `internal` within one module. Reviewers should confirm that nothing outside the owning concern starts using the widened helper.
