# ADR 0014: No layer or unit branches on another's text

- Status: Accepted
- Date: 2026-09-26
- Amends: [ADR 0002](./0002-typed-detector-and-report-contracts.md), [ADR 0005](./0005-native-unit-boundaries.md)

## Context

Typed report contracts ([ADR 0002](./0002-typed-detector-and-report-contracts.md)) did not stop layers from reading meaning back out of each other's words. The TEE card chose the dashboard's top finding by searching the TEE summary for "key visibility". The SELinux card graded policy notes by the words in them. Fourteen ui modules found their overview facts by display labels such as "State". The early virtualization preload matched another native unit's finding labels. Rewording any of these strings silently changed what the app showed or detected, and no test or guard noticed.

## Decision

1. Presentation, ui, core, SDK and app code, and native units, decide from typed values: enums, typed ids, flags and typed lists, set where the evidence is produced. They do not compare, search or strip text another layer or unit wrote, and they do not look text up in literal sets.
2. Display text stays beside its type. Enums own their labels, such as header facts and methods. Notes and findings carry a kind next to their sentence. Codecs decode wire values into types at the boundary.
3. Changing text is allowed to change only text. Where the old text match produced an accidental result, the typed version keeps it and records a follow-up; icons that depended on words in labels were made consistent per type, and each such commit lists the rows that changed.
4. `check-text-protocols.py` enforces the rule for Kotlin in the presentation, ui, core, SDK and app roots and for native units, with a self-test. `text-protocols.json` lists the few files that read text by nature, each with a reason: a wire codec, platform values, user input, bundled asset keys, and the export renderer's layout choices. An entry a file no longer needs is rejected.
5. Data layers may still interpret text they receive from the platform, such as keystore2's error messages. They turn it into types there, as the TEE grant evidence does.

## Consequences

- Rewording a label, summary or note changes only what is shown and exported.
- A new detector, including one made by `scripts/new_detector.py`, passes the checker; the scaffold test runs it on generated code.
- Adding a decision that needs a new distinction means adding a type where the evidence is produced, not a string to match.
- Data layers are not scanned; the follow-ups list the text they still read.
