<p align="center">
  <a href="CONTRIBUTING.md">English</a> &nbsp; <a href="CONTRIBUTING_ZH.md">简体中文</a>
</p>

# Contribution Provenance and Attribution

This document covers the provenance and attribution of contributions to this repository, including code, documentation, UI copy, assets, and research material. It works alongside [`CODING_STANDARDS.md`](./CODING_STANDARDS.md), which governs implementation, testing, and commits. The [module architecture](./docs/architecture/README.md) and [detector guide](./docs/guides/adding-a-detector.md) remain authoritative for engineering requirements.

## 1. Principles

- **Traceable:** contributors should be able to explain the sources of their research and any material incorporated into their changes.
- **Proportionate:** enforce licensing and confidentiality requirements, while treating the origins of an idea as descriptive information rather than an automatic barrier to contribution.
- **Legally precise:** distinguish copyright-protected expression from independently observed facts and general methods. Patent, trade-secret, contractual, and jurisdiction-specific obligations may still apply.

## 2. Sources and attribution

### 2.1 Ideas, methods, and independent research

Copyright generally protects original expression, not ideas, methods, algorithms as such, or independently observed functional behaviour. Independently implementing a comparable detection technique does not, by itself, establish copying or ownership of another person's source code. Being the first to suggest an idea does not justify blocking or disparaging an independent implementation. Separate rights, including patents and trade secrets, may still matter.

### 2.2 Protected expression and licensing

If a contribution quotes, adapts, or incorporates third-party code, documentation, tests, images, or other protected expression, the contributor must identify the material and comply with its licence or permission, including required copyright notices, attribution, and modification notices. Preserve these notices in the appropriate files and repository documentation. Attribution alone does **not** make an otherwise prohibited redistribution lawful.

### 2.3 Credit for prior ideas and discoveries

Acknowledging useful ideas, prior research, and discoveries is **expected, not mandatory**. This may appear in a PR, a README, or a suitable research reference. Such acknowledgement is distinct from legally required notices and does not imply code co-authorship.

Missing voluntary credit alone must not be used to allege plagiarism or demand that a contribution be withdrawn. Specific concerns about copied expression, authorship, or licence compliance may still be raised with evidence and reviewed on their merits.

## 3. Sources that must not be introduced

Do not incorporate:

- third-party code or protected material without permission to distribute it under the project's applicable licensing and distribution arrangements. In particular, do not copy GPL-family source into this Apache-2.0 repository and redistribute it as Apache-2.0 merely by adding credit or rewriting identifiers. Apache-2.0-to-GPLv3 compatibility does not work in reverse. External dependencies, linking, and separately licensed submodules require review of their actual licence terms and distribution model rather than a blanket assumption;
- leaked source code, confidential or NDA-restricted material, or material obtained in violation of applicable legal or contractual restrictions.

It is legitimate to study publicly available implementations and observable behaviour, including closed-source software, and independently implement factual mechanisms. The restriction concerns copying protected material, not merely having read or analysed another program. Describe the observed behaviour and write an independent implementation instead of translating or lightly rewriting restricted code.

## 4. Provenance disclosure in pull requests

State the **category of knowledge sources** used, as applicable:

- independent or original research;
- public documentation and authoritative source material (AOSP, ACK, platform specifications, etc.);
- black-box observation of publicly available software or devices;
- reverse engineering (decompilation, disassembly, or dynamic analysis);
- third-party research or upstream projects.

These categories may be combined. The disclosure is **descriptive, not a standalone merge gate**. Separately identify any third-party code, text, or assets actually copied or adapted, together with the applicable licence or permission; write “none” where appropriate. Also disclose AI or code-generation assistance.

For detector changes, the owning `feature/<name>/EVIDENCE.md` or `capability/<name>/EVIDENCE.md` must document the observable signal, producing subsystem, mechanism, primary references, applicability, visibility limits, result states, and interpretation. Cite release-matched AOSP/kernel paths or reproducible observations where they support the claim; mark exploratory evidence accordingly. The capability collects shared evidence; the feature domain interprets it; presentation and UI display the typed result. Source provenance does not replace mechanism validation, platform compatibility testing, or the checks required by `CODING_STANDARDS.md`.

## 5. AI and tooling attribution

- AI and code-generation tools **must not** appear in `Signed-off-by`, which represents a person's attestation.
- When AI or code-generation tools materially contribute, disclose the tool and its role in the PR and acknowledge the contribution with a `Co-authored-by:` or `Assisted-by:` trailer. The human contributor remains responsible for reviewing the change, its licensing, and its validation.
- `Co-authored-by: Name <email>` requires an accurate identity and email. Do not fabricate a person's identity or address for a tool. `Assisted-by: Tool or model` is the appropriate alternative where no valid co-author identity exists; it is a project convention, not a GitHub-recognized co-author trailer.
- Maintain and formalize existing conventions, such as `Meow` and `This PR is made by …`, without treating them as substitutes for required attribution. Commit titles and bodies must still follow `CODING_STANDARDS.md`.

## 6. Scope

This document concerns provenance, licensing, and attribution. It does not introduce a Contributor License Agreement (CLA), a Developer Certificate of Origin (DCO) sign-off requirement, or a separate code-of-conduct enforcement process. Concrete licensing, authorship, or confidentiality disputes should be evaluated based on their facts rather than presumed from a contributor's choice of research tools or sources.
