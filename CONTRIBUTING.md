<p align="center">
  <a href="CONTRIBUTING.md">English</a> &nbsp; <a href="CONTRIBUTING_ZH.md">简体中文</a>
</p>

# Contribution Provenance and Attribution

This document applies to every contribution to this repository: code, documentation, copy, assets, and research material.

It works alongside [`CODING_STANDARDS.md`](./CODING_STANDARDS.md): that document covers how a change is written, tested, and submitted; this one covers how its sources are declared, how attribution is given, and which sources must not be introduced.

## 1. Principles

- **Traceable**: a contribution should be able to state the category of its sources and material.
- **Proportionate**: hard constraints apply only to sources that carry real risk; everything else is handled by disclosure and credit.
- **Jurisdiction-neutral**: no contributor's jurisdiction is assumed. Statements below about legal rights are framed in terms of "protected expression".

## 2. Sources and attribution

### 2.1 Ideas and methods are not protected

Ideas, methods, algorithms, and discoveries are not protected by copyright and create no ownership: anyone may independently implement the same approach. Being first to think of something does not justify blocking or disparaging another contributor's independent implementation of a comparable detector.

### 2.2 Protected expression must be attributed

When you quote, adapt, or port another party's copyright-protected **code, text, or assets**, you must:

- attribute it at the source (in a Chinese-language context, the right of authorship under Article 10 of the Copyright Law of the People's Republic of China);
- comply with its licence. Material whose licence is incompatible with this repository (Apache-2.0) must not be introduced (see §3).

### 2.3 Credit

Crediting an idea, a discovery, or prior work is **expected, not required**. Noting it in the README, a source comment, or a `Co-authored-by` trailer is welcome; but missing credit must not be used to allege plagiarism or to demand that a contribution be withdrawn.

## 3. Banned sources (hard rule)

Do not introduce:

- code under a licence incompatible with this repository's Apache-2.0, in particular **GPL-family** code (KernelSU, Magisk, and LSPosed are all GPL-3.0);
- leaked source code, material under NDA, or material obtained in violation of an applicable licence or contract.

For the same functionality, **describe the behaviour and reimplement independently** rather than copying code.

> The subjects this repository inspects (including closed-source hiding modules) expose **functional facts** (timing signatures, property names, and so on), which are not protected by copyright. The constraint in this section targets the **porting of code and protected text**, not whether someone has read or observed a given program.

## 4. Provenance disclosure in pull requests

In a PR, state the **category** of the change's knowledge source (**descriptive, not a gate**):

- original;
- public authoritative documentation (AOSP, ACK, official Android docs, and so on);
- black-box observation of a publicly available product;
- reverse engineering of a program (decompilation / disassembly / dynamic analysis);
- third party (upstream, sister project, and so on).

Also state whether AI or code-generation tools were used.

## 5. AI and tooling attribution

- AI tools **must not** appear in `Signed-off-by` (that trailer is a person's authorisation statement);
- when AI or code-generation tools are used, credit them with a `Co-authored-by:` or `Assisted-by: <model>` trailer;
- keep and formalise the existing conventions, such as `Moew`, `This PR is made by …`, and `Co-authored-by: <tool>`.

## 6. What this document does not cover

This document addresses provenance and attribution only. It does not introduce a CLA, a DCO gate, or a code-of-conduct enforcement process. If a concrete trigger ever arises (for example a vendor complaint, a licensing dispute, or a conflict that cannot be resolved internally), that will be discussed separately.
