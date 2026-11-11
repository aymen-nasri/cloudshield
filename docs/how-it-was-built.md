# How this was built

Design, implementation, process and how status is reported. Part of the [CloudShield documentation](../README.md#documentation).

Status markers: ✅ built and tested · 🧩 written as code, not deployed · 📐 designed only · 🔬 run on an emulator or a stand-in, not on real AWS.

## How this was built

CloudShield is a portfolio project: a working core plus a documented target design, built to show how I approach security engineering end to end.

- **Design.** The problem, architecture, threat model, response rules and attack scenarios started as my own written design. The main decisions are recorded as [architecture decision records](adr) and in [Design decisions](design-decisions.md).
- **Implementation.** I directed the work, chose the designs and approved every merge.
- **Process.** Every change went through a pull request and CI: tests (including PostgreSQL and policy-bypass tests), ruff, mypy, Gitleaks, Trivy and infrastructure validation. Nothing merges on a red build, and since v0.8.0 GitHub enforces that for everyone, including me.
- **Timeline.** The first two releases came out of a focused build sprint at the end of October 2026 (see the [changelog](../CHANGELOG.md)). Work continues in small pull requests along the [roadmap](roadmap.md#roadmap).
- **Honest status.** The ✅ / 🧩 / 📐 / 🔬 markers show what runs, what is written as code but not deployed, what is design only, and what has only run on an emulator.
