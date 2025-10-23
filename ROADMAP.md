# Cardputer Wallet Delivery Roadmap

This roadmap breaks the specification into iterative milestones, highlighting critical deliverables, test coverage, and CI automation required for a production-grade release.

## Phase 0 – Project Foundation
- Finalize architecture vision and confirm hardware constraints (SPEC §1, §5).
- Establish repository structure with firmware, companion tooling, documentation, and test harness directories.
- Set up core developer tooling: formatter, linter, static analysis, unit-test framework, hardware emulators.
- Author CONTRIBUTING.md and coding standards aligned with security and performance goals.
- Bootstrap GitHub Actions workflows for build, lint, tests, artifact publishing, and nightly hardware-in-the-loop (SPEC §8, §10).

## Phase 1 – Secure Data Core
- Implement encrypted persistence layer with schema migrations (SPEC §3.1, §3.2, §6, §4 Security).
- Create domain services for accounts, categories, transactions with unit tests covering CRUD and currency conversion (SPEC §3.1–§3.2, §8).
- Integrate PBKDF2-based key management and passphrase setup flow with recovery options (SPEC §4 Security, §3.4).
- Deliver command-line simulator for data layer to accelerate test-driven development.
- CI: add formatting + static analysis gates, unit-test job, and schema migration verification.

## Phase 2 – User Experience & Core Wallet Flows
- Build LVGL-based UI scaffolding with navigation shell and theme engine (SPEC §3.5, §5).
- Implement transaction capture screens with batch entry mode and undo/redo (SPEC §3.2).
- Add balance overview dashboards and category insights (SPEC §2.2, §3.2).
- Ensure accessibility (font scaling, high contrast) and localization hooks (SPEC §3.5).
- Extend automated UI tests via emulator snapshots and Golden master comparisons (SPEC §8).
- Update CI to execute headless UI tests with artifact uploads for screenshots/regressions.

## Phase 3 – Portfolio & Advanced Modules
- Deliver portfolio data ingestion (CSV/JSON) and manual asset management (SPEC §3.3, §6).
- Integrate optional market data refresh service with configurable providers (SPEC §3.3).
- Implement charts/metrics optimized for Cardputer display constraints (SPEC §3.3, §5 Presentation).
- Add contextual tutorials and command palette for expert workflows (SPEC §3.5).
- Expand integration tests to cover portfolio workflows and ensure performance targets (SPEC §4 Performance, §8).
- CI enhancements: schedule nightly regression suite with coverage reports and performance benchmarks.

## Phase 4 – Sync, Backup & Companion Integration
- Implement encrypted QR/USB/Wi-Fi sync protocol with differential updates (SPEC §3.4, §5 APIs).
- Develop desktop/mobile companion reference client for data exchange and conflict resolution (SPEC §3.4, §5 APIs, §9 Documentation).
- Add automated backup scheduler with retention policies and telemetry hooks (SPEC §3.4, §7).
- Provide end-to-end sync tests (emulated hardware ↔ companion) and security penetration tests (SPEC §8, §10).
- Update CI to publish nightly sync compatibility matrix and signed artifacts for testers.

## Phase 5 – Hardening & Release Readiness
- Conduct full security review, threat modeling, and remediation (SPEC §4 Security, §10).
- Stress-test persistence, sync, and UI for reliability; integrate watchdog monitoring (SPEC §4 Reliability, §7).
- Finalize documentation: developer guide, user manual, API reference, privacy notice (SPEC §9).
- Implement opt-in telemetry with anonymization and diagnostics dashboard (SPEC §7).
- Achieve 80%+ code coverage and ensure zero P0/P1 defects prior to release (SPEC §8, §10).
- Prepare reproducible build pipeline, signed release artifacts, and release checklist execution (SPEC §10).

## Continuous Activities
- Maintain backlog grooming and cross-functional reviews at each phase gate.
- Monitor CI health dashboards; enforce green builds before merges.
- Collect user feedback from pilot testers and feed insights into future roadmap iterations.
