# Cardputer Wallet Specification

## 1. Product Overview
- **Purpose**: Provide an offline-first personal finance wallet tailored for the M5Stack Cardputer device, enabling users to manage multiple accounts, capture transactions quickly, and synchronize with a companion service when connectivity is available.
- **Target users**: Enthusiasts who use the Cardputer as a pocketable companion for expense tracking and lightweight portfolio monitoring.
- **Primary goals**:
  - Fast capture of expenses and income with minimal input.
  - Secure storage of sensitive data on-device with optional encrypted export.
  - Seamless synchronization with desktop/mobile companion services through QR, Wi-Fi, or USB serial links.

## 2. Use Cases
1. **Quick expense capture** – User opens the wallet, selects an account, and logs an expense in under 10 seconds.
2. **Balance overview** – User views account balances and aggregated metrics for the week/month.
3. **Portfolio snapshot** – User imports external holdings data (CSV/JSON) and monitors valuations.
4. **Offline synchronization** – User generates an encrypted QR/USB payload to sync with another device when connectivity becomes available.
5. **Device provisioning** – User sets up the wallet for the first time, creating a master passphrase and restoring from a backup if desired.

## 3. Functional Requirements
### 3.1 Account and Category Management
- Create, edit, archive, and reorder accounts with metadata (name, currency, icon).
- Create and manage categories/tags with hierarchical relationships.
- Support multiple currencies with configurable exchange rates and automatic conversion to a base currency.

### 3.2 Transaction Capture & History
- Log income, expense, and transfer transactions with amount, currency, date, category, notes, and optional attachments.
- Batch entry mode for rapid capture (pre-fill last used values, smart suggestions).
- Full transaction history with filters by date, account, category, and free-text search.
- Undo/redo support for last N operations and soft-delete with recycle bin.

### 3.3 Portfolio Module
- Import holdings data via CSV/JSON or manual entry.
- Track asset metadata (symbol, name, type, acquisition price, quantity).
- Integrate with optional market data provider for price refresh when connected.
- Display charts and key metrics (gain/loss, allocation) optimized for the Cardputer display.

### 3.4 Synchronization & Backup
- Encrypted export/import of wallet data via QR codes, USB serial, and Wi-Fi AP mode.
- Differential sync to reduce payload size.
- Automatic daily local backups with configurable retention.
- Compatibility with desktop/mobile companion tools through a documented protocol.

### 3.5 User Interface & Experience
- UI optimized for the Cardputer keypad and small display.
- Configurable themes (light/dark) and accessibility options (font scaling, high contrast).
- Contextual tutorials and command palette for power users.
- Localization support (English baseline; architecture ready for additional locales).

## 4. Non-Functional Requirements
- **Performance**: UI actions must respond within 200 ms; sync operations must complete within 3 seconds for typical datasets (<5k transactions).
- **Security**: All sensitive data encrypted at rest using AES-256 with PBKDF2-derived keys; secrets never stored in plaintext.
- **Reliability**: Automatic crash recovery, watchdog to detect hangs, transactional persistence to avoid data loss.
- **Extensibility**: Modular architecture to support future payment integrations.
- **Compliance**: Follow MIT license obligations and provide privacy documentation for data handling.

## 5. System Architecture
- **Layers**:
  - Presentation layer built with LVGL (or equivalent) for Cardputer UI.
  - Application layer providing domain services (accounts, transactions, sync) written in C++ (preferred) or MicroPython, abstracted behind interfaces for testing.
  - Persistence layer using SQLite (preferred) or embedded key-value store, encrypted via SQLCipher or custom wrapper.
- **Modules**: Accounts, Transactions, Portfolio, Sync, Settings, Security, Telemetry.
- **APIs**: Provide gRPC-over-serial or REST-over-Wi-Fi adapters for companion integration.

## 6. Data Model
- Define schemas for accounts, categories, transactions, portfolios, user settings, sync checkpoints, and audit logs.
- Maintain migration framework with versioned upgrades and rollback support.

## 7. Telemetry & Logging
- Structured logging with log levels and rotation.
- Optional anonymous usage metrics (opt-in) exported via sync payloads.
- On-device diagnostics screen to view recent errors and system status.

## 8. Testing Strategy
- Unit tests for domain services and data access layers (minimum 80% coverage).
- Integration tests covering UI flows using emulator harnesses.
- Hardware-in-the-loop tests for sync and peripheral access (NFC, USB).
- Regression suite executed in CI (GitHub Actions) and nightly on dedicated hardware farm.

## 9. Documentation
- Developer guide covering architecture, build steps, and contribution workflow.
- User manual for onboarding, daily usage, and troubleshooting.
- API reference for companion protocol.

## 10. Release Criteria
- All critical defects resolved, zero open P0/P1 issues.
- CI pipeline green across formatting, linting, static analysis, and test stages.
- Security review completed with documented findings and mitigations.
- Signed release package with reproducible build scripts and published checksum.
