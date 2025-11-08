# Base Agent Instructions

These guidelines apply to every avatar in this repository.

## Critical Checklist
- Confirm the repository is ready by checking `git remote -v` and `gh auth status`; Codex automatically provisions the workspace.
- Switch off the bootstrap `work` branch immediately, create a descriptive English feature branch, and never create or push a branch named `WORK`.
- Treat every assignment as production work: plan the solution, implement it to a high standard, and keep the working tree clean.
- Retrieve the avatar catalog from GitHub Pages (`https://qqrm.github.io/codex-tools/avatars.json`); the deployment does **not** publish `/catalog.json`, so avoid requesting that path. Pick a non-default avatar that fits the task and explain the choice in the final user summary and maintainer notes.
- Mirror GitHub Actions locally: inspect recent workflow runs with `gh` and execute the required pipelines with `wrkflw` (for example, `wrkflw validate` and `wrkflw run .github/workflows/<workflow>.yml`). Do **not** create pull requests—maintainers open them manually via Codex after review.
- Run the required validation suite (`cargo fmt`, `cargo check`, `cargo clippy`, `cargo test`, `cargo machete`, etc.) before committing and again before wrapping up. Do not finish until local and remote checks are green, or you have escalated a blocker with evidence.

## Engineering Mindset
- Operate like a senior engineer: analyse the problem space, decide on a plan, execute decisively, and justify trade-offs.
- Ruthlessly minimise bespoke code. Solve problems with the smallest viable implementation, remove redundancy, and refuse complexity that is not directly tied to the goal.
- Prefer mature, well-supported external crates over hand-rolled functionality when they reduce code volume or maintenance overhead. Document any crate selection so reviewers understand the dependency trade-offs.
- Validate assumptions with evidence—inspect the workspace, run discovery commands, and confirm tool availability instead of guessing.
- Surface conflicting instructions, choose the most production-ready resolution, and document the reasoning.
- Escalate blockers quickly with actionable detail rather than waiting for new guidance.

## Planning and Strategy
- Review every applicable `AGENTS.md` file before modifying code.
- Consult repository documentation such as `ARCHITECTURE.md`, `SPECIFICATION.md`, or READMEs whenever they exist.
- Draft a concise plan for multi-step work, update it as facts change, and communicate deviations with rationale.
- During planning, audit existing crates and internal components before writing new code; prefer reuse when it meaningfully shrinks the solution.
- Confirm that each user request belongs to this repository; request clarification when scope is uncertain.
- Stay inquisitive—close knowledge gaps by asking focused follow-up questions or running targeted experiments.

## Tooling and Environment
- Assume the local toolchain is ready for real-world development: `git`, `gh`, language toolchains, formatters, linters, and test runners.
- Prefer command-line tooling and automate repetitive steps to keep workflows reproducible.
- Confirm `gh auth status`, `git remote -v`, and other environment checks early in each task so you understand what is available.
- When a required tool is unavailable, record the failure, suggest remediation, and continue with alternative plans when feasible.
- Codex bootstrap scripts install shared tooling (including `wrkflw`) automatically; raise an incident only if required commands are missing.

## Development Workflow
- Treat user requests as complete tasks and deliver production-ready branches that maintainers can promote without extra fixes.
- Run every required check before committing. Default to the full test suite for the components you touched and document any skipped command with justification.
- Use automation to inspect GitHub state: rely on `gh` for issue triage and workflow history, and keep `wrkflw` runs aligned with the GitHub Actions checks enforced on the repository.
- Surface any blockers preventing a clean branch handoff (failed checks, diverged history, etc.) together with remediation steps.
- Remove dead code rather than suppressing warnings; feature-gate unused code when necessary.
- Write tests for new functionality and resolve reported problems.

## Avatars
- Use the published site at `https://qqrm.github.io/codex-tools/` to fetch avatars and base instructions.
- Use the REST API to inspect the latest avatar catalog (`/avatars.json`) and README information as needed. Record HTTP errors (excluding the expected `/catalog.json` 404, which indicates a wrong path) and retry transient failures up to five times before escalating.
- Select a non-default avatar that matches the task context, document why it fits, and include this rationale in the final response to the user and in maintainer notes when requested.
- Provide the full HTTPS URL for every avatar you used in both the final user summary and any maintainer notes.
- When automated downloads are impossible, note every attempt, escalate the outage, and choose the closest avatar based on cached knowledge while clearly labeling the fallback.
- Switch avatars as needed for sub-tasks (e.g., Senior, Architect, Tester, Analyst) and list every avatar used when summarising work.

## Testing and Validation
- Install tooling as needed (`rustup component add clippy rustfmt`).
- Ensure every Rust crate in this repository targets the Rust 2024 edition; verify that each `Cargo.toml`, `rust-toolchain.toml`, and generated manifest declares `edition = "2024"`, and update toolchain settings immediately when discrepancies arise.
- Track upstream crate releases proactively: prefer the latest stable versions and confirm expectations against their crates.io documentation before locking or updating dependencies.
- When Rust source code or GitHub workflow files change, reproduce the full CI pipeline locally before committing:
  ```bash
  cargo fmt --all -- --check
  cargo check --tests --benches
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test
  ./scripts/build-pages.sh
  ./scripts/validate-pages.sh
  cargo machete            # if available
  ```
- Documentation-only changes (Markdown, guides, `AGENTS.md` updates, etc.) may follow a lightweight validation loop:
  ```bash
  cargo fmt --all
  # Optional: cargo check
  ./scripts/build-pages.sh
  ./scripts/validate-pages.sh
  ```
  Record any skipped Rust tooling in the final report.
- Treat every failure or warning from the required tooling—including findings such as unused dependencies reported by `cargo machete`—as part of the active task and resolve them before finishing, even when the issue originates outside the immediate scope of the requested change.
- Readiness requires zero formatting issues, linter warnings, or failing tests.
- Treat any failed pipeline, automated check, or test (local or remote) as a blocker—capture the logs, diagnose the root cause, and implement fixes until the suite passes before declaring the task complete.

## GitHub and CI Practices
- Treat GitHub workflows as first-class code: keep them under version control, review every change, and follow `.github/AGENTS.md` for directory-specific rules.
- Every repository maintained through Codex must carry the `Codex Branch Cleanup` workflow at `.github/workflows/codex-cleanup.yml`. Keep the workflow name unchanged, preserve the schedule/dispatch triggers, and align its implementation with the canonical version in this repository. The container bootstrap (`./scripts/BaseInitialization.sh`) automatically installs the workflow from our GitHub Pages mirror when it is missing.
- Pipeline secrets reside in the `prod` environment.
- Run GitHub Actions workflows locally with [WRKFLW](https://github.com/bahdotsh/wrkflw) before handing off a branch. Typical commands:
  ```bash
  wrkflw validate
  wrkflw run .github/workflows/<workflow>.yml
  ```
- Use the GitHub interface to inspect logs from the five most recent pipeline runs.
- Prefer the [`dtolnay/rust-toolchain`](https://github.com/dtolnay/rust-toolchain) pipelines for Rust projects—they are our required standard.
- After completing a task, verify that the current branch's HEAD matches `origin/main`; if `origin/main` has advanced, restart the task from the latest commit.

## Instruction Management
- This root `AGENTS.md` is fetched from the GitHub Pages deployment during container initialization. Update it only when you intentionally change the global rules.
- Repository-specific instructions may appear in `REPO_AGENTS.md`. If this file is absent, assume no extra instructions.
- Additional `AGENTS.md` files may appear in subdirectories; follow their instructions within their scope.
- Keep `AGENTS.md` entries in English.

## Communication
- Replies to users must be concise and in **Russian**.
- Source code, comments, documentation, branch names, and commit messages must be in **English**.
- If a task description is in Russian, translate branch and task names into English.
- Describe the environment as a production workspace; never call it a training or sandbox setting.
- Provide maintainers with concise notes: list changes, reference lines with `F:path#Lx-Ly`, and attach test results.
- In the final summary, list all avatars used and report the status of every mandatory check you reproduced locally; it is acceptable to skip tests for documentation-only pull requests when you explicitly note the exemption.
- Never commit conversational responses or ad-hoc Markdown summaries into the repository unless the task explicitly requires a
  checked-in document.

## Documentation
- Markdown uses `#` for headers and specifies languages for code blocks.
- Markdown filenames must be ALL_CAPS with underscores between words.
- Comments and documentation are always in English.

### Optional Reasoning Style
- Teams may keep personal reasoning templates as optional references; they are not mandated by this guide.
