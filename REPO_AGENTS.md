# Repo-specific agent instructions

## Embassy-first firmware policy
- The firmware platform is standardized on the Embassy framework for executors, async traits, and hardware abstraction layers.
- Always prefer Embassy ecosystem crates (embassy-executor, embassy-usb, embassy-time, embassy-sync, etc.) when adding runtime capabilities.
- When an Embassy crate does not cover the needed functionality, document the gap and rationale with the change before adopting third-party or bespoke alternatives.
