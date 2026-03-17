# Contributing to node-red-contrib-say

Thanks for your interest in contributing to `node-red-contrib-say` – community help keeps this node alive and useful.

This document explains how to get set up, how to run tests, and how to structure your changes and commits.

All documentation is written in English and aims to be inclusive and gender-neutral.

---

## Getting started

### Prerequisites

- **Node.js**: v20+ (the repo currently uses the built-in `node:test` runner).
- **pnpm**: this project uses pnpm as the package manager (see `packageManager` in `package.json`).
- A working **Node-RED** installation is helpful for local manual testing.

### Clone and install

```bash
git clone https://github.com/programmerqeu/node-red-contrib-say.git
cd node-red-contrib-say
pnpm install
```

---

## Project structure (quick tour)

- `say.js` – implementation of the `say` Node-RED node.
- `say.html` – Node-RED editor UI and help for the node.
- `test/` – automated tests and test utilities:
  - `test/say.test.js` – unit tests for the node.
  - `test/mocks/say.js` – mock implementation of the `say` module used in tests.
  - `test/README.md` – documentation for the test setup.
- `.github/workflows/` – CI configuration (including Release Please and npm publish).
- `release-please-config.json` / `.release-please-manifest.json` – Release Please configuration and manifest.

---

## Running tests

Tests use the Node.js built-in test runner and a mocked `say` implementation to avoid real audio output.

From the project root:

```bash
pnpm test
```

Under the hood this runs:

```bash
SAY_TEST_MODULE=test/mocks/say.js node --test test/
```

The environment variable `SAY_TEST_MODULE` tells `say.js` to load the mock from `test/mocks/say.js` instead of the real `say` package.

> See [`test/README.md`](test/README.md) for more details on what is covered by the tests.

Please make sure tests pass before opening a pull request.

---

## Development workflow

1. **Fork** the repository (or create a feature branch if you have direct write access).
2. **Create a branch** for your change:

   ```bash
   git checkout -b feat/better-voice-handling
   ```

3. Make your changes to `say.js`, `say.html`, tests, or documentation as needed.
4. **Keep tests green**:

   ```bash
   pnpm test
   ```

5. Commit using **Conventional Commits** (see next section).
6. Push your branch and open a **pull request** against `main`.

If your change adds new configuration options or behaviours for the node:

- Update:
  - `say.html` (editor UI),
  - `say.js` (runtime implementation),
  - `README.md` (user-facing docs),
  - and tests in `test/say.test.js`.

---

## Commit messages (Conventional Commits)

This project uses the [Conventional Commits](https://www.conventionalcommits.org/) style. Some useful types:

- `feat: ...` – new user-facing feature for the node.
- `fix: ...` – bug fix.
- `docs: ...` – documentation-only changes.
- `test: ...` – tests only.
- `chore: ...` – build tooling, CI, non-user-facing maintenance.
- `refactor: ...` – internal refactoring with no behaviour change.

Examples:

- `feat: add custom voice string support`
- `fix: handle empty payload without crashing`
- `docs: update README with usage examples`
- `test: cover error path for invalid voice`

If a change is breaking (for example changing the node’s runtime behaviour or configuration in an incompatible way), add:

- `!` after the type, e.g. `feat!: ...`
- or a `BREAKING CHANGE:` section in the commit body.

Release Please will use these messages to determine version bumps and changelog entries.

---

## Releases (Release Please)

Releases are automated using **Release Please**:

- Do **not** manually bump `version` in `package.json`.
- Do **not** tag releases by hand.

Instead:

- Land your changes on `main` with proper Conventional Commits.
- Release Please creates a release PR and tags versions.
- The GitHub Actions workflows then handle npm publishing (using `NPM_TOKEN`) once a release is created.

If you touch release-related files:

- `release-please-config.json`
- `.release-please-manifest.json`
- `.github/workflows/release-please.yml`
- `.github/workflows/npm-publish.yml`

…please describe why in your PR description.

---

## Style and guidelines

### Code

- Follow the existing style in `say.js` / `say.html`.
- Keep the node behaviour **simple and predictable**:
  - Input comes in via `msg` and configuration.
  - Output is the same `msg`, optionally with additional properties (document those in the README if added).
- Handle errors by calling `node.error(err)` rather than throwing uncaught exceptions.

### Documentation

- Write docs in **English**.
- Keep language gender-neutral and inclusive.
- When adding new node options:
  - Document them in `README.md` under *Node configuration*.
  - If they are user-facing, describe them in the node help (`say.html`, `<script data-help-name="say">`).

### Tests

- New behaviour should come with new or updated tests.
- For changes that are difficult to test automatically (for example OS-specific TTS quirks), please explain your manual test steps in the PR description.

---

## Reporting issues

If you find a bug:

1. Check existing issues first to avoid duplicates.
2. Provide as much context as possible:
   - Node-RED version and Node.js version.
   - Operating system (macOS, Linux distro, Windows).
   - How you installed `node-red-contrib-say`.
   - A minimal flow that reproduces the issue (use the **Export** feature in the Node-RED editor).

Feature ideas are also welcome – please explain the use case and how you imagine the node should behave.

---

## Thank you

Your contributions – whether code, docs, tests, or issues – are very welcome.  
Even small improvements (typos, clarifications, better examples) can make a big difference for other users.

