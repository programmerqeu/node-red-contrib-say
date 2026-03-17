# Contributing

Thanks for your interest in contributing to `node-red-contrib-say`. This document describes how to set up and work on the project locally.

## Development

If you are developing this node locally:

- Install dependencies with:

  ```bash
  pnpm install
  ```

- Run the unit tests (using Node's built‑in test runner and a mocked `say` implementation):

  ```bash
  pnpm test
  ```

  See [`test/README.md`](test/README.md) for more details.

> The tests do **not** trigger real audio. They use `SAY_TEST_MODULE` to inject a mock `say` module from `test/mocks/say.js`.

### Linting

- Lint the codebase with:

  ```bash
  pnpm lint
  ```

- Automatically fix simple issues where possible:

  ```bash
  pnpm lint:fix
  ```

### Git hooks

This project uses Husky to enforce basic checks before each commit:

- On every commit, the following run automatically:
  - `pnpm lint`
  - `pnpm test`

If either command fails, the commit is aborted so you can fix issues first.
