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

## Local Node-RED development

Use this workflow to develop the node against a real Node-RED instance on your machine.

### 1) Prepare this repository

From the project root:

```bash
pnpm install
```

### 2) Link this package globally

Still in this repository:

```bash
pnpm link --global
```

### 3) Link it into your Node-RED user directory

In your Node-RED user directory (usually `~/.node-red`):

```bash
cd ~/.node-red
pnpm link node-red-contrib-say
```

> Important: run this command from `~/.node-red`, not from this repository.
> With pnpm v10, using `--global` here can fail with `Symlink path is the same as the target path`.

### 4) Start Node-RED

```bash
node-red
```

After startup, the `say` node should be available in the **Output** category.

### Fast edit/test loop

1. Edit files in this repository (`say.js`, `say.html`, docs, tests).
2. Restart Node-RED to reload runtime/editor files.
3. Refresh the Node-RED editor in your browser.
4. Re-test your flow.

### Alternative: install from local path (without global link)

If you do not want to use global linking, install directly from a local path:

```bash
cd ~/.node-red
pnpm add /absolute/path/to/node-red-contrib-say
```

Then restart Node-RED.

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
