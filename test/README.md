# Tests for node-red-contrib-say

Unit tests for the Say node using Node.js built-in test runner. The real `say` (TTS) package is replaced by a mock when `SAY_TEST_MODULE` is set so tests run without audio.

## Run tests

```bash
pnpm test
```

Or with the env var set explicitly:

```bash
SAY_TEST_MODULE=test/mocks/say.js node --test test/say.test.js
```

## What is tested

- **Node registration**: Type `say` is registered with RED and `createNode` is called with config.
- **Text / payload priority**: `config.text` > `config.name` > `msg.payload`.
- **Voice selection**: `config.voice` when not `":"`, else `config.voiceString`.
- **Speed**: `config.speed` (number or string), default `1`.
- **Success path**: `node.send(msg)` after `say.speak` succeeds.
- **Error path**: `node.error(err)` when `say.speak` fails; `node.send` is not called.
- **Edge cases**: Missing payload, undefined voice, full `msg` passed through to `send`.

## Mock (test/mocks/say.js)

Used when `SAY_TEST_MODULE=test/mocks/say.js`. Set `global.__SAY_MOCK_FAIL = true` in a test to simulate TTS failure.
