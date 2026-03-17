/**
 * Unit tests for the Say node (node-red-contrib-say).
 * Uses SAY_TEST_MODULE to inject test/mocks/say.js so no real TTS runs.
 * Run: SAY_TEST_MODULE=test/mocks/say.js node --test test/say.test.js
 * Or: pnpm test (script sets the env)
 */
const path = require('path');
if (!process.env.SAY_TEST_MODULE) {
	process.env.SAY_TEST_MODULE = path.join(__dirname, 'mocks', 'say.js');
}

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert');
const loadSayNode = require(path.join(__dirname, '..', 'say.js'));
const mockSay = require(path.join(__dirname, 'mocks', 'say.js'));

describe('Say node', { concurrency: 1 }, () => {
	let mockRED;
	let SayNodeConstructor;

	beforeEach(() => {
		mockSay.reset();
		const createNodeCalls = [];
		mockRED = {
			nodes: {
				createNode: (node, config) => {
					createNodeCalls.push({ node, config });
					node.id = 'test-node-id';
				},
				registerType: (name, constructor) => {
					assert.strictEqual(name, 'say');
					SayNodeConstructor = constructor;
				},
				_createNodeCalls: createNodeCalls,
			},
		};
		loadSayNode(mockRED);
		assert.ok(SayNodeConstructor, 'SayNode should be registered');
	});

	function createNode(config = {}) {
		const node = {
			on: (event, handler) => {
				node._inputHandler = handler;
			},
			error: (err) => {
				node._lastError = err;
			},
			send: (msg) => {
				node._lastSent = msg;
			},
			_lastError: null,
			_lastSent: null,
			_inputHandler: null,
		};
		SayNodeConstructor.call(node, config);
		return node;
	}

	describe('node registration', () => {
		it('registers type "say" with RED', () => {
			assert.ok(SayNodeConstructor);
			assert.strictEqual(typeof SayNodeConstructor, 'function');
		});

		it('calls RED.nodes.createNode with config when constructed', () => {
			const createNodeCalls = mockRED.nodes._createNodeCalls;
			createNodeCalls.length = 0;
			createNode({ text: 'hi', name: 'TestNode' });
			assert.ok(createNodeCalls.length >= 1);
			const lastCall = createNodeCalls[createNodeCalls.length - 1];
			assert.strictEqual(lastCall.config.text, 'hi');
			assert.strictEqual(lastCall.config.name, 'TestNode');
		});
	});

	describe('text / payload priority', () => {
		it('uses config.text when set', (t, done) => {
			const node = createNode({ text: 'Configured text', name: 'MyNode' });
			node._inputHandler({ payload: 'From payload' });
			setImmediate(() => {
				const last = mockSay.getLastCall();
				assert.ok(last);
				assert.strictEqual(last.text, 'Configured text');
				done();
			});
		});

		it('falls back to config.name when config.text is empty', (t, done) => {
			const node = createNode({ text: '', name: 'FallbackName' });
			node._inputHandler({ payload: 'From payload' });
			setImmediate(() => {
				assert.strictEqual(mockSay.getLastCall().text, 'FallbackName');
				done();
			});
		});

		it('falls back to msg.payload when config.text and config.name are empty', (t, done) => {
			const node = createNode({ text: '', name: '' });
			node._inputHandler({ payload: 'From payload' });
			setImmediate(() => {
				assert.strictEqual(mockSay.getLastCall().text, 'From payload');
				done();
			});
		});

		it('uses msg.payload when config has no text or name', (t, done) => {
			const node = createNode({});
			node._inputHandler({ payload: 'Only payload' });
			setImmediate(() => {
				assert.strictEqual(mockSay.getLastCall().text, 'Only payload');
				done();
			});
		});
	});

	describe('voice selection', () => {
		it('uses config.voice when not ":"', (t, done) => {
			const node = createNode({ voice: 'Alex' });
			node._inputHandler({ payload: 'test' });
			setImmediate(() => {
				assert.strictEqual(mockSay.getLastCall().voice, 'Alex');
				done();
			});
		});

		it('uses config.voiceString when config.voice is ":"', (t, done) => {
			const node = createNode({ voice: ':', voiceString: 'CustomVoice' });
			node._inputHandler({ payload: 'test' });
			setImmediate(() => {
				assert.strictEqual(mockSay.getLastCall().voice, 'CustomVoice');
				done();
			});
		});

		it('uses empty string for default voice when both voice and voiceString empty', (t, done) => {
			const node = createNode({ voice: '', voiceString: '' });
			node._inputHandler({ payload: 'test' });
			setImmediate(() => {
				assert.strictEqual(mockSay.getLastCall().voice, '');
				done();
			});
		});
	});

	describe('speed', () => {
		it('uses config.speed when set (number)', (t, done) => {
			const node = createNode({ speed: 1.5 });
			node._inputHandler({ payload: 'test' });
			setImmediate(() => {
				assert.strictEqual(mockSay.getLastCall().speed, 1.5);
				done();
			});
		});

		it('uses 1 when config.speed is not set', (t, done) => {
			const node = createNode({});
			node._inputHandler({ payload: 'test' });
			setImmediate(() => {
				assert.strictEqual(mockSay.getLastCall().speed, 1);
				done();
			});
		});

		it('converts string speed to number', (t, done) => {
			const node = createNode({ speed: '0.8' });
			node._inputHandler({ payload: 'test' });
			setImmediate(() => {
				assert.strictEqual(mockSay.getLastCall().speed, 0.8);
				done();
			});
		});
	});

	describe('success path', () => {
		it('calls node.send(msg) when say.speak succeeds', (t, done) => {
			const node = createNode({});
			const msg = { payload: 'hello' };
			node._inputHandler(msg);
			setImmediate(() => {
				assert.strictEqual(node._lastSent, msg);
				assert.strictEqual(node._lastError, null);
				done();
			});
		});
	});

	describe('error path', () => {
		it('calls node.error(err) when say.speak fails', (t, done) => {
			global.__SAY_MOCK_FAIL = true;
			const node = createNode({});
			node._inputHandler({ payload: 'test' });
			setImmediate(() => {
				try {
					assert.ok(node._lastError);
					assert.strictEqual(node._lastSent, null);
					done();
				} finally {
					global.__SAY_MOCK_FAIL = false;
				}
			});
		});

		it('does not call node.send when say.speak fails', (t, done) => {
			global.__SAY_MOCK_FAIL = true;
			const node = createNode({});
			node._inputHandler({ payload: 'test' });
			setImmediate(() => {
				try {
					assert.ok(node._lastError);
					assert.strictEqual(node._lastSent, null);
					done();
				} finally {
					global.__SAY_MOCK_FAIL = false;
				}
			});
		});
	});

	describe('edge cases', () => {
		it('handles msg without payload (uses config.text or config.name)', (t, done) => {
			const node = createNode({ text: 'Default text' });
			node._inputHandler({});
			setImmediate(() => {
				assert.strictEqual(mockSay.getLastCall().text, 'Default text');
				done();
			});
		});

		it('handles config.voice undefined (uses config.voice)', (t, done) => {
			const node = createNode({ voice: undefined, voiceString: 'Custom' });
			node._inputHandler({ payload: 'x' });
			setImmediate(() => {
				assert.strictEqual(mockSay.getLastCall().voice, undefined);
				done();
			});
		});

		it('passes through full msg object to node.send', (t, done) => {
			const node = createNode({ text: 'fixed' });
			const msg = { payload: 'ignored', topic: 'test', custom: 42 };
			node._inputHandler(msg);
			setImmediate(() => {
				assert.strictEqual(node._lastSent.topic, 'test');
				assert.strictEqual(node._lastSent.custom, 42);
				done();
			});
		});
	});
});
