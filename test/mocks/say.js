/**
 * Mock "say" module for unit tests. Avoids real TTS.
 * Used when SAY_TEST_MODULE=test/mocks/say.js (relative to project root).
 * Set global.__SAY_MOCK_FAIL to an Error to make speak() call the callback with that error.
 */
const calls = [];
function speak(text, voice, speed, callback) {
	calls.push({ text, voice, speed, callback });
	if (typeof callback === 'function') {
		const err = typeof global !== 'undefined' && global.__SAY_MOCK_FAIL
			? (global.__SAY_MOCK_FAIL === true ? new Error('TTS failed') : global.__SAY_MOCK_FAIL)
			: null;
		setImmediate(() => callback(err));
	}
}
function getLastCall() {
	return calls[calls.length - 1] || null;
}
function getCalls() {
	return calls;
}
function reset() {
	calls.length = 0;
}
module.exports = { speak, getLastCall, getCalls, reset };
