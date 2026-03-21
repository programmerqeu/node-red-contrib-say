/**
 * Node
 *
 * LICENSE:    MIT
 *
 * @project    node-red-contrib-say
 * @package    NodeRedNode
 * @author     André Lademann <andre@programmerq.eu>
 * @copyright  Copyright (c) 2014 programmerq.eu (http://programmerq.eu)
 * @license    http://programmerq.eu/license
 * @since      2014-11-27 - 08:53:21 AM
 */
module.exports = function (RED) {
	'use strict';

	const path = require('path');
	const say = process.env.SAY_TEST_MODULE
		? require(path.resolve(__dirname, process.env.SAY_TEST_MODULE))
		: require('say');

	/**
	 * Text to speak: same priority as config.text || config.name || msg.payload,
	 * but msg.payload 0 (and false) are preserved instead of being skipped by ||.
	 *
	 * @param {*} config
	 * @param {*} msg
	 * @return {string}
	 */
	function resolveSpeakText(config, msg) {
		let raw = config.text;
		if (raw === undefined || raw === null || raw === '') {
			raw = config.name;
		}
		if (raw === undefined || raw === null || raw === '') {
			raw = msg.payload;
		}
		if (raw === undefined || raw === null || raw === '') {
			return '';
		}
		return String(raw);
	}

	/**
	 * Say node
	 *
	 * @property {*} config Configuration object
	 * @return void
	 **/
	function SayNode(config) {
		RED.nodes.createNode(this, config);
		const node = this;

		const voice = config.voice !== ':' ? config.voice : config.voiceString;

		this.on('input', function (msg) {
			say.speak(
				resolveSpeakText(config, msg),
				voice,
				config.speed ? Number(config.speed) : 1,
				function (err) {
					if (err) {
						return node.error(err);
					}
					node.send(msg);
			});
		});
	}

	RED.nodes.registerType('say', SayNode);
};
