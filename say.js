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

	var path = require('path');
	var say = process.env.SAY_TEST_MODULE
		? require(path.resolve(__dirname, process.env.SAY_TEST_MODULE))
		: require('say');

	/**
	 * Say node
	 *
	 * @property {*} config Configuration object
	 * @return void
	 **/
	function SayNode(config) {
		RED.nodes.createNode(this, config);
		var node = this;

		const voice = config.voice != ':' ? config.voice : config.voiceString

		this.on('input', function (msg) {
			say.speak(
				config.text || config.name || msg.payload,
				voice,
				config.speed ? Number(config.speed) : 1,
				function(err) {
					if (err) {
				    return node.error(err);
				  }
				node.send(msg);
			});
		});
	}

	RED.nodes.registerType('say', SayNode);
};
