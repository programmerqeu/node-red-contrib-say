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

	var say = require('say');

	/**
	 * SayNode
	 *
	 * @param config
	 * @constructor
	 * @return void
	 */
	function SayNode(config) {

		RED.nodes.createNode(this, config);
		var node = this;
		this.on('input', function (msg) {
			console.log(node);
			if(node.async) {
				say.speak(null, this.name || msg.payload , function() {
					node.send(msg);
				});
			} else {
				say.speak(null, this.name || msg.payload);
				node.send(msg);
			}
		});
	}

	RED.nodes.registerType('say', SayNode);

	/**
	 * SayOutNode
	 *
	 * @param config
	 * @constructor
	 * @return void
	 */
	function SayOutNode(config) {
		RED.nodes.createNode(this, config);
		var node = this;
		this.on('input', function (msg) {
			say.speak(null, this.name || msg.payload , function() {
				node.send(msg);
			});
		});
	}

	RED.nodes.registerType('say out', SayOutNode);
};
