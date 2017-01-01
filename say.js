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
	 * Say node
	 *
	 * @property {*} config Configuration object
	 * @return void
	 **/
	function SayNode(config) {
		RED.nodes.createNode(this, config);
		var node = this;
		this.on('input', function (msg) {
			say.speak(
				this.name || msg.payload,
				this.voice,
				1,
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
