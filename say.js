/**
 * Node
 *
 * LICENSE:    MIT
 *
 * @project    node-red-node-say
 * @package    NodeRedNode
 * @author     André Lademann <andre@programmerq.eu>
 * @copyright  Copyright (c) 2014 programmerq.eu (http://programmerq.eu)
 * @license    http://programmerq.eu/license
 * @since      2014-11-27 - 08:53:21 AM
 */
module.exports = function(RED) {
	function sayNode(config) {
		RED.nodes.createNode(this,config);
		var node = this;
		this.on('input', function(msg) {
			node.send(msg);
		});
	}
	RED.nodes.registerType('say',SayNode);
};
