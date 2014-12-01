var global = Function("return this;")();
/*!
  * Ender: open module JavaScript framework (client-lib)
  * copyright Dustin Diaz & Jacob Thornton 2011 (@ded @fat)
  * http://ender.no.de
  * License MIT
  */
!function (context) {

  // a global object for node.js module compatiblity
  // ============================================

  context['global'] = context

  // Implements simple module system
  // losely based on CommonJS Modules spec v1.1.1
  // ============================================

  var modules = {}
    , old = context.$

  function require (identifier) {
    // modules can be required from ender's build system, or found on the window
    var module = modules[identifier] || window[identifier]
    if (!module) throw new Error("Requested module '" + identifier + "' has not been defined.")
    return module
  }

  function provide (name, what) {
    return (modules[name] = what)
  }

  context['provide'] = provide
  context['require'] = require

  function aug(o, o2) {
    for (var k in o2) k != 'noConflict' && k != '_VERSION' && (o[k] = o2[k])
    return o
  }

  function boosh(s, r, els) {
    // string || node || nodelist || window
    if (typeof s == 'string' || s.nodeName || (s.length && 'item' in s) || s == window) {
      els = ender._select(s, r)
      els.selector = s
    } else els = isFinite(s.length) ? s : [s]
    return aug(els, boosh)
  }

  function ender(s, r) {
    return boosh(s, r)
  }

  aug(ender, {
      _VERSION: '0.3.6'
    , fn: boosh // for easy compat to jQuery plugins
    , ender: function (o, chain) {
        aug(chain ? boosh : ender, o)
      }
    , _select: function (s, r) {
        return (r || document).querySelectorAll(s)
      }
  })

  aug(boosh, {
    forEach: function (fn, scope, i) {
      // opt out of native forEach so we can intentionally call our own scope
      // defaulting to the current item and be able to return self
      for (i = 0, l = this.length; i < l; ++i) i in this && fn.call(scope || this[i], this[i], i, this)
      // return self for chaining
      return this
    },
    $: ender // handy reference to self
  })

  ender.noConflict = function () {
    context.$ = old
    return this
  }

  if (typeof module !== 'undefined' && module.exports) module.exports = ender
  // use subscript notation as extern for Closure compilation
  context['ender'] = context['$'] = context['ender'] || ender

}(this);
// pakmanager:hoek/lib/escape
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Declare internals
    
    var internals = {};
    
    
    exports.escapeJavaScript = function (input) {
    
        if (!input) {
            return '';
        }
    
        var escaped = '';
    
        for (var i = 0, il = input.length; i < il; ++i) {
    
            var charCode = input.charCodeAt(i);
    
            if (internals.isSafe(charCode)) {
                escaped += input[i];
            }
            else {
                escaped += internals.escapeJavaScriptChar(charCode);
            }
        }
    
        return escaped;
    };
    
    
    exports.escapeHtml = function (input) {
    
        if (!input) {
            return '';
        }
    
        var escaped = '';
    
        for (var i = 0, il = input.length; i < il; ++i) {
    
            var charCode = input.charCodeAt(i);
    
            if (internals.isSafe(charCode)) {
                escaped += input[i];
            }
            else {
                escaped += internals.escapeHtmlChar(charCode);
            }
        }
    
        return escaped;
    };
    
    
    internals.escapeJavaScriptChar = function (charCode) {
    
        if (charCode >= 256) {
            return '\\u' + internals.padLeft('' + charCode, 4);
        }
    
        var hexValue = new Buffer(String.fromCharCode(charCode), 'ascii').toString('hex');
        return '\\x' + internals.padLeft(hexValue, 2);
    };
    
    
    internals.escapeHtmlChar = function (charCode) {
    
        var namedEscape = internals.namedHtml[charCode];
        if (typeof namedEscape !== 'undefined') {
            return namedEscape;
        }
    
        if (charCode >= 256) {
            return '&#' + charCode + ';';
        }
    
        var hexValue = new Buffer(String.fromCharCode(charCode), 'ascii').toString('hex');
        return '&#x' + internals.padLeft(hexValue, 2) + ';';
    };
    
    
    internals.padLeft = function (str, len) {
    
        while (str.length < len) {
            str = '0' + str;
        }
    
        return str;
    };
    
    
    internals.isSafe = function (charCode) {
    
        return (typeof internals.safeCharCodes[charCode] !== 'undefined');
    };
    
    
    internals.namedHtml = {
        '38': '&amp;',
        '60': '&lt;',
        '62': '&gt;',
        '34': '&quot;',
        '160': '&nbsp;',
        '162': '&cent;',
        '163': '&pound;',
        '164': '&curren;',
        '169': '&copy;',
        '174': '&reg;'
    };
    
    
    internals.safeCharCodes = (function () {
    
        var safe = {};
    
        for (var i = 32; i < 123; ++i) {
    
            if ((i >= 97) ||                    // a-z
                (i >= 65 && i <= 90) ||         // A-Z
                (i >= 48 && i <= 57) ||         // 0-9
                i === 32 ||                     // space
                i === 46 ||                     // .
                i === 44 ||                     // ,
                i === 45 ||                     // -
                i === 58 ||                     // :
                i === 95) {                     // _
    
                safe[i] = null;
            }
        }
    
        return safe;
    }());
    
  provide("hoek/lib/escape", module.exports);
}(global));

// pakmanager:hoek/lib
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Load modules
    
    var Crypto = require('crypto');
    var Path = require('path');
    var Util = require('util');
    var Escape =  require('hoek/lib/escape');
    
    
    // Declare internals
    
    var internals = {};
    
    
    // Clone object or array
    
    exports.clone = function (obj, seen) {
    
        if (typeof obj !== 'object' ||
            obj === null) {
    
            return obj;
        }
    
        seen = seen || { orig: [], copy: [] };
    
        var lookup = seen.orig.indexOf(obj);
        if (lookup !== -1) {
            return seen.copy[lookup];
        }
    
        var newObj;
        var cloneDeep = false;
    
        if (!Array.isArray(obj)) {
            if (Buffer.isBuffer(obj)) {
                newObj = new Buffer(obj);
            }
            else if (obj instanceof Date) {
                newObj = new Date(obj.getTime());
            }
            else if (obj instanceof RegExp) {
                newObj = new RegExp(obj);
            }
            else {
                var proto = Object.getPrototypeOf(obj);
                if (!proto || proto.isImmutable) {
                    newObj = obj;
                }
                else {
                    newObj = Object.create(proto);
                    cloneDeep = true;
                }
            }
        }
        else {
            newObj = [];
            cloneDeep = true;
        }
    
        seen.orig.push(obj);
        seen.copy.push(newObj);
    
        if (cloneDeep) {
            for (var i in obj) {
                if (obj.hasOwnProperty(i)) {
                    var descriptor = Object.getOwnPropertyDescriptor(obj, i);
                    if (descriptor.get ||
                        descriptor.set) {
    
                        Object.defineProperty(newObj, i, descriptor);
                    }
                    else {
                        newObj[i] = exports.clone(obj[i], seen);
                    }
                }
            }
        }
    
        return newObj;
    };
    
    
    // Merge all the properties of source into target, source wins in conflict, and by default null and undefined from source are applied
    
    exports.merge = function (target, source, isNullOverride /* = true */, isMergeArrays /* = true */) {
    
        exports.assert(target && typeof target === 'object', 'Invalid target value: must be an object');
        exports.assert(source === null || source === undefined || typeof source === 'object', 'Invalid source value: must be null, undefined, or an object');
    
        if (!source) {
            return target;
        }
    
        if (Array.isArray(source)) {
            exports.assert(Array.isArray(target), 'Cannot merge array onto an object');
            if (isMergeArrays === false) {                                                  // isMergeArrays defaults to true
                target.length = 0;                                                          // Must not change target assignment
            }
    
            for (var i = 0, il = source.length; i < il; ++i) {
                target.push(exports.clone(source[i]));
            }
    
            return target;
        }
    
        var keys = Object.keys(source);
        for (var k = 0, kl = keys.length; k < kl; ++k) {
            var key = keys[k];
            var value = source[key];
            if (value &&
                typeof value === 'object') {
    
                if (!target[key] ||
                    typeof target[key] !== 'object' ||
                    (Array.isArray(target[key]) ^ Array.isArray(value)) ||
                    value instanceof Date ||
                    Buffer.isBuffer(value) ||
                    value instanceof RegExp) {
    
                    target[key] = exports.clone(value);
                }
                else {
                    exports.merge(target[key], value, isNullOverride, isMergeArrays);
                }
            }
            else {
                if (value !== null &&
                    value !== undefined) {                              // Explicit to preserve empty strings
    
                    target[key] = value;
                }
                else if (isNullOverride !== false) {                    // Defaults to true
                    target[key] = value;
                }
            }
        }
    
        return target;
    };
    
    
    // Apply options to a copy of the defaults
    
    exports.applyToDefaults = function (defaults, options) {
    
        exports.assert(defaults && typeof defaults === 'object', 'Invalid defaults value: must be an object');
        exports.assert(!options || options === true || typeof options === 'object', 'Invalid options value: must be true, falsy or an object');
    
        if (!options) {                                                 // If no options, return null
            return null;
        }
    
        var copy = exports.clone(defaults);
    
        if (options === true) {                                         // If options is set to true, use defaults
            return copy;
        }
    
        return exports.merge(copy, options, false, false);
    };
    
    
    // Clone an object except for the listed keys which are shallow copied
    
    exports.cloneWithShallow = function (source, keys) {
    
        if (!source ||
            typeof source !== 'object') {
    
            return source;
        }
    
        var storage = internals.store(source, keys);    // Move shallow copy items to storage
        var copy = exports.clone(source);               // Deep copy the rest
        internals.restore(copy, source, storage);       // Shallow copy the stored items and restore
        return copy;
    };
    
    
    internals.store = function (source, keys) {
    
        var storage = {};
        for (var i = 0, il = keys.length; i < il; ++i) {
            var key = keys[i];
            var value = exports.reach(source, key);
            if (value !== undefined) {
                storage[key] = value;
                internals.reachSet(source, key, undefined);
            }
        }
    
        return storage;
    };
    
    
    internals.restore = function (copy, source, storage) {
    
        var keys = Object.keys(storage);
        for (var i = 0, il = keys.length; i < il; ++i) {
            var key = keys[i];
            internals.reachSet(copy, key, storage[key]);
            internals.reachSet(source, key, storage[key]);
        }
    };
    
    
    internals.reachSet = function (obj, key, value) {
    
        var path = key.split('.');
        var ref = obj;
        for (var i = 0, il = path.length; i < il; ++i) {
            var segment = path[i];
            if (i + 1 === il) {
                ref[segment] = value;
            }
    
            ref = ref[segment];
        }
    };
    
    
    // Apply options to defaults except for the listed keys which are shallow copied from option without merging
    
    exports.applyToDefaultsWithShallow = function (defaults, options, keys) {
    
        exports.assert(defaults && typeof defaults === 'object', 'Invalid defaults value: must be an object');
        exports.assert(!options || options === true || typeof options === 'object', 'Invalid options value: must be true, falsy or an object');
        exports.assert(keys && Array.isArray(keys), 'Invalid keys');
    
        if (!options) {                                                 // If no options, return null
            return null;
        }
    
        var copy = exports.cloneWithShallow(defaults, keys);
    
        if (options === true) {                                         // If options is set to true, use defaults
            return copy;
        }
    
        var storage = internals.store(options, keys);   // Move shallow copy items to storage
        exports.merge(copy, options, false, false);     // Deep copy the rest
        internals.restore(copy, options, storage);      // Shallow copy the stored items and restore
        return copy;
    };
    
    
    // Deep object or array comparison
    
    exports.deepEqual = function (obj, ref, seen) {
    
        var type = typeof obj;
        if (type !== typeof ref) {
            return false;
        }
    
        if (type !== 'object' ||
            obj === null ||
            ref === null) {
    
            if (obj === ref) {                                                      // Copied from Deep-eql, copyright(c) 2013 Jake Luer, jake@alogicalparadox.com, MIT Licensed, https://github.com/chaijs/deep-eql
                return obj !== 0 || 1 / obj === 1 / ref;        // -0 / +0
            }
    
            return obj !== obj && ref !== ref;                  // NaN
        }
    
        seen = seen || [];
        if (seen.indexOf(obj) !== -1) {
            return true;                            // If previous comparison failed, it would have stopped execution
        }
    
        seen.push(obj);
    
        if (Array.isArray(obj)) {
            if (!Array.isArray(ref)) {
                return false;
            }
    
            if (obj.length !== ref.length) {
                return false;
            }
    
            for (var i = 0, il = obj.length; i < il; ++i) {
                if (!exports.deepEqual(obj[i], ref[i])) {
                    return false;
                }
            }
    
            return true;
        }
    
        if (Buffer.isBuffer(obj)) {
            if (!Buffer.isBuffer(ref)) {
                return false;
            }
    
            if (obj.length !== ref.length) {
                return false;
            }
    
            for (var j = 0, jl = obj.length; j < jl; ++j) {
                if (obj[j] !== ref[j]) {
                    return false;
                }
            }
    
            return true;
        }
    
        if (obj instanceof Date) {
            return (ref instanceof Date && obj.getTime() === ref.getTime());
        }
    
        if (obj instanceof RegExp) {
            return (ref instanceof RegExp && obj.toString() === ref.toString());
        }
    
        if (Object.getPrototypeOf(obj) !== Object.getPrototypeOf(ref)) {
            return false;
        }
    
        var keys = Object.keys(obj);
        for (var k = 0, kl = keys.length; k < kl; ++k) {
            var key = keys[k];
            var descriptor = Object.getOwnPropertyDescriptor(obj, key);
            if (descriptor.get) {
                if (!exports.deepEqual(descriptor, Object.getOwnPropertyDescriptor(ref, key), seen)) {
                    return false;
                }
            }
            else if (!exports.deepEqual(obj[key], ref[key], seen)) {
                return false;
            }
        }
    
        return true;
    };
    
    
    // Remove duplicate items from array
    
    exports.unique = function (array, key) {
    
        var index = {};
        var result = [];
    
        for (var i = 0, il = array.length; i < il; ++i) {
            var id = (key ? array[i][key] : array[i]);
            if (index[id] !== true) {
    
                result.push(array[i]);
                index[id] = true;
            }
        }
    
        return result;
    };
    
    
    // Convert array into object
    
    exports.mapToObject = function (array, key) {
    
        if (!array) {
            return null;
        }
    
        var obj = {};
        for (var i = 0, il = array.length; i < il; ++i) {
            if (key) {
                if (array[i][key]) {
                    obj[array[i][key]] = true;
                }
            }
            else {
                obj[array[i]] = true;
            }
        }
    
        return obj;
    };
    
    
    // Find the common unique items in two arrays
    
    exports.intersect = function (array1, array2, justFirst) {
    
        if (!array1 || !array2) {
            return [];
        }
    
        var common = [];
        var hash = (Array.isArray(array1) ? exports.mapToObject(array1) : array1);
        var found = {};
        for (var i = 0, il = array2.length; i < il; ++i) {
            if (hash[array2[i]] && !found[array2[i]]) {
                if (justFirst) {
                    return array2[i];
                }
    
                common.push(array2[i]);
                found[array2[i]] = true;
            }
        }
    
        return (justFirst ? null : common);
    };
    
    
    // Test if the reference contains the values
    
    exports.contain = function (ref, values, options) {
    
        /*
            string -> string(s)
            array -> item(s)
            object -> key(s)
            object -> object (key:value)
        */
    
        var valuePairs = null;
        if (typeof ref === 'object' &&
            typeof values === 'object' &&
            !Array.isArray(ref) &&
            !Array.isArray(values)) {
    
            valuePairs = values;
            values = Object.keys(values);
        }
        else {
            values = [].concat(values);
        }
    
        options = options || {};            // deep, once, only, part
    
        exports.assert(arguments.length >= 2, 'Insufficient arguments');
        exports.assert(typeof ref === 'string' || typeof ref === 'object', 'Reference must be string or an object');
        exports.assert(values.length, 'Values array cannot be empty');
    
        var compare = options.deep ? exports.deepEqual : function (a, b) { return a === b; };
    
        var misses = false;
        var matches = new Array(values.length);
        for (var i = 0, il = matches.length; i < il; ++i) {
            matches[i] = 0;
        }
    
        if (typeof ref === 'string') {
            var pattern = '(';
            for (i = 0, il = values.length; i < il; ++i) {
                var value = values[i];
                exports.assert(typeof value === 'string', 'Cannot compare string reference to non-string value');
                pattern += (i ? '|' : '') + exports.escapeRegex(value);
            }
    
            var regex = new RegExp(pattern + ')', 'g');
            var leftovers = ref.replace(regex, function ($0, $1) {
    
                var index = values.indexOf($1);
                ++matches[index];
                return '';          // Remove from string
            });
    
            misses = !!leftovers;
        }
        else if (Array.isArray(ref)) {
            for (i = 0, il = ref.length; i < il; ++i) {
                for (var j = 0, jl = values.length, matched = false; j < jl && matched === false; ++j) {
                    matched = compare(ref[i], values[j]) && j;
                }
    
                if (matched !== false) {
                    ++matches[matched];
                }
                else {
                    misses = true;
                }
            }
        }
        else {
            var keys = Object.keys(ref);
            for (i = 0, il = keys.length; i < il; ++i) {
                var key = keys[i];
                var pos = values.indexOf(key);
                if (pos !== -1) {
                    if (valuePairs &&
                        !compare(ref[key], valuePairs[key])) {
    
                        return false;
                    }
    
                    ++matches[pos];
                }
                else {
                    misses = true;
                }
            }
        }
    
        var result = false;
        for (i = 0, il = matches.length; i < il; ++i) {
            result = result || !!matches[i];
            if ((options.once && matches[i] > 1) ||
                (!options.part && !matches[i])) {
    
                return false;
            }
        }
    
        if (options.only &&
            misses) {
    
            return false;
        }
    
        return result;
    };
    
    
    // Flatten array
    
    exports.flatten = function (array, target) {
    
        var result = target || [];
    
        for (var i = 0, il = array.length; i < il; ++i) {
            if (Array.isArray(array[i])) {
                exports.flatten(array[i], result);
            }
            else {
                result.push(array[i]);
            }
        }
    
        return result;
    };
    
    
    // Convert an object key chain string ('a.b.c') to reference (object[a][b][c])
    
    exports.reach = function (obj, chain, options) {
    
        options = options || {};
        if (typeof options === 'string') {
            options = { separator: options };
        }
    
        var path = chain.split(options.separator || '.');
        var ref = obj;
        for (var i = 0, il = path.length; i < il; ++i) {
            if (!ref ||
                !ref.hasOwnProperty(path[i]) ||
                (typeof ref !== 'object' && options.functions === false)) {         // Only object and function can have properties
    
                exports.assert(!options.strict || i + 1 === il, 'Missing segment', path[i], 'in reach path ', chain);
                exports.assert(typeof ref === 'object' || options.functions === true || typeof ref !== 'function', 'Invalid segment', path[i], 'in reach path ', chain);
                ref = options.default;
                break;
            }
    
            ref = ref[path[i]];
        }
    
        return ref;
    };
    
    
    exports.formatStack = function (stack) {
    
        var trace = [];
        for (var i = 0, il = stack.length; i < il; ++i) {
            var item = stack[i];
            trace.push([item.getFileName(), item.getLineNumber(), item.getColumnNumber(), item.getFunctionName(), item.isConstructor()]);
        }
    
        return trace;
    };
    
    
    exports.formatTrace = function (trace) {
    
        var display = [];
    
        for (var i = 0, il = trace.length; i < il; ++i) {
            var row = trace[i];
            display.push((row[4] ? 'new ' : '') + row[3] + ' (' + row[0] + ':' + row[1] + ':' + row[2] + ')');
        }
    
        return display;
    };
    
    
    exports.callStack = function (slice) {
    
        // http://code.google.com/p/v8/wiki/JavaScriptStackTraceApi
    
        var v8 = Error.prepareStackTrace;
        Error.prepareStackTrace = function (err, stack) {
    
            return stack;
        };
    
        var capture = {};
        Error.captureStackTrace(capture, arguments.callee);     /*eslint no-caller:0 */
        var stack = capture.stack;
    
        Error.prepareStackTrace = v8;
    
        var trace = exports.formatStack(stack);
    
        if (slice) {
            return trace.slice(slice);
        }
    
        return trace;
    };
    
    
    exports.displayStack = function (slice) {
    
        var trace = exports.callStack(slice === undefined ? 1 : slice + 1);
    
        return exports.formatTrace(trace);
    };
    
    
    exports.abortThrow = false;
    
    
    exports.abort = function (message, hideStack) {
    
        if (process.env.NODE_ENV === 'test' || exports.abortThrow === true) {
            throw new Error(message || 'Unknown error');
        }
    
        var stack = '';
        if (!hideStack) {
            stack = exports.displayStack(1).join('\n\t');
        }
        console.log('ABORT: ' + message + '\n\t' + stack);
        process.exit(1);
    };
    
    
    exports.assert = function (condition /*, msg1, msg2, msg3 */) {
    
        if (condition) {
            return;
        }
    
        var msgs = [];
        for (var i = 1, il = arguments.length; i < il; ++i) {
            if (arguments[i] !== '') {
                msgs.push(arguments[i]);            // Avoids Array.slice arguments leak, allowing for V8 optimizations
            }
        }
    
        msgs = msgs.map(function (msg) {
    
            return typeof msg === 'string' ? msg : msg instanceof Error ? msg.message : exports.stringify(msg);
        });
        throw new Error(msgs.join(' ') || 'Unknown error');
    };
    
    
    exports.Timer = function () {
    
        this.ts = 0;
        this.reset();
    };
    
    
    exports.Timer.prototype.reset = function () {
    
        this.ts = Date.now();
    };
    
    
    exports.Timer.prototype.elapsed = function () {
    
        return Date.now() - this.ts;
    };
    
    
    exports.Bench = function () {
    
        this.ts = 0;
        this.reset();
    };
    
    
    exports.Bench.prototype.reset = function () {
    
        this.ts = exports.Bench.now();
    };
    
    
    exports.Bench.prototype.elapsed = function () {
    
        return exports.Bench.now() - this.ts;
    };
    
    
    exports.Bench.now = function () {
    
        var ts = process.hrtime();
        return (ts[0] * 1e3) + (ts[1] / 1e6);
    };
    
    
    // Escape string for Regex construction
    
    exports.escapeRegex = function (string) {
    
        // Escape ^$.*+-?=!:|\/()[]{},
        return string.replace(/[\^\$\.\*\+\-\?\=\!\:\|\\\/\(\)\[\]\{\}\,]/g, '\\$&');
    };
    
    
    // Base64url (RFC 4648) encode
    
    exports.base64urlEncode = function (value, encoding) {
    
        var buf = (Buffer.isBuffer(value) ? value : new Buffer(value, encoding || 'binary'));
        return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
    };
    
    
    // Base64url (RFC 4648) decode
    
    exports.base64urlDecode = function (value, encoding) {
    
        if (value &&
            !/^[\w\-]*$/.test(value)) {
    
            return new Error('Invalid character');
        }
    
        try {
            var buf = new Buffer(value, 'base64');
            return (encoding === 'buffer' ? buf : buf.toString(encoding || 'binary'));
        }
        catch (err) {
            return err;
        }
    };
    
    
    // Escape attribute value for use in HTTP header
    
    exports.escapeHeaderAttribute = function (attribute) {
    
        // Allowed value characters: !#$%&'()*+,-./:;<=>?@[]^_`{|}~ and space, a-z, A-Z, 0-9, \, "
    
        exports.assert(/^[ \w\!#\$%&'\(\)\*\+,\-\.\/\:;<\=>\?@\[\]\^`\{\|\}~\"\\]*$/.test(attribute), 'Bad attribute value (' + attribute + ')');
    
        return attribute.replace(/\\/g, '\\\\').replace(/\"/g, '\\"');                             // Escape quotes and slash
    };
    
    
    exports.escapeHtml = function (string) {
    
        return Escape.escapeHtml(string);
    };
    
    
    exports.escapeJavaScript = function (string) {
    
        return Escape.escapeJavaScript(string);
    };
    
    
    exports.nextTick = function (callback) {
    
        return function () {
    
            var args = arguments;
            process.nextTick(function () {
    
                callback.apply(null, args);
            });
        };
    };
    
    
    exports.once = function (method) {
    
        if (method._hoekOnce) {
            return method;
        }
    
        var once = false;
        var wrapped = function () {
    
            if (!once) {
                once = true;
                method.apply(null, arguments);
            }
        };
    
        wrapped._hoekOnce = true;
    
        return wrapped;
    };
    
    
    exports.isAbsolutePath = function (path, platform) {
    
        if (!path) {
            return false;
        }
    
        if (Path.isAbsolute) {                      // node >= 0.11
            return Path.isAbsolute(path);
        }
    
        platform = platform || process.platform;
    
        // Unix
    
        if (platform !== 'win32') {
            return path[0] === '/';
        }
    
        // Windows
    
        return !!/^(?:[a-zA-Z]:[\\\/])|(?:[\\\/]{2}[^\\\/]+[\\\/]+[^\\\/])/.test(path);        // C:\ or \\something\something
    };
    
    
    exports.isInteger = function (value) {
    
        return (typeof value === 'number' &&
                parseFloat(value) === parseInt(value, 10) &&
                !isNaN(value));
    };
    
    
    exports.ignore = function () { };
    
    
    exports.inherits = Util.inherits;
    
    
    exports.format = Util.format;
    
    
    exports.transform = function (source, transform, options) {
    
        exports.assert(source === null || source === undefined || typeof source === 'object', 'Invalid source object: must be null, undefined, or an object');
    
        var result = {};
        var keys = Object.keys(transform);
    
        for (var k = 0, kl = keys.length; k < kl; ++k) {
            var key = keys[k];
            var path = key.split('.');
            var sourcePath = transform[key];
    
            exports.assert(typeof sourcePath === 'string', 'All mappings must be "." delineated strings');
    
            var segment;
            var res = result;
    
            while (path.length > 1) {
                segment = path.shift();
                if (!res[segment]) {
                    res[segment] = {};
                }
                res = res[segment];
            }
            segment = path.shift();
            res[segment] = exports.reach(source, sourcePath, options);
        }
    
        return result;
    };
    
    
    exports.uniqueFilename = function (path, extension) {
    
        if (extension) {
            extension = extension[0] !== '.' ? '.' + extension : extension;
        }
        else {
            extension = '';
        }
    
        path = Path.resolve(path);
        var name = [Date.now(), process.pid, Crypto.randomBytes(8).toString('hex')].join('-') + extension;
        return Path.join(path, name);
    };
    
    
    exports.stringify = function () {
    
        try {
            return JSON.stringify.apply(null, arguments);
        }
        catch (err) {
            return '[Cannot display object: ' + err.message + ']';
        }
    };
    
    
    exports.shallow = function (source) {
    
        var target = {};
        var keys = Object.keys(source);
        for (var i = 0, il = keys.length; i < il; ++i) {
            var key = keys[i];
            target[key] = source[key];
        }
    
        return target;
    };
    
  provide("hoek/lib", module.exports);
}(global));

// pakmanager:hoek
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  module.exports =  require('hoek/lib');
    
  provide("hoek", module.exports);
}(global));

// pakmanager:core-util-is
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright Joyent, Inc. and other Node contributors.
    //
    // Permission is hereby granted, free of charge, to any person obtaining a
    // copy of this software and associated documentation files (the
    // "Software"), to deal in the Software without restriction, including
    // without limitation the rights to use, copy, modify, merge, publish,
    // distribute, sublicense, and/or sell copies of the Software, and to permit
    // persons to whom the Software is furnished to do so, subject to the
    // following conditions:
    //
    // The above copyright notice and this permission notice shall be included
    // in all copies or substantial portions of the Software.
    //
    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
    // NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    // DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    // OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
    // USE OR OTHER DEALINGS IN THE SOFTWARE.
    
    // NOTE: These type checking functions intentionally don't use `instanceof`
    // because it is fragile and can be easily faked with `Object.create()`.
    function isArray(ar) {
      return Array.isArray(ar);
    }
    exports.isArray = isArray;
    
    function isBoolean(arg) {
      return typeof arg === 'boolean';
    }
    exports.isBoolean = isBoolean;
    
    function isNull(arg) {
      return arg === null;
    }
    exports.isNull = isNull;
    
    function isNullOrUndefined(arg) {
      return arg == null;
    }
    exports.isNullOrUndefined = isNullOrUndefined;
    
    function isNumber(arg) {
      return typeof arg === 'number';
    }
    exports.isNumber = isNumber;
    
    function isString(arg) {
      return typeof arg === 'string';
    }
    exports.isString = isString;
    
    function isSymbol(arg) {
      return typeof arg === 'symbol';
    }
    exports.isSymbol = isSymbol;
    
    function isUndefined(arg) {
      return arg === void 0;
    }
    exports.isUndefined = isUndefined;
    
    function isRegExp(re) {
      return isObject(re) && objectToString(re) === '[object RegExp]';
    }
    exports.isRegExp = isRegExp;
    
    function isObject(arg) {
      return typeof arg === 'object' && arg !== null;
    }
    exports.isObject = isObject;
    
    function isDate(d) {
      return isObject(d) && objectToString(d) === '[object Date]';
    }
    exports.isDate = isDate;
    
    function isError(e) {
      return isObject(e) &&
          (objectToString(e) === '[object Error]' || e instanceof Error);
    }
    exports.isError = isError;
    
    function isFunction(arg) {
      return typeof arg === 'function';
    }
    exports.isFunction = isFunction;
    
    function isPrimitive(arg) {
      return arg === null ||
             typeof arg === 'boolean' ||
             typeof arg === 'number' ||
             typeof arg === 'string' ||
             typeof arg === 'symbol' ||  // ES6 symbol
             typeof arg === 'undefined';
    }
    exports.isPrimitive = isPrimitive;
    
    function isBuffer(arg) {
      return Buffer.isBuffer(arg);
    }
    exports.isBuffer = isBuffer;
    
    function objectToString(o) {
      return Object.prototype.toString.call(o);
    }
  provide("core-util-is", module.exports);
}(global));

// pakmanager:isarray
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  module.exports = Array.isArray || function (arr) {
      return Object.prototype.toString.call(arr) == '[object Array]';
    };
    
  provide("isarray", module.exports);
}(global));

// pakmanager:string_decoder
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright Joyent, Inc. and other Node contributors.
    //
    // Permission is hereby granted, free of charge, to any person obtaining a
    // copy of this software and associated documentation files (the
    // "Software"), to deal in the Software without restriction, including
    // without limitation the rights to use, copy, modify, merge, publish,
    // distribute, sublicense, and/or sell copies of the Software, and to permit
    // persons to whom the Software is furnished to do so, subject to the
    // following conditions:
    //
    // The above copyright notice and this permission notice shall be included
    // in all copies or substantial portions of the Software.
    //
    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
    // NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    // DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    // OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
    // USE OR OTHER DEALINGS IN THE SOFTWARE.
    
    var Buffer = require('buffer').Buffer;
    
    var isBufferEncoding = Buffer.isEncoding
      || function(encoding) {
           switch (encoding && encoding.toLowerCase()) {
             case 'hex': case 'utf8': case 'utf-8': case 'ascii': case 'binary': case 'base64': case 'ucs2': case 'ucs-2': case 'utf16le': case 'utf-16le': case 'raw': return true;
             default: return false;
           }
         }
    
    
    function assertEncoding(encoding) {
      if (encoding && !isBufferEncoding(encoding)) {
        throw new Error('Unknown encoding: ' + encoding);
      }
    }
    
    // StringDecoder provides an interface for efficiently splitting a series of
    // buffers into a series of JS strings without breaking apart multi-byte
    // characters. CESU-8 is handled as part of the UTF-8 encoding.
    //
    // @TODO Handling all encodings inside a single object makes it very difficult
    // to reason about this code, so it should be split up in the future.
    // @TODO There should be a utf8-strict encoding that rejects invalid UTF-8 code
    // points as used by CESU-8.
    var StringDecoder = exports.StringDecoder = function(encoding) {
      this.encoding = (encoding || 'utf8').toLowerCase().replace(/[-_]/, '');
      assertEncoding(encoding);
      switch (this.encoding) {
        case 'utf8':
          // CESU-8 represents each of Surrogate Pair by 3-bytes
          this.surrogateSize = 3;
          break;
        case 'ucs2':
        case 'utf16le':
          // UTF-16 represents each of Surrogate Pair by 2-bytes
          this.surrogateSize = 2;
          this.detectIncompleteChar = utf16DetectIncompleteChar;
          break;
        case 'base64':
          // Base-64 stores 3 bytes in 4 chars, and pads the remainder.
          this.surrogateSize = 3;
          this.detectIncompleteChar = base64DetectIncompleteChar;
          break;
        default:
          this.write = passThroughWrite;
          return;
      }
    
      // Enough space to store all bytes of a single character. UTF-8 needs 4
      // bytes, but CESU-8 may require up to 6 (3 bytes per surrogate).
      this.charBuffer = new Buffer(6);
      // Number of bytes received for the current incomplete multi-byte character.
      this.charReceived = 0;
      // Number of bytes expected for the current incomplete multi-byte character.
      this.charLength = 0;
    };
    
    
    // write decodes the given buffer and returns it as JS string that is
    // guaranteed to not contain any partial multi-byte characters. Any partial
    // character found at the end of the buffer is buffered up, and will be
    // returned when calling write again with the remaining bytes.
    //
    // Note: Converting a Buffer containing an orphan surrogate to a String
    // currently works, but converting a String to a Buffer (via `new Buffer`, or
    // Buffer#write) will replace incomplete surrogates with the unicode
    // replacement character. See https://codereview.chromium.org/121173009/ .
    StringDecoder.prototype.write = function(buffer) {
      var charStr = '';
      // if our last write ended with an incomplete multibyte character
      while (this.charLength) {
        // determine how many remaining bytes this buffer has to offer for this char
        var available = (buffer.length >= this.charLength - this.charReceived) ?
            this.charLength - this.charReceived :
            buffer.length;
    
        // add the new bytes to the char buffer
        buffer.copy(this.charBuffer, this.charReceived, 0, available);
        this.charReceived += available;
    
        if (this.charReceived < this.charLength) {
          // still not enough chars in this buffer? wait for more ...
          return '';
        }
    
        // remove bytes belonging to the current character from the buffer
        buffer = buffer.slice(available, buffer.length);
    
        // get the character that was split
        charStr = this.charBuffer.slice(0, this.charLength).toString(this.encoding);
    
        // CESU-8: lead surrogate (D800-DBFF) is also the incomplete character
        var charCode = charStr.charCodeAt(charStr.length - 1);
        if (charCode >= 0xD800 && charCode <= 0xDBFF) {
          this.charLength += this.surrogateSize;
          charStr = '';
          continue;
        }
        this.charReceived = this.charLength = 0;
    
        // if there are no more bytes in this buffer, just emit our char
        if (buffer.length === 0) {
          return charStr;
        }
        break;
      }
    
      // determine and set charLength / charReceived
      this.detectIncompleteChar(buffer);
    
      var end = buffer.length;
      if (this.charLength) {
        // buffer the incomplete character bytes we got
        buffer.copy(this.charBuffer, 0, buffer.length - this.charReceived, end);
        end -= this.charReceived;
      }
    
      charStr += buffer.toString(this.encoding, 0, end);
    
      var end = charStr.length - 1;
      var charCode = charStr.charCodeAt(end);
      // CESU-8: lead surrogate (D800-DBFF) is also the incomplete character
      if (charCode >= 0xD800 && charCode <= 0xDBFF) {
        var size = this.surrogateSize;
        this.charLength += size;
        this.charReceived += size;
        this.charBuffer.copy(this.charBuffer, size, 0, size);
        buffer.copy(this.charBuffer, 0, 0, size);
        return charStr.substring(0, end);
      }
    
      // or just emit the charStr
      return charStr;
    };
    
    // detectIncompleteChar determines if there is an incomplete UTF-8 character at
    // the end of the given buffer. If so, it sets this.charLength to the byte
    // length that character, and sets this.charReceived to the number of bytes
    // that are available for this character.
    StringDecoder.prototype.detectIncompleteChar = function(buffer) {
      // determine how many bytes we have to check at the end of this buffer
      var i = (buffer.length >= 3) ? 3 : buffer.length;
    
      // Figure out if one of the last i bytes of our buffer announces an
      // incomplete char.
      for (; i > 0; i--) {
        var c = buffer[buffer.length - i];
    
        // See http://en.wikipedia.org/wiki/UTF-8#Description
    
        // 110XXXXX
        if (i == 1 && c >> 5 == 0x06) {
          this.charLength = 2;
          break;
        }
    
        // 1110XXXX
        if (i <= 2 && c >> 4 == 0x0E) {
          this.charLength = 3;
          break;
        }
    
        // 11110XXX
        if (i <= 3 && c >> 3 == 0x1E) {
          this.charLength = 4;
          break;
        }
      }
      this.charReceived = i;
    };
    
    StringDecoder.prototype.end = function(buffer) {
      var res = '';
      if (buffer && buffer.length)
        res = this.write(buffer);
    
      if (this.charReceived) {
        var cr = this.charReceived;
        var buf = this.charBuffer;
        var enc = this.encoding;
        res += buf.slice(0, cr).toString(enc);
      }
    
      return res;
    };
    
    function passThroughWrite(buffer) {
      return buffer.toString(this.encoding);
    }
    
    function utf16DetectIncompleteChar(buffer) {
      this.charReceived = buffer.length % 2;
      this.charLength = this.charReceived ? 2 : 0;
    }
    
    function base64DetectIncompleteChar(buffer) {
      this.charReceived = buffer.length % 3;
      this.charLength = this.charReceived ? 3 : 0;
    }
    
  provide("string_decoder", module.exports);
}(global));

// pakmanager:inherits
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  module.exports = require('util').inherits
    
  provide("inherits", module.exports);
}(global));

// pakmanager:delayed-stream
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  var Stream = require('stream').Stream;
    var util = require('util');
    
    module.exports = DelayedStream;
    function DelayedStream() {
      this.source = null;
      this.dataSize = 0;
      this.maxDataSize = 1024 * 1024;
      this.pauseStream = true;
    
      this._maxDataSizeExceeded = false;
      this._released = false;
      this._bufferedEvents = [];
    }
    util.inherits(DelayedStream, Stream);
    
    DelayedStream.create = function(source, options) {
      var delayedStream = new this();
    
      options = options || {};
      for (var option in options) {
        delayedStream[option] = options[option];
      }
    
      delayedStream.source = source;
    
      var realEmit = source.emit;
      source.emit = function() {
        delayedStream._handleEmit(arguments);
        return realEmit.apply(source, arguments);
      };
    
      source.on('error', function() {});
      if (delayedStream.pauseStream) {
        source.pause();
      }
    
      return delayedStream;
    };
    
    DelayedStream.prototype.__defineGetter__('readable', function() {
      return this.source.readable;
    });
    
    DelayedStream.prototype.setEncoding = function() {
      return this.source.setEncoding.apply(this.source, arguments);
    };
    
    DelayedStream.prototype.resume = function() {
      if (!this._released) {
        this.release();
      }
    
      this.source.resume();
    };
    
    DelayedStream.prototype.pause = function() {
      this.source.pause();
    };
    
    DelayedStream.prototype.release = function() {
      this._released = true;
    
      this._bufferedEvents.forEach(function(args) {
        this.emit.apply(this, args);
      }.bind(this));
      this._bufferedEvents = [];
    };
    
    DelayedStream.prototype.pipe = function() {
      var r = Stream.prototype.pipe.apply(this, arguments);
      this.resume();
      return r;
    };
    
    DelayedStream.prototype._handleEmit = function(args) {
      if (this._released) {
        this.emit.apply(this, args);
        return;
      }
    
      if (args[0] === 'data') {
        this.dataSize += args[1].length;
        this._checkIfMaxDataSizeExceeded();
      }
    
      this._bufferedEvents.push(args);
    };
    
    DelayedStream.prototype._checkIfMaxDataSizeExceeded = function() {
      if (this._maxDataSizeExceeded) {
        return;
      }
    
      if (this.dataSize <= this.maxDataSize) {
        return;
      }
    
      this._maxDataSizeExceeded = true;
      var message =
        'DelayedStream#maxDataSize of ' + this.maxDataSize + ' bytes exceeded.'
      this.emit('error', new Error(message));
    };
    
  provide("delayed-stream", module.exports);
}(global));

// pakmanager:boom/lib
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Load modules
    
    var Http = require('http');
    var Hoek = require('hoek');
    
    
    // Declare internals
    
    var internals = {};
    
    
    exports.wrap = function (error, statusCode, message) {
    
        Hoek.assert(error instanceof Error, 'Cannot wrap non-Error object');
        return (error.isBoom ? error : internals.initialize(error, statusCode || 500, message));
    };
    
    
    exports.create = function (statusCode, message, data) {
    
        var error = new Error(message ? message : undefined);       // Avoids settings null message
        error.data = data || null;
        internals.initialize(error, statusCode);
        return error;
    };
    
    
    internals.initialize = function (error, statusCode, message) {
    
        Hoek.assert(!isNaN(parseFloat(statusCode)) && isFinite(statusCode) && statusCode >= 400, 'First argument must be a number (400+):', statusCode);
    
        error.isBoom = true;
    
        if (!error.hasOwnProperty('data')) {
            error.data = null;
        }
    
        error.output = {
            statusCode: statusCode,
            payload: {},
            headers: {}
        };
    
        error.reformat = internals.reformat;
        error.reformat();
    
        if (!message &&
            !error.message) {
    
            message = error.output.payload.error;
        }
    
        if (message) {
            error.message = (message + (error.message ? ': ' + error.message : ''));
        }
    
        return error;
    };
    
    
    internals.reformat = function () {
    
        this.output.payload.statusCode = this.output.statusCode;
        this.output.payload.error = Http.STATUS_CODES[this.output.statusCode] || 'Unknown';
    
        if (this.output.statusCode === 500) {
            this.output.payload.message = 'An internal server error occurred';              // Hide actual error from user
        }
        else if (this.message) {
            this.output.payload.message = this.message;
        }
    };
    
    
    // 4xx Client Errors
    
    exports.badRequest = function (message, data) {
    
        return exports.create(400, message, data);
    };
    
    
    exports.unauthorized = function (message, scheme, attributes) {          // Or function (message, wwwAuthenticate[])
    
        var err = exports.create(401, message);
    
        if (!scheme) {
            return err;
        }
    
        var wwwAuthenticate = '';
        var i = 0;
        var il = 0;
    
        if (typeof scheme === 'string') {
    
            // function (message, scheme, attributes)
    
            wwwAuthenticate = scheme;
            if (attributes) {
                var names = Object.keys(attributes);
                for (i = 0, il = names.length; i < il; ++i) {
                    if (i) {
                        wwwAuthenticate += ',';
                    }
    
                    var value = attributes[names[i]];
                    if (value === null ||
                        value === undefined) {              // Value can be zero
    
                        value = '';
                    }
                    wwwAuthenticate += ' ' + names[i] + '="' + Hoek.escapeHeaderAttribute(value.toString()) + '"';
                }
            }
    
            if (message) {
                if (attributes) {
                    wwwAuthenticate += ',';
                }
                wwwAuthenticate += ' error="' + Hoek.escapeHeaderAttribute(message) + '"';
            }
            else {
                err.isMissing = true;
            }
        }
        else {
    
            // function (message, wwwAuthenticate[])
    
            var wwwArray = scheme;
            for (i = 0, il = wwwArray.length; i < il; ++i) {
                if (i) {
                    wwwAuthenticate += ', ';
                }
    
                wwwAuthenticate += wwwArray[i];
            }
        }
    
        err.output.headers['WWW-Authenticate'] = wwwAuthenticate;
    
        return err;
    };
    
    
    exports.forbidden = function (message, data) {
    
        return exports.create(403, message, data);
    };
    
    
    exports.notFound = function (message, data) {
    
        return exports.create(404, message, data);
    };
    
    
    exports.methodNotAllowed = function (message, data) {
    
        return exports.create(405, message, data);
    };
    
    
    exports.notAcceptable = function (message, data) {
    
        return exports.create(406, message, data);
    };
    
    
    exports.proxyAuthRequired = function (message, data) {
    
        return exports.create(407, message, data);
    };
    
    
    exports.clientTimeout = function (message, data) {
    
        return exports.create(408, message, data);
    };
    
    
    exports.conflict = function (message, data) {
    
        return exports.create(409, message, data);
    };
    
    
    exports.resourceGone = function (message, data) {
    
        return exports.create(410, message, data);
    };
    
    
    exports.lengthRequired = function (message, data) {
    
        return exports.create(411, message, data);
    };
    
    
    exports.preconditionFailed = function (message, data) {
    
        return exports.create(412, message, data);
    };
    
    
    exports.entityTooLarge = function (message, data) {
    
        return exports.create(413, message, data);
    };
    
    
    exports.uriTooLong = function (message, data) {
    
        return exports.create(414, message, data);
    };
    
    
    exports.unsupportedMediaType = function (message, data) {
    
        return exports.create(415, message, data);
    };
    
    
    exports.rangeNotSatisfiable = function (message, data) {
    
        return exports.create(416, message, data);
    };
    
    
    exports.expectationFailed = function (message, data) {
    
        return exports.create(417, message, data);
    };
    
    exports.badData = function (message, data) {
    
        return exports.create(422, message, data);
    };
    
    
    exports.tooManyRequests = function (message, data) {
    
        return exports.create(429, message, data);
    };
    
    
    // 5xx Server Errors
    
    exports.internal = function (message, data, statusCode) {
    
        var error = (data instanceof Error ? exports.wrap(data, statusCode, message) : exports.create(statusCode || 500, message));
    
        if (data instanceof Error === false) {
            error.data = data;
        }
    
        return error;
    };
    
    
    exports.notImplemented = function (message, data) {
    
        return exports.internal(message, data, 501);
    };
    
    
    exports.badGateway = function (message, data) {
    
        return exports.internal(message, data, 502);
    };
    
    
    exports.serverTimeout = function (message, data) {
    
        return exports.internal(message, data, 503);
    };
    
    
    exports.gatewayTimeout = function (message, data) {
    
        return exports.internal(message, data, 504);
    };
    
    
    exports.badImplementation = function (message, data) {
    
        var err = exports.internal(message, data, 500);
        err.isDeveloperError = true;
        return err;
    };
    
    
  provide("boom/lib", module.exports);
}(global));

// pakmanager:boom
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  module.exports =  require('boom/lib');
  provide("boom", module.exports);
}(global));

// pakmanager:readable-stream/lib/_stream_readable
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright Joyent, Inc. and other Node contributors.
    //
    // Permission is hereby granted, free of charge, to any person obtaining a
    // copy of this software and associated documentation files (the
    // "Software"), to deal in the Software without restriction, including
    // without limitation the rights to use, copy, modify, merge, publish,
    // distribute, sublicense, and/or sell copies of the Software, and to permit
    // persons to whom the Software is furnished to do so, subject to the
    // following conditions:
    //
    // The above copyright notice and this permission notice shall be included
    // in all copies or substantial portions of the Software.
    //
    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
    // NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    // DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    // OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
    // USE OR OTHER DEALINGS IN THE SOFTWARE.
    
    module.exports = Readable;
    
    /*<replacement>*/
    var isArray = require('isarray');
    /*</replacement>*/
    
    
    /*<replacement>*/
    var Buffer = require('buffer').Buffer;
    /*</replacement>*/
    
    Readable.ReadableState = ReadableState;
    
    var EE = require('events').EventEmitter;
    
    /*<replacement>*/
    if (!EE.listenerCount) EE.listenerCount = function(emitter, type) {
      return emitter.listeners(type).length;
    };
    /*</replacement>*/
    
    var Stream = require('stream');
    
    /*<replacement>*/
    var util = require('core-util-is');
    util.inherits = require('inherits');
    /*</replacement>*/
    
    var StringDecoder;
    
    util.inherits(Readable, Stream);
    
    function ReadableState(options, stream) {
      options = options || {};
    
      // the point at which it stops calling _read() to fill the buffer
      // Note: 0 is a valid value, means "don't call _read preemptively ever"
      var hwm = options.highWaterMark;
      this.highWaterMark = (hwm || hwm === 0) ? hwm : 16 * 1024;
    
      // cast to ints.
      this.highWaterMark = ~~this.highWaterMark;
    
      this.buffer = [];
      this.length = 0;
      this.pipes = null;
      this.pipesCount = 0;
      this.flowing = false;
      this.ended = false;
      this.endEmitted = false;
      this.reading = false;
    
      // In streams that never have any data, and do push(null) right away,
      // the consumer can miss the 'end' event if they do some I/O before
      // consuming the stream.  So, we don't emit('end') until some reading
      // happens.
      this.calledRead = false;
    
      // a flag to be able to tell if the onwrite cb is called immediately,
      // or on a later tick.  We set this to true at first, becuase any
      // actions that shouldn't happen until "later" should generally also
      // not happen before the first write call.
      this.sync = true;
    
      // whenever we return null, then we set a flag to say
      // that we're awaiting a 'readable' event emission.
      this.needReadable = false;
      this.emittedReadable = false;
      this.readableListening = false;
    
    
      // object stream flag. Used to make read(n) ignore n and to
      // make all the buffer merging and length checks go away
      this.objectMode = !!options.objectMode;
    
      // Crypto is kind of old and crusty.  Historically, its default string
      // encoding is 'binary' so we have to make this configurable.
      // Everything else in the universe uses 'utf8', though.
      this.defaultEncoding = options.defaultEncoding || 'utf8';
    
      // when piping, we only care about 'readable' events that happen
      // after read()ing all the bytes and not getting any pushback.
      this.ranOut = false;
    
      // the number of writers that are awaiting a drain event in .pipe()s
      this.awaitDrain = 0;
    
      // if true, a maybeReadMore has been scheduled
      this.readingMore = false;
    
      this.decoder = null;
      this.encoding = null;
      if (options.encoding) {
        if (!StringDecoder)
          StringDecoder = require('string_decoder/').StringDecoder;
        this.decoder = new StringDecoder(options.encoding);
        this.encoding = options.encoding;
      }
    }
    
    function Readable(options) {
      if (!(this instanceof Readable))
        return new Readable(options);
    
      this._readableState = new ReadableState(options, this);
    
      // legacy
      this.readable = true;
    
      Stream.call(this);
    }
    
    // Manually shove something into the read() buffer.
    // This returns true if the highWaterMark has not been hit yet,
    // similar to how Writable.write() returns true if you should
    // write() some more.
    Readable.prototype.push = function(chunk, encoding) {
      var state = this._readableState;
    
      if (typeof chunk === 'string' && !state.objectMode) {
        encoding = encoding || state.defaultEncoding;
        if (encoding !== state.encoding) {
          chunk = new Buffer(chunk, encoding);
          encoding = '';
        }
      }
    
      return readableAddChunk(this, state, chunk, encoding, false);
    };
    
    // Unshift should *always* be something directly out of read()
    Readable.prototype.unshift = function(chunk) {
      var state = this._readableState;
      return readableAddChunk(this, state, chunk, '', true);
    };
    
    function readableAddChunk(stream, state, chunk, encoding, addToFront) {
      var er = chunkInvalid(state, chunk);
      if (er) {
        stream.emit('error', er);
      } else if (chunk === null || chunk === undefined) {
        state.reading = false;
        if (!state.ended)
          onEofChunk(stream, state);
      } else if (state.objectMode || chunk && chunk.length > 0) {
        if (state.ended && !addToFront) {
          var e = new Error('stream.push() after EOF');
          stream.emit('error', e);
        } else if (state.endEmitted && addToFront) {
          var e = new Error('stream.unshift() after end event');
          stream.emit('error', e);
        } else {
          if (state.decoder && !addToFront && !encoding)
            chunk = state.decoder.write(chunk);
    
          // update the buffer info.
          state.length += state.objectMode ? 1 : chunk.length;
          if (addToFront) {
            state.buffer.unshift(chunk);
          } else {
            state.reading = false;
            state.buffer.push(chunk);
          }
    
          if (state.needReadable)
            emitReadable(stream);
    
          maybeReadMore(stream, state);
        }
      } else if (!addToFront) {
        state.reading = false;
      }
    
      return needMoreData(state);
    }
    
    
    
    // if it's past the high water mark, we can push in some more.
    // Also, if we have no data yet, we can stand some
    // more bytes.  This is to work around cases where hwm=0,
    // such as the repl.  Also, if the push() triggered a
    // readable event, and the user called read(largeNumber) such that
    // needReadable was set, then we ought to push more, so that another
    // 'readable' event will be triggered.
    function needMoreData(state) {
      return !state.ended &&
             (state.needReadable ||
              state.length < state.highWaterMark ||
              state.length === 0);
    }
    
    // backwards compatibility.
    Readable.prototype.setEncoding = function(enc) {
      if (!StringDecoder)
        StringDecoder = require('string_decoder/').StringDecoder;
      this._readableState.decoder = new StringDecoder(enc);
      this._readableState.encoding = enc;
    };
    
    // Don't raise the hwm > 128MB
    var MAX_HWM = 0x800000;
    function roundUpToNextPowerOf2(n) {
      if (n >= MAX_HWM) {
        n = MAX_HWM;
      } else {
        // Get the next highest power of 2
        n--;
        for (var p = 1; p < 32; p <<= 1) n |= n >> p;
        n++;
      }
      return n;
    }
    
    function howMuchToRead(n, state) {
      if (state.length === 0 && state.ended)
        return 0;
    
      if (state.objectMode)
        return n === 0 ? 0 : 1;
    
      if (n === null || isNaN(n)) {
        // only flow one buffer at a time
        if (state.flowing && state.buffer.length)
          return state.buffer[0].length;
        else
          return state.length;
      }
    
      if (n <= 0)
        return 0;
    
      // If we're asking for more than the target buffer level,
      // then raise the water mark.  Bump up to the next highest
      // power of 2, to prevent increasing it excessively in tiny
      // amounts.
      if (n > state.highWaterMark)
        state.highWaterMark = roundUpToNextPowerOf2(n);
    
      // don't have that much.  return null, unless we've ended.
      if (n > state.length) {
        if (!state.ended) {
          state.needReadable = true;
          return 0;
        } else
          return state.length;
      }
    
      return n;
    }
    
    // you can override either this method, or the async _read(n) below.
    Readable.prototype.read = function(n) {
      var state = this._readableState;
      state.calledRead = true;
      var nOrig = n;
      var ret;
    
      if (typeof n !== 'number' || n > 0)
        state.emittedReadable = false;
    
      // if we're doing read(0) to trigger a readable event, but we
      // already have a bunch of data in the buffer, then just trigger
      // the 'readable' event and move on.
      if (n === 0 &&
          state.needReadable &&
          (state.length >= state.highWaterMark || state.ended)) {
        emitReadable(this);
        return null;
      }
    
      n = howMuchToRead(n, state);
    
      // if we've ended, and we're now clear, then finish it up.
      if (n === 0 && state.ended) {
        ret = null;
    
        // In cases where the decoder did not receive enough data
        // to produce a full chunk, then immediately received an
        // EOF, state.buffer will contain [<Buffer >, <Buffer 00 ...>].
        // howMuchToRead will see this and coerce the amount to
        // read to zero (because it's looking at the length of the
        // first <Buffer > in state.buffer), and we'll end up here.
        //
        // This can only happen via state.decoder -- no other venue
        // exists for pushing a zero-length chunk into state.buffer
        // and triggering this behavior. In this case, we return our
        // remaining data and end the stream, if appropriate.
        if (state.length > 0 && state.decoder) {
          ret = fromList(n, state);
          state.length -= ret.length;
        }
    
        if (state.length === 0)
          endReadable(this);
    
        return ret;
      }
    
      // All the actual chunk generation logic needs to be
      // *below* the call to _read.  The reason is that in certain
      // synthetic stream cases, such as passthrough streams, _read
      // may be a completely synchronous operation which may change
      // the state of the read buffer, providing enough data when
      // before there was *not* enough.
      //
      // So, the steps are:
      // 1. Figure out what the state of things will be after we do
      // a read from the buffer.
      //
      // 2. If that resulting state will trigger a _read, then call _read.
      // Note that this may be asynchronous, or synchronous.  Yes, it is
      // deeply ugly to write APIs this way, but that still doesn't mean
      // that the Readable class should behave improperly, as streams are
      // designed to be sync/async agnostic.
      // Take note if the _read call is sync or async (ie, if the read call
      // has returned yet), so that we know whether or not it's safe to emit
      // 'readable' etc.
      //
      // 3. Actually pull the requested chunks out of the buffer and return.
    
      // if we need a readable event, then we need to do some reading.
      var doRead = state.needReadable;
    
      // if we currently have less than the highWaterMark, then also read some
      if (state.length - n <= state.highWaterMark)
        doRead = true;
    
      // however, if we've ended, then there's no point, and if we're already
      // reading, then it's unnecessary.
      if (state.ended || state.reading)
        doRead = false;
    
      if (doRead) {
        state.reading = true;
        state.sync = true;
        // if the length is currently zero, then we *need* a readable event.
        if (state.length === 0)
          state.needReadable = true;
        // call internal read method
        this._read(state.highWaterMark);
        state.sync = false;
      }
    
      // If _read called its callback synchronously, then `reading`
      // will be false, and we need to re-evaluate how much data we
      // can return to the user.
      if (doRead && !state.reading)
        n = howMuchToRead(nOrig, state);
    
      if (n > 0)
        ret = fromList(n, state);
      else
        ret = null;
    
      if (ret === null) {
        state.needReadable = true;
        n = 0;
      }
    
      state.length -= n;
    
      // If we have nothing in the buffer, then we want to know
      // as soon as we *do* get something into the buffer.
      if (state.length === 0 && !state.ended)
        state.needReadable = true;
    
      // If we happened to read() exactly the remaining amount in the
      // buffer, and the EOF has been seen at this point, then make sure
      // that we emit 'end' on the very next tick.
      if (state.ended && !state.endEmitted && state.length === 0)
        endReadable(this);
    
      return ret;
    };
    
    function chunkInvalid(state, chunk) {
      var er = null;
      if (!Buffer.isBuffer(chunk) &&
          'string' !== typeof chunk &&
          chunk !== null &&
          chunk !== undefined &&
          !state.objectMode) {
        er = new TypeError('Invalid non-string/buffer chunk');
      }
      return er;
    }
    
    
    function onEofChunk(stream, state) {
      if (state.decoder && !state.ended) {
        var chunk = state.decoder.end();
        if (chunk && chunk.length) {
          state.buffer.push(chunk);
          state.length += state.objectMode ? 1 : chunk.length;
        }
      }
      state.ended = true;
    
      // if we've ended and we have some data left, then emit
      // 'readable' now to make sure it gets picked up.
      if (state.length > 0)
        emitReadable(stream);
      else
        endReadable(stream);
    }
    
    // Don't emit readable right away in sync mode, because this can trigger
    // another read() call => stack overflow.  This way, it might trigger
    // a nextTick recursion warning, but that's not so bad.
    function emitReadable(stream) {
      var state = stream._readableState;
      state.needReadable = false;
      if (state.emittedReadable)
        return;
    
      state.emittedReadable = true;
      if (state.sync)
        process.nextTick(function() {
          emitReadable_(stream);
        });
      else
        emitReadable_(stream);
    }
    
    function emitReadable_(stream) {
      stream.emit('readable');
    }
    
    
    // at this point, the user has presumably seen the 'readable' event,
    // and called read() to consume some data.  that may have triggered
    // in turn another _read(n) call, in which case reading = true if
    // it's in progress.
    // However, if we're not ended, or reading, and the length < hwm,
    // then go ahead and try to read some more preemptively.
    function maybeReadMore(stream, state) {
      if (!state.readingMore) {
        state.readingMore = true;
        process.nextTick(function() {
          maybeReadMore_(stream, state);
        });
      }
    }
    
    function maybeReadMore_(stream, state) {
      var len = state.length;
      while (!state.reading && !state.flowing && !state.ended &&
             state.length < state.highWaterMark) {
        stream.read(0);
        if (len === state.length)
          // didn't get any data, stop spinning.
          break;
        else
          len = state.length;
      }
      state.readingMore = false;
    }
    
    // abstract method.  to be overridden in specific implementation classes.
    // call cb(er, data) where data is <= n in length.
    // for virtual (non-string, non-buffer) streams, "length" is somewhat
    // arbitrary, and perhaps not very meaningful.
    Readable.prototype._read = function(n) {
      this.emit('error', new Error('not implemented'));
    };
    
    Readable.prototype.pipe = function(dest, pipeOpts) {
      var src = this;
      var state = this._readableState;
    
      switch (state.pipesCount) {
        case 0:
          state.pipes = dest;
          break;
        case 1:
          state.pipes = [state.pipes, dest];
          break;
        default:
          state.pipes.push(dest);
          break;
      }
      state.pipesCount += 1;
    
      var doEnd = (!pipeOpts || pipeOpts.end !== false) &&
                  dest !== process.stdout &&
                  dest !== process.stderr;
    
      var endFn = doEnd ? onend : cleanup;
      if (state.endEmitted)
        process.nextTick(endFn);
      else
        src.once('end', endFn);
    
      dest.on('unpipe', onunpipe);
      function onunpipe(readable) {
        if (readable !== src) return;
        cleanup();
      }
    
      function onend() {
        dest.end();
      }
    
      // when the dest drains, it reduces the awaitDrain counter
      // on the source.  This would be more elegant with a .once()
      // handler in flow(), but adding and removing repeatedly is
      // too slow.
      var ondrain = pipeOnDrain(src);
      dest.on('drain', ondrain);
    
      function cleanup() {
        // cleanup event handlers once the pipe is broken
        dest.removeListener('close', onclose);
        dest.removeListener('finish', onfinish);
        dest.removeListener('drain', ondrain);
        dest.removeListener('error', onerror);
        dest.removeListener('unpipe', onunpipe);
        src.removeListener('end', onend);
        src.removeListener('end', cleanup);
    
        // if the reader is waiting for a drain event from this
        // specific writer, then it would cause it to never start
        // flowing again.
        // So, if this is awaiting a drain, then we just call it now.
        // If we don't know, then assume that we are waiting for one.
        if (!dest._writableState || dest._writableState.needDrain)
          ondrain();
      }
    
      // if the dest has an error, then stop piping into it.
      // however, don't suppress the throwing behavior for this.
      function onerror(er) {
        unpipe();
        dest.removeListener('error', onerror);
        if (EE.listenerCount(dest, 'error') === 0)
          dest.emit('error', er);
      }
      // This is a brutally ugly hack to make sure that our error handler
      // is attached before any userland ones.  NEVER DO THIS.
      if (!dest._events || !dest._events.error)
        dest.on('error', onerror);
      else if (isArray(dest._events.error))
        dest._events.error.unshift(onerror);
      else
        dest._events.error = [onerror, dest._events.error];
    
    
    
      // Both close and finish should trigger unpipe, but only once.
      function onclose() {
        dest.removeListener('finish', onfinish);
        unpipe();
      }
      dest.once('close', onclose);
      function onfinish() {
        dest.removeListener('close', onclose);
        unpipe();
      }
      dest.once('finish', onfinish);
    
      function unpipe() {
        src.unpipe(dest);
      }
    
      // tell the dest that it's being piped to
      dest.emit('pipe', src);
    
      // start the flow if it hasn't been started already.
      if (!state.flowing) {
        // the handler that waits for readable events after all
        // the data gets sucked out in flow.
        // This would be easier to follow with a .once() handler
        // in flow(), but that is too slow.
        this.on('readable', pipeOnReadable);
    
        state.flowing = true;
        process.nextTick(function() {
          flow(src);
        });
      }
    
      return dest;
    };
    
    function pipeOnDrain(src) {
      return function() {
        var dest = this;
        var state = src._readableState;
        state.awaitDrain--;
        if (state.awaitDrain === 0)
          flow(src);
      };
    }
    
    function flow(src) {
      var state = src._readableState;
      var chunk;
      state.awaitDrain = 0;
    
      function write(dest, i, list) {
        var written = dest.write(chunk);
        if (false === written) {
          state.awaitDrain++;
        }
      }
    
      while (state.pipesCount && null !== (chunk = src.read())) {
    
        if (state.pipesCount === 1)
          write(state.pipes, 0, null);
        else
          forEach(state.pipes, write);
    
        src.emit('data', chunk);
    
        // if anyone needs a drain, then we have to wait for that.
        if (state.awaitDrain > 0)
          return;
      }
    
      // if every destination was unpiped, either before entering this
      // function, or in the while loop, then stop flowing.
      //
      // NB: This is a pretty rare edge case.
      if (state.pipesCount === 0) {
        state.flowing = false;
    
        // if there were data event listeners added, then switch to old mode.
        if (EE.listenerCount(src, 'data') > 0)
          emitDataEvents(src);
        return;
      }
    
      // at this point, no one needed a drain, so we just ran out of data
      // on the next readable event, start it over again.
      state.ranOut = true;
    }
    
    function pipeOnReadable() {
      if (this._readableState.ranOut) {
        this._readableState.ranOut = false;
        flow(this);
      }
    }
    
    
    Readable.prototype.unpipe = function(dest) {
      var state = this._readableState;
    
      // if we're not piping anywhere, then do nothing.
      if (state.pipesCount === 0)
        return this;
    
      // just one destination.  most common case.
      if (state.pipesCount === 1) {
        // passed in one, but it's not the right one.
        if (dest && dest !== state.pipes)
          return this;
    
        if (!dest)
          dest = state.pipes;
    
        // got a match.
        state.pipes = null;
        state.pipesCount = 0;
        this.removeListener('readable', pipeOnReadable);
        state.flowing = false;
        if (dest)
          dest.emit('unpipe', this);
        return this;
      }
    
      // slow case. multiple pipe destinations.
    
      if (!dest) {
        // remove all.
        var dests = state.pipes;
        var len = state.pipesCount;
        state.pipes = null;
        state.pipesCount = 0;
        this.removeListener('readable', pipeOnReadable);
        state.flowing = false;
    
        for (var i = 0; i < len; i++)
          dests[i].emit('unpipe', this);
        return this;
      }
    
      // try to find the right one.
      var i = indexOf(state.pipes, dest);
      if (i === -1)
        return this;
    
      state.pipes.splice(i, 1);
      state.pipesCount -= 1;
      if (state.pipesCount === 1)
        state.pipes = state.pipes[0];
    
      dest.emit('unpipe', this);
    
      return this;
    };
    
    // set up data events if they are asked for
    // Ensure readable listeners eventually get something
    Readable.prototype.on = function(ev, fn) {
      var res = Stream.prototype.on.call(this, ev, fn);
    
      if (ev === 'data' && !this._readableState.flowing)
        emitDataEvents(this);
    
      if (ev === 'readable' && this.readable) {
        var state = this._readableState;
        if (!state.readableListening) {
          state.readableListening = true;
          state.emittedReadable = false;
          state.needReadable = true;
          if (!state.reading) {
            this.read(0);
          } else if (state.length) {
            emitReadable(this, state);
          }
        }
      }
    
      return res;
    };
    Readable.prototype.addListener = Readable.prototype.on;
    
    // pause() and resume() are remnants of the legacy readable stream API
    // If the user uses them, then switch into old mode.
    Readable.prototype.resume = function() {
      emitDataEvents(this);
      this.read(0);
      this.emit('resume');
    };
    
    Readable.prototype.pause = function() {
      emitDataEvents(this, true);
      this.emit('pause');
    };
    
    function emitDataEvents(stream, startPaused) {
      var state = stream._readableState;
    
      if (state.flowing) {
        // https://github.com/isaacs/readable-stream/issues/16
        throw new Error('Cannot switch to old mode now.');
      }
    
      var paused = startPaused || false;
      var readable = false;
    
      // convert to an old-style stream.
      stream.readable = true;
      stream.pipe = Stream.prototype.pipe;
      stream.on = stream.addListener = Stream.prototype.on;
    
      stream.on('readable', function() {
        readable = true;
    
        var c;
        while (!paused && (null !== (c = stream.read())))
          stream.emit('data', c);
    
        if (c === null) {
          readable = false;
          stream._readableState.needReadable = true;
        }
      });
    
      stream.pause = function() {
        paused = true;
        this.emit('pause');
      };
    
      stream.resume = function() {
        paused = false;
        if (readable)
          process.nextTick(function() {
            stream.emit('readable');
          });
        else
          this.read(0);
        this.emit('resume');
      };
    
      // now make it start, just in case it hadn't already.
      stream.emit('readable');
    }
    
    // wrap an old-style stream as the async data source.
    // This is *not* part of the readable stream interface.
    // It is an ugly unfortunate mess of history.
    Readable.prototype.wrap = function(stream) {
      var state = this._readableState;
      var paused = false;
    
      var self = this;
      stream.on('end', function() {
        if (state.decoder && !state.ended) {
          var chunk = state.decoder.end();
          if (chunk && chunk.length)
            self.push(chunk);
        }
    
        self.push(null);
      });
    
      stream.on('data', function(chunk) {
        if (state.decoder)
          chunk = state.decoder.write(chunk);
    
        // don't skip over falsy values in objectMode
        //if (state.objectMode && util.isNullOrUndefined(chunk))
        if (state.objectMode && (chunk === null || chunk === undefined))
          return;
        else if (!state.objectMode && (!chunk || !chunk.length))
          return;
    
        var ret = self.push(chunk);
        if (!ret) {
          paused = true;
          stream.pause();
        }
      });
    
      // proxy all the other methods.
      // important when wrapping filters and duplexes.
      for (var i in stream) {
        if (typeof stream[i] === 'function' &&
            typeof this[i] === 'undefined') {
          this[i] = function(method) { return function() {
            return stream[method].apply(stream, arguments);
          }}(i);
        }
      }
    
      // proxy certain important events.
      var events = ['error', 'close', 'destroy', 'pause', 'resume'];
      forEach(events, function(ev) {
        stream.on(ev, self.emit.bind(self, ev));
      });
    
      // when we try to consume some more bytes, simply unpause the
      // underlying stream.
      self._read = function(n) {
        if (paused) {
          paused = false;
          stream.resume();
        }
      };
    
      return self;
    };
    
    
    
    // exposed for testing purposes only.
    Readable._fromList = fromList;
    
    // Pluck off n bytes from an array of buffers.
    // Length is the combined lengths of all the buffers in the list.
    function fromList(n, state) {
      var list = state.buffer;
      var length = state.length;
      var stringMode = !!state.decoder;
      var objectMode = !!state.objectMode;
      var ret;
    
      // nothing in the list, definitely empty.
      if (list.length === 0)
        return null;
    
      if (length === 0)
        ret = null;
      else if (objectMode)
        ret = list.shift();
      else if (!n || n >= length) {
        // read it all, truncate the array.
        if (stringMode)
          ret = list.join('');
        else
          ret = Buffer.concat(list, length);
        list.length = 0;
      } else {
        // read just some of it.
        if (n < list[0].length) {
          // just take a part of the first list item.
          // slice is the same for buffers and strings.
          var buf = list[0];
          ret = buf.slice(0, n);
          list[0] = buf.slice(n);
        } else if (n === list[0].length) {
          // first list is a perfect match
          ret = list.shift();
        } else {
          // complex case.
          // we have enough to cover it, but it spans past the first buffer.
          if (stringMode)
            ret = '';
          else
            ret = new Buffer(n);
    
          var c = 0;
          for (var i = 0, l = list.length; i < l && c < n; i++) {
            var buf = list[0];
            var cpy = Math.min(n - c, buf.length);
    
            if (stringMode)
              ret += buf.slice(0, cpy);
            else
              buf.copy(ret, c, 0, cpy);
    
            if (cpy < buf.length)
              list[0] = buf.slice(cpy);
            else
              list.shift();
    
            c += cpy;
          }
        }
      }
    
      return ret;
    }
    
    function endReadable(stream) {
      var state = stream._readableState;
    
      // If we get here before consuming all the bytes, then that is a
      // bug in node.  Should never happen.
      if (state.length > 0)
        throw new Error('endReadable called on non-empty stream');
    
      if (!state.endEmitted && state.calledRead) {
        state.ended = true;
        process.nextTick(function() {
          // Check that we didn't get one last unshift.
          if (!state.endEmitted && state.length === 0) {
            state.endEmitted = true;
            stream.readable = false;
            stream.emit('end');
          }
        });
      }
    }
    
    function forEach (xs, f) {
      for (var i = 0, l = xs.length; i < l; i++) {
        f(xs[i], i);
      }
    }
    
    function indexOf (xs, x) {
      for (var i = 0, l = xs.length; i < l; i++) {
        if (xs[i] === x) return i;
      }
      return -1;
    }
    
  provide("readable-stream/lib/_stream_readable", module.exports);
}(global));

// pakmanager:readable-stream/lib/_stream_writable
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright Joyent, Inc. and other Node contributors.
    //
    // Permission is hereby granted, free of charge, to any person obtaining a
    // copy of this software and associated documentation files (the
    // "Software"), to deal in the Software without restriction, including
    // without limitation the rights to use, copy, modify, merge, publish,
    // distribute, sublicense, and/or sell copies of the Software, and to permit
    // persons to whom the Software is furnished to do so, subject to the
    // following conditions:
    //
    // The above copyright notice and this permission notice shall be included
    // in all copies or substantial portions of the Software.
    //
    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
    // NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    // DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    // OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
    // USE OR OTHER DEALINGS IN THE SOFTWARE.
    
    // A bit simpler than readable streams.
    // Implement an async ._write(chunk, cb), and it'll handle all
    // the drain event emission and buffering.
    
    module.exports = Writable;
    
    /*<replacement>*/
    var Buffer = require('buffer').Buffer;
    /*</replacement>*/
    
    Writable.WritableState = WritableState;
    
    
    /*<replacement>*/
    var util = require('core-util-is');
    util.inherits = require('inherits');
    /*</replacement>*/
    
    var Stream = require('stream');
    
    util.inherits(Writable, Stream);
    
    function WriteReq(chunk, encoding, cb) {
      this.chunk = chunk;
      this.encoding = encoding;
      this.callback = cb;
    }
    
    function WritableState(options, stream) {
      options = options || {};
    
      // the point at which write() starts returning false
      // Note: 0 is a valid value, means that we always return false if
      // the entire buffer is not flushed immediately on write()
      var hwm = options.highWaterMark;
      this.highWaterMark = (hwm || hwm === 0) ? hwm : 16 * 1024;
    
      // object stream flag to indicate whether or not this stream
      // contains buffers or objects.
      this.objectMode = !!options.objectMode;
    
      // cast to ints.
      this.highWaterMark = ~~this.highWaterMark;
    
      this.needDrain = false;
      // at the start of calling end()
      this.ending = false;
      // when end() has been called, and returned
      this.ended = false;
      // when 'finish' is emitted
      this.finished = false;
    
      // should we decode strings into buffers before passing to _write?
      // this is here so that some node-core streams can optimize string
      // handling at a lower level.
      var noDecode = options.decodeStrings === false;
      this.decodeStrings = !noDecode;
    
      // Crypto is kind of old and crusty.  Historically, its default string
      // encoding is 'binary' so we have to make this configurable.
      // Everything else in the universe uses 'utf8', though.
      this.defaultEncoding = options.defaultEncoding || 'utf8';
    
      // not an actual buffer we keep track of, but a measurement
      // of how much we're waiting to get pushed to some underlying
      // socket or file.
      this.length = 0;
    
      // a flag to see when we're in the middle of a write.
      this.writing = false;
    
      // a flag to be able to tell if the onwrite cb is called immediately,
      // or on a later tick.  We set this to true at first, becuase any
      // actions that shouldn't happen until "later" should generally also
      // not happen before the first write call.
      this.sync = true;
    
      // a flag to know if we're processing previously buffered items, which
      // may call the _write() callback in the same tick, so that we don't
      // end up in an overlapped onwrite situation.
      this.bufferProcessing = false;
    
      // the callback that's passed to _write(chunk,cb)
      this.onwrite = function(er) {
        onwrite(stream, er);
      };
    
      // the callback that the user supplies to write(chunk,encoding,cb)
      this.writecb = null;
    
      // the amount that is being written when _write is called.
      this.writelen = 0;
    
      this.buffer = [];
    
      // True if the error was already emitted and should not be thrown again
      this.errorEmitted = false;
    }
    
    function Writable(options) {
      var Duplex =  require('readable-stream/lib/_stream_duplex');
    
      // Writable ctor is applied to Duplexes, though they're not
      // instanceof Writable, they're instanceof Readable.
      if (!(this instanceof Writable) && !(this instanceof Duplex))
        return new Writable(options);
    
      this._writableState = new WritableState(options, this);
    
      // legacy.
      this.writable = true;
    
      Stream.call(this);
    }
    
    // Otherwise people can pipe Writable streams, which is just wrong.
    Writable.prototype.pipe = function() {
      this.emit('error', new Error('Cannot pipe. Not readable.'));
    };
    
    
    function writeAfterEnd(stream, state, cb) {
      var er = new Error('write after end');
      // TODO: defer error events consistently everywhere, not just the cb
      stream.emit('error', er);
      process.nextTick(function() {
        cb(er);
      });
    }
    
    // If we get something that is not a buffer, string, null, or undefined,
    // and we're not in objectMode, then that's an error.
    // Otherwise stream chunks are all considered to be of length=1, and the
    // watermarks determine how many objects to keep in the buffer, rather than
    // how many bytes or characters.
    function validChunk(stream, state, chunk, cb) {
      var valid = true;
      if (!Buffer.isBuffer(chunk) &&
          'string' !== typeof chunk &&
          chunk !== null &&
          chunk !== undefined &&
          !state.objectMode) {
        var er = new TypeError('Invalid non-string/buffer chunk');
        stream.emit('error', er);
        process.nextTick(function() {
          cb(er);
        });
        valid = false;
      }
      return valid;
    }
    
    Writable.prototype.write = function(chunk, encoding, cb) {
      var state = this._writableState;
      var ret = false;
    
      if (typeof encoding === 'function') {
        cb = encoding;
        encoding = null;
      }
    
      if (Buffer.isBuffer(chunk))
        encoding = 'buffer';
      else if (!encoding)
        encoding = state.defaultEncoding;
    
      if (typeof cb !== 'function')
        cb = function() {};
    
      if (state.ended)
        writeAfterEnd(this, state, cb);
      else if (validChunk(this, state, chunk, cb))
        ret = writeOrBuffer(this, state, chunk, encoding, cb);
    
      return ret;
    };
    
    function decodeChunk(state, chunk, encoding) {
      if (!state.objectMode &&
          state.decodeStrings !== false &&
          typeof chunk === 'string') {
        chunk = new Buffer(chunk, encoding);
      }
      return chunk;
    }
    
    // if we're already writing something, then just put this
    // in the queue, and wait our turn.  Otherwise, call _write
    // If we return false, then we need a drain event, so set that flag.
    function writeOrBuffer(stream, state, chunk, encoding, cb) {
      chunk = decodeChunk(state, chunk, encoding);
      if (Buffer.isBuffer(chunk))
        encoding = 'buffer';
      var len = state.objectMode ? 1 : chunk.length;
    
      state.length += len;
    
      var ret = state.length < state.highWaterMark;
      // we must ensure that previous needDrain will not be reset to false.
      if (!ret)
        state.needDrain = true;
    
      if (state.writing)
        state.buffer.push(new WriteReq(chunk, encoding, cb));
      else
        doWrite(stream, state, len, chunk, encoding, cb);
    
      return ret;
    }
    
    function doWrite(stream, state, len, chunk, encoding, cb) {
      state.writelen = len;
      state.writecb = cb;
      state.writing = true;
      state.sync = true;
      stream._write(chunk, encoding, state.onwrite);
      state.sync = false;
    }
    
    function onwriteError(stream, state, sync, er, cb) {
      if (sync)
        process.nextTick(function() {
          cb(er);
        });
      else
        cb(er);
    
      stream._writableState.errorEmitted = true;
      stream.emit('error', er);
    }
    
    function onwriteStateUpdate(state) {
      state.writing = false;
      state.writecb = null;
      state.length -= state.writelen;
      state.writelen = 0;
    }
    
    function onwrite(stream, er) {
      var state = stream._writableState;
      var sync = state.sync;
      var cb = state.writecb;
    
      onwriteStateUpdate(state);
    
      if (er)
        onwriteError(stream, state, sync, er, cb);
      else {
        // Check if we're actually ready to finish, but don't emit yet
        var finished = needFinish(stream, state);
    
        if (!finished && !state.bufferProcessing && state.buffer.length)
          clearBuffer(stream, state);
    
        if (sync) {
          process.nextTick(function() {
            afterWrite(stream, state, finished, cb);
          });
        } else {
          afterWrite(stream, state, finished, cb);
        }
      }
    }
    
    function afterWrite(stream, state, finished, cb) {
      if (!finished)
        onwriteDrain(stream, state);
      cb();
      if (finished)
        finishMaybe(stream, state);
    }
    
    // Must force callback to be called on nextTick, so that we don't
    // emit 'drain' before the write() consumer gets the 'false' return
    // value, and has a chance to attach a 'drain' listener.
    function onwriteDrain(stream, state) {
      if (state.length === 0 && state.needDrain) {
        state.needDrain = false;
        stream.emit('drain');
      }
    }
    
    
    // if there's something in the buffer waiting, then process it
    function clearBuffer(stream, state) {
      state.bufferProcessing = true;
    
      for (var c = 0; c < state.buffer.length; c++) {
        var entry = state.buffer[c];
        var chunk = entry.chunk;
        var encoding = entry.encoding;
        var cb = entry.callback;
        var len = state.objectMode ? 1 : chunk.length;
    
        doWrite(stream, state, len, chunk, encoding, cb);
    
        // if we didn't call the onwrite immediately, then
        // it means that we need to wait until it does.
        // also, that means that the chunk and cb are currently
        // being processed, so move the buffer counter past them.
        if (state.writing) {
          c++;
          break;
        }
      }
    
      state.bufferProcessing = false;
      if (c < state.buffer.length)
        state.buffer = state.buffer.slice(c);
      else
        state.buffer.length = 0;
    }
    
    Writable.prototype._write = function(chunk, encoding, cb) {
      cb(new Error('not implemented'));
    };
    
    Writable.prototype.end = function(chunk, encoding, cb) {
      var state = this._writableState;
    
      if (typeof chunk === 'function') {
        cb = chunk;
        chunk = null;
        encoding = null;
      } else if (typeof encoding === 'function') {
        cb = encoding;
        encoding = null;
      }
    
      if (typeof chunk !== 'undefined' && chunk !== null)
        this.write(chunk, encoding);
    
      // ignore unnecessary end() calls.
      if (!state.ending && !state.finished)
        endWritable(this, state, cb);
    };
    
    
    function needFinish(stream, state) {
      return (state.ending &&
              state.length === 0 &&
              !state.finished &&
              !state.writing);
    }
    
    function finishMaybe(stream, state) {
      var need = needFinish(stream, state);
      if (need) {
        state.finished = true;
        stream.emit('finish');
      }
      return need;
    }
    
    function endWritable(stream, state, cb) {
      state.ending = true;
      finishMaybe(stream, state);
      if (cb) {
        if (state.finished)
          process.nextTick(cb);
        else
          stream.once('finish', cb);
      }
      state.ended = true;
    }
    
  provide("readable-stream/lib/_stream_writable", module.exports);
}(global));

// pakmanager:readable-stream/lib/_stream_duplex
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright Joyent, Inc. and other Node contributors.
    //
    // Permission is hereby granted, free of charge, to any person obtaining a
    // copy of this software and associated documentation files (the
    // "Software"), to deal in the Software without restriction, including
    // without limitation the rights to use, copy, modify, merge, publish,
    // distribute, sublicense, and/or sell copies of the Software, and to permit
    // persons to whom the Software is furnished to do so, subject to the
    // following conditions:
    //
    // The above copyright notice and this permission notice shall be included
    // in all copies or substantial portions of the Software.
    //
    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
    // NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    // DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    // OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
    // USE OR OTHER DEALINGS IN THE SOFTWARE.
    
    // a duplex stream is just a stream that is both readable and writable.
    // Since JS doesn't have multiple prototypal inheritance, this class
    // prototypally inherits from Readable, and then parasitically from
    // Writable.
    
    module.exports = Duplex;
    
    /*<replacement>*/
    var objectKeys = Object.keys || function (obj) {
      var keys = [];
      for (var key in obj) keys.push(key);
      return keys;
    }
    /*</replacement>*/
    
    
    /*<replacement>*/
    var util = require('core-util-is');
    util.inherits = require('inherits');
    /*</replacement>*/
    
    var Readable =  require('readable-stream/lib/_stream_readable');
    var Writable =  require('readable-stream/lib/_stream_writable');
    
    util.inherits(Duplex, Readable);
    
    forEach(objectKeys(Writable.prototype), function(method) {
      if (!Duplex.prototype[method])
        Duplex.prototype[method] = Writable.prototype[method];
    });
    
    function Duplex(options) {
      if (!(this instanceof Duplex))
        return new Duplex(options);
    
      Readable.call(this, options);
      Writable.call(this, options);
    
      if (options && options.readable === false)
        this.readable = false;
    
      if (options && options.writable === false)
        this.writable = false;
    
      this.allowHalfOpen = true;
      if (options && options.allowHalfOpen === false)
        this.allowHalfOpen = false;
    
      this.once('end', onend);
    }
    
    // the no-half-open enforcer
    function onend() {
      // if we allow half-open state, or if the writable side ended,
      // then we're ok.
      if (this.allowHalfOpen || this._writableState.ended)
        return;
    
      // no more data can be written.
      // But allow more writes to happen in this tick.
      process.nextTick(this.end.bind(this));
    }
    
    function forEach (xs, f) {
      for (var i = 0, l = xs.length; i < l; i++) {
        f(xs[i], i);
      }
    }
    
  provide("readable-stream/lib/_stream_duplex", module.exports);
}(global));

// pakmanager:readable-stream/lib/_stream_transform
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright Joyent, Inc. and other Node contributors.
    //
    // Permission is hereby granted, free of charge, to any person obtaining a
    // copy of this software and associated documentation files (the
    // "Software"), to deal in the Software without restriction, including
    // without limitation the rights to use, copy, modify, merge, publish,
    // distribute, sublicense, and/or sell copies of the Software, and to permit
    // persons to whom the Software is furnished to do so, subject to the
    // following conditions:
    //
    // The above copyright notice and this permission notice shall be included
    // in all copies or substantial portions of the Software.
    //
    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
    // NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    // DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    // OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
    // USE OR OTHER DEALINGS IN THE SOFTWARE.
    
    
    // a transform stream is a readable/writable stream where you do
    // something with the data.  Sometimes it's called a "filter",
    // but that's not a great name for it, since that implies a thing where
    // some bits pass through, and others are simply ignored.  (That would
    // be a valid example of a transform, of course.)
    //
    // While the output is causally related to the input, it's not a
    // necessarily symmetric or synchronous transformation.  For example,
    // a zlib stream might take multiple plain-text writes(), and then
    // emit a single compressed chunk some time in the future.
    //
    // Here's how this works:
    //
    // The Transform stream has all the aspects of the readable and writable
    // stream classes.  When you write(chunk), that calls _write(chunk,cb)
    // internally, and returns false if there's a lot of pending writes
    // buffered up.  When you call read(), that calls _read(n) until
    // there's enough pending readable data buffered up.
    //
    // In a transform stream, the written data is placed in a buffer.  When
    // _read(n) is called, it transforms the queued up data, calling the
    // buffered _write cb's as it consumes chunks.  If consuming a single
    // written chunk would result in multiple output chunks, then the first
    // outputted bit calls the readcb, and subsequent chunks just go into
    // the read buffer, and will cause it to emit 'readable' if necessary.
    //
    // This way, back-pressure is actually determined by the reading side,
    // since _read has to be called to start processing a new chunk.  However,
    // a pathological inflate type of transform can cause excessive buffering
    // here.  For example, imagine a stream where every byte of input is
    // interpreted as an integer from 0-255, and then results in that many
    // bytes of output.  Writing the 4 bytes {ff,ff,ff,ff} would result in
    // 1kb of data being output.  In this case, you could write a very small
    // amount of input, and end up with a very large amount of output.  In
    // such a pathological inflating mechanism, there'd be no way to tell
    // the system to stop doing the transform.  A single 4MB write could
    // cause the system to run out of memory.
    //
    // However, even in such a pathological case, only a single written chunk
    // would be consumed, and then the rest would wait (un-transformed) until
    // the results of the previous transformed chunk were consumed.
    
    module.exports = Transform;
    
    var Duplex =  require('readable-stream/lib/_stream_duplex');
    
    /*<replacement>*/
    var util = require('core-util-is');
    util.inherits = require('inherits');
    /*</replacement>*/
    
    util.inherits(Transform, Duplex);
    
    
    function TransformState(options, stream) {
      this.afterTransform = function(er, data) {
        return afterTransform(stream, er, data);
      };
    
      this.needTransform = false;
      this.transforming = false;
      this.writecb = null;
      this.writechunk = null;
    }
    
    function afterTransform(stream, er, data) {
      var ts = stream._transformState;
      ts.transforming = false;
    
      var cb = ts.writecb;
    
      if (!cb)
        return stream.emit('error', new Error('no writecb in Transform class'));
    
      ts.writechunk = null;
      ts.writecb = null;
    
      if (data !== null && data !== undefined)
        stream.push(data);
    
      if (cb)
        cb(er);
    
      var rs = stream._readableState;
      rs.reading = false;
      if (rs.needReadable || rs.length < rs.highWaterMark) {
        stream._read(rs.highWaterMark);
      }
    }
    
    
    function Transform(options) {
      if (!(this instanceof Transform))
        return new Transform(options);
    
      Duplex.call(this, options);
    
      var ts = this._transformState = new TransformState(options, this);
    
      // when the writable side finishes, then flush out anything remaining.
      var stream = this;
    
      // start out asking for a readable event once data is transformed.
      this._readableState.needReadable = true;
    
      // we have implemented the _read method, and done the other things
      // that Readable wants before the first _read call, so unset the
      // sync guard flag.
      this._readableState.sync = false;
    
      this.once('finish', function() {
        if ('function' === typeof this._flush)
          this._flush(function(er) {
            done(stream, er);
          });
        else
          done(stream);
      });
    }
    
    Transform.prototype.push = function(chunk, encoding) {
      this._transformState.needTransform = false;
      return Duplex.prototype.push.call(this, chunk, encoding);
    };
    
    // This is the part where you do stuff!
    // override this function in implementation classes.
    // 'chunk' is an input chunk.
    //
    // Call `push(newChunk)` to pass along transformed output
    // to the readable side.  You may call 'push' zero or more times.
    //
    // Call `cb(err)` when you are done with this chunk.  If you pass
    // an error, then that'll put the hurt on the whole operation.  If you
    // never call cb(), then you'll never get another chunk.
    Transform.prototype._transform = function(chunk, encoding, cb) {
      throw new Error('not implemented');
    };
    
    Transform.prototype._write = function(chunk, encoding, cb) {
      var ts = this._transformState;
      ts.writecb = cb;
      ts.writechunk = chunk;
      ts.writeencoding = encoding;
      if (!ts.transforming) {
        var rs = this._readableState;
        if (ts.needTransform ||
            rs.needReadable ||
            rs.length < rs.highWaterMark)
          this._read(rs.highWaterMark);
      }
    };
    
    // Doesn't matter what the args are here.
    // _transform does all the work.
    // That we got here means that the readable side wants more data.
    Transform.prototype._read = function(n) {
      var ts = this._transformState;
    
      if (ts.writechunk !== null && ts.writecb && !ts.transforming) {
        ts.transforming = true;
        this._transform(ts.writechunk, ts.writeencoding, ts.afterTransform);
      } else {
        // mark that we need a transform, so that any data that comes in
        // will get processed, now that we've asked for it.
        ts.needTransform = true;
      }
    };
    
    
    function done(stream, er) {
      if (er)
        return stream.emit('error', er);
    
      // if there's nothing in the write buffer, then that means
      // that nothing more will ever be provided
      var ws = stream._writableState;
      var rs = stream._readableState;
      var ts = stream._transformState;
    
      if (ws.length)
        throw new Error('calling transform done when ws.length != 0');
    
      if (ts.transforming)
        throw new Error('calling transform done when still transforming');
    
      return stream.push(null);
    }
    
  provide("readable-stream/lib/_stream_transform", module.exports);
}(global));

// pakmanager:readable-stream/lib/_stream_readable.js
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright Joyent, Inc. and other Node contributors.
    //
    // Permission is hereby granted, free of charge, to any person obtaining a
    // copy of this software and associated documentation files (the
    // "Software"), to deal in the Software without restriction, including
    // without limitation the rights to use, copy, modify, merge, publish,
    // distribute, sublicense, and/or sell copies of the Software, and to permit
    // persons to whom the Software is furnished to do so, subject to the
    // following conditions:
    //
    // The above copyright notice and this permission notice shall be included
    // in all copies or substantial portions of the Software.
    //
    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
    // NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    // DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    // OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
    // USE OR OTHER DEALINGS IN THE SOFTWARE.
    
    module.exports = Readable;
    
    /*<replacement>*/
    var isArray = require('isarray');
    /*</replacement>*/
    
    
    /*<replacement>*/
    var Buffer = require('buffer').Buffer;
    /*</replacement>*/
    
    Readable.ReadableState = ReadableState;
    
    var EE = require('events').EventEmitter;
    
    /*<replacement>*/
    if (!EE.listenerCount) EE.listenerCount = function(emitter, type) {
      return emitter.listeners(type).length;
    };
    /*</replacement>*/
    
    var Stream = require('stream');
    
    /*<replacement>*/
    var util = require('core-util-is');
    util.inherits = require('inherits');
    /*</replacement>*/
    
    var StringDecoder;
    
    util.inherits(Readable, Stream);
    
    function ReadableState(options, stream) {
      options = options || {};
    
      // the point at which it stops calling _read() to fill the buffer
      // Note: 0 is a valid value, means "don't call _read preemptively ever"
      var hwm = options.highWaterMark;
      this.highWaterMark = (hwm || hwm === 0) ? hwm : 16 * 1024;
    
      // cast to ints.
      this.highWaterMark = ~~this.highWaterMark;
    
      this.buffer = [];
      this.length = 0;
      this.pipes = null;
      this.pipesCount = 0;
      this.flowing = false;
      this.ended = false;
      this.endEmitted = false;
      this.reading = false;
    
      // In streams that never have any data, and do push(null) right away,
      // the consumer can miss the 'end' event if they do some I/O before
      // consuming the stream.  So, we don't emit('end') until some reading
      // happens.
      this.calledRead = false;
    
      // a flag to be able to tell if the onwrite cb is called immediately,
      // or on a later tick.  We set this to true at first, becuase any
      // actions that shouldn't happen until "later" should generally also
      // not happen before the first write call.
      this.sync = true;
    
      // whenever we return null, then we set a flag to say
      // that we're awaiting a 'readable' event emission.
      this.needReadable = false;
      this.emittedReadable = false;
      this.readableListening = false;
    
    
      // object stream flag. Used to make read(n) ignore n and to
      // make all the buffer merging and length checks go away
      this.objectMode = !!options.objectMode;
    
      // Crypto is kind of old and crusty.  Historically, its default string
      // encoding is 'binary' so we have to make this configurable.
      // Everything else in the universe uses 'utf8', though.
      this.defaultEncoding = options.defaultEncoding || 'utf8';
    
      // when piping, we only care about 'readable' events that happen
      // after read()ing all the bytes and not getting any pushback.
      this.ranOut = false;
    
      // the number of writers that are awaiting a drain event in .pipe()s
      this.awaitDrain = 0;
    
      // if true, a maybeReadMore has been scheduled
      this.readingMore = false;
    
      this.decoder = null;
      this.encoding = null;
      if (options.encoding) {
        if (!StringDecoder)
          StringDecoder = require('string_decoder/').StringDecoder;
        this.decoder = new StringDecoder(options.encoding);
        this.encoding = options.encoding;
      }
    }
    
    function Readable(options) {
      if (!(this instanceof Readable))
        return new Readable(options);
    
      this._readableState = new ReadableState(options, this);
    
      // legacy
      this.readable = true;
    
      Stream.call(this);
    }
    
    // Manually shove something into the read() buffer.
    // This returns true if the highWaterMark has not been hit yet,
    // similar to how Writable.write() returns true if you should
    // write() some more.
    Readable.prototype.push = function(chunk, encoding) {
      var state = this._readableState;
    
      if (typeof chunk === 'string' && !state.objectMode) {
        encoding = encoding || state.defaultEncoding;
        if (encoding !== state.encoding) {
          chunk = new Buffer(chunk, encoding);
          encoding = '';
        }
      }
    
      return readableAddChunk(this, state, chunk, encoding, false);
    };
    
    // Unshift should *always* be something directly out of read()
    Readable.prototype.unshift = function(chunk) {
      var state = this._readableState;
      return readableAddChunk(this, state, chunk, '', true);
    };
    
    function readableAddChunk(stream, state, chunk, encoding, addToFront) {
      var er = chunkInvalid(state, chunk);
      if (er) {
        stream.emit('error', er);
      } else if (chunk === null || chunk === undefined) {
        state.reading = false;
        if (!state.ended)
          onEofChunk(stream, state);
      } else if (state.objectMode || chunk && chunk.length > 0) {
        if (state.ended && !addToFront) {
          var e = new Error('stream.push() after EOF');
          stream.emit('error', e);
        } else if (state.endEmitted && addToFront) {
          var e = new Error('stream.unshift() after end event');
          stream.emit('error', e);
        } else {
          if (state.decoder && !addToFront && !encoding)
            chunk = state.decoder.write(chunk);
    
          // update the buffer info.
          state.length += state.objectMode ? 1 : chunk.length;
          if (addToFront) {
            state.buffer.unshift(chunk);
          } else {
            state.reading = false;
            state.buffer.push(chunk);
          }
    
          if (state.needReadable)
            emitReadable(stream);
    
          maybeReadMore(stream, state);
        }
      } else if (!addToFront) {
        state.reading = false;
      }
    
      return needMoreData(state);
    }
    
    
    
    // if it's past the high water mark, we can push in some more.
    // Also, if we have no data yet, we can stand some
    // more bytes.  This is to work around cases where hwm=0,
    // such as the repl.  Also, if the push() triggered a
    // readable event, and the user called read(largeNumber) such that
    // needReadable was set, then we ought to push more, so that another
    // 'readable' event will be triggered.
    function needMoreData(state) {
      return !state.ended &&
             (state.needReadable ||
              state.length < state.highWaterMark ||
              state.length === 0);
    }
    
    // backwards compatibility.
    Readable.prototype.setEncoding = function(enc) {
      if (!StringDecoder)
        StringDecoder = require('string_decoder/').StringDecoder;
      this._readableState.decoder = new StringDecoder(enc);
      this._readableState.encoding = enc;
    };
    
    // Don't raise the hwm > 128MB
    var MAX_HWM = 0x800000;
    function roundUpToNextPowerOf2(n) {
      if (n >= MAX_HWM) {
        n = MAX_HWM;
      } else {
        // Get the next highest power of 2
        n--;
        for (var p = 1; p < 32; p <<= 1) n |= n >> p;
        n++;
      }
      return n;
    }
    
    function howMuchToRead(n, state) {
      if (state.length === 0 && state.ended)
        return 0;
    
      if (state.objectMode)
        return n === 0 ? 0 : 1;
    
      if (n === null || isNaN(n)) {
        // only flow one buffer at a time
        if (state.flowing && state.buffer.length)
          return state.buffer[0].length;
        else
          return state.length;
      }
    
      if (n <= 0)
        return 0;
    
      // If we're asking for more than the target buffer level,
      // then raise the water mark.  Bump up to the next highest
      // power of 2, to prevent increasing it excessively in tiny
      // amounts.
      if (n > state.highWaterMark)
        state.highWaterMark = roundUpToNextPowerOf2(n);
    
      // don't have that much.  return null, unless we've ended.
      if (n > state.length) {
        if (!state.ended) {
          state.needReadable = true;
          return 0;
        } else
          return state.length;
      }
    
      return n;
    }
    
    // you can override either this method, or the async _read(n) below.
    Readable.prototype.read = function(n) {
      var state = this._readableState;
      state.calledRead = true;
      var nOrig = n;
      var ret;
    
      if (typeof n !== 'number' || n > 0)
        state.emittedReadable = false;
    
      // if we're doing read(0) to trigger a readable event, but we
      // already have a bunch of data in the buffer, then just trigger
      // the 'readable' event and move on.
      if (n === 0 &&
          state.needReadable &&
          (state.length >= state.highWaterMark || state.ended)) {
        emitReadable(this);
        return null;
      }
    
      n = howMuchToRead(n, state);
    
      // if we've ended, and we're now clear, then finish it up.
      if (n === 0 && state.ended) {
        ret = null;
    
        // In cases where the decoder did not receive enough data
        // to produce a full chunk, then immediately received an
        // EOF, state.buffer will contain [<Buffer >, <Buffer 00 ...>].
        // howMuchToRead will see this and coerce the amount to
        // read to zero (because it's looking at the length of the
        // first <Buffer > in state.buffer), and we'll end up here.
        //
        // This can only happen via state.decoder -- no other venue
        // exists for pushing a zero-length chunk into state.buffer
        // and triggering this behavior. In this case, we return our
        // remaining data and end the stream, if appropriate.
        if (state.length > 0 && state.decoder) {
          ret = fromList(n, state);
          state.length -= ret.length;
        }
    
        if (state.length === 0)
          endReadable(this);
    
        return ret;
      }
    
      // All the actual chunk generation logic needs to be
      // *below* the call to _read.  The reason is that in certain
      // synthetic stream cases, such as passthrough streams, _read
      // may be a completely synchronous operation which may change
      // the state of the read buffer, providing enough data when
      // before there was *not* enough.
      //
      // So, the steps are:
      // 1. Figure out what the state of things will be after we do
      // a read from the buffer.
      //
      // 2. If that resulting state will trigger a _read, then call _read.
      // Note that this may be asynchronous, or synchronous.  Yes, it is
      // deeply ugly to write APIs this way, but that still doesn't mean
      // that the Readable class should behave improperly, as streams are
      // designed to be sync/async agnostic.
      // Take note if the _read call is sync or async (ie, if the read call
      // has returned yet), so that we know whether or not it's safe to emit
      // 'readable' etc.
      //
      // 3. Actually pull the requested chunks out of the buffer and return.
    
      // if we need a readable event, then we need to do some reading.
      var doRead = state.needReadable;
    
      // if we currently have less than the highWaterMark, then also read some
      if (state.length - n <= state.highWaterMark)
        doRead = true;
    
      // however, if we've ended, then there's no point, and if we're already
      // reading, then it's unnecessary.
      if (state.ended || state.reading)
        doRead = false;
    
      if (doRead) {
        state.reading = true;
        state.sync = true;
        // if the length is currently zero, then we *need* a readable event.
        if (state.length === 0)
          state.needReadable = true;
        // call internal read method
        this._read(state.highWaterMark);
        state.sync = false;
      }
    
      // If _read called its callback synchronously, then `reading`
      // will be false, and we need to re-evaluate how much data we
      // can return to the user.
      if (doRead && !state.reading)
        n = howMuchToRead(nOrig, state);
    
      if (n > 0)
        ret = fromList(n, state);
      else
        ret = null;
    
      if (ret === null) {
        state.needReadable = true;
        n = 0;
      }
    
      state.length -= n;
    
      // If we have nothing in the buffer, then we want to know
      // as soon as we *do* get something into the buffer.
      if (state.length === 0 && !state.ended)
        state.needReadable = true;
    
      // If we happened to read() exactly the remaining amount in the
      // buffer, and the EOF has been seen at this point, then make sure
      // that we emit 'end' on the very next tick.
      if (state.ended && !state.endEmitted && state.length === 0)
        endReadable(this);
    
      return ret;
    };
    
    function chunkInvalid(state, chunk) {
      var er = null;
      if (!Buffer.isBuffer(chunk) &&
          'string' !== typeof chunk &&
          chunk !== null &&
          chunk !== undefined &&
          !state.objectMode) {
        er = new TypeError('Invalid non-string/buffer chunk');
      }
      return er;
    }
    
    
    function onEofChunk(stream, state) {
      if (state.decoder && !state.ended) {
        var chunk = state.decoder.end();
        if (chunk && chunk.length) {
          state.buffer.push(chunk);
          state.length += state.objectMode ? 1 : chunk.length;
        }
      }
      state.ended = true;
    
      // if we've ended and we have some data left, then emit
      // 'readable' now to make sure it gets picked up.
      if (state.length > 0)
        emitReadable(stream);
      else
        endReadable(stream);
    }
    
    // Don't emit readable right away in sync mode, because this can trigger
    // another read() call => stack overflow.  This way, it might trigger
    // a nextTick recursion warning, but that's not so bad.
    function emitReadable(stream) {
      var state = stream._readableState;
      state.needReadable = false;
      if (state.emittedReadable)
        return;
    
      state.emittedReadable = true;
      if (state.sync)
        process.nextTick(function() {
          emitReadable_(stream);
        });
      else
        emitReadable_(stream);
    }
    
    function emitReadable_(stream) {
      stream.emit('readable');
    }
    
    
    // at this point, the user has presumably seen the 'readable' event,
    // and called read() to consume some data.  that may have triggered
    // in turn another _read(n) call, in which case reading = true if
    // it's in progress.
    // However, if we're not ended, or reading, and the length < hwm,
    // then go ahead and try to read some more preemptively.
    function maybeReadMore(stream, state) {
      if (!state.readingMore) {
        state.readingMore = true;
        process.nextTick(function() {
          maybeReadMore_(stream, state);
        });
      }
    }
    
    function maybeReadMore_(stream, state) {
      var len = state.length;
      while (!state.reading && !state.flowing && !state.ended &&
             state.length < state.highWaterMark) {
        stream.read(0);
        if (len === state.length)
          // didn't get any data, stop spinning.
          break;
        else
          len = state.length;
      }
      state.readingMore = false;
    }
    
    // abstract method.  to be overridden in specific implementation classes.
    // call cb(er, data) where data is <= n in length.
    // for virtual (non-string, non-buffer) streams, "length" is somewhat
    // arbitrary, and perhaps not very meaningful.
    Readable.prototype._read = function(n) {
      this.emit('error', new Error('not implemented'));
    };
    
    Readable.prototype.pipe = function(dest, pipeOpts) {
      var src = this;
      var state = this._readableState;
    
      switch (state.pipesCount) {
        case 0:
          state.pipes = dest;
          break;
        case 1:
          state.pipes = [state.pipes, dest];
          break;
        default:
          state.pipes.push(dest);
          break;
      }
      state.pipesCount += 1;
    
      var doEnd = (!pipeOpts || pipeOpts.end !== false) &&
                  dest !== process.stdout &&
                  dest !== process.stderr;
    
      var endFn = doEnd ? onend : cleanup;
      if (state.endEmitted)
        process.nextTick(endFn);
      else
        src.once('end', endFn);
    
      dest.on('unpipe', onunpipe);
      function onunpipe(readable) {
        if (readable !== src) return;
        cleanup();
      }
    
      function onend() {
        dest.end();
      }
    
      // when the dest drains, it reduces the awaitDrain counter
      // on the source.  This would be more elegant with a .once()
      // handler in flow(), but adding and removing repeatedly is
      // too slow.
      var ondrain = pipeOnDrain(src);
      dest.on('drain', ondrain);
    
      function cleanup() {
        // cleanup event handlers once the pipe is broken
        dest.removeListener('close', onclose);
        dest.removeListener('finish', onfinish);
        dest.removeListener('drain', ondrain);
        dest.removeListener('error', onerror);
        dest.removeListener('unpipe', onunpipe);
        src.removeListener('end', onend);
        src.removeListener('end', cleanup);
    
        // if the reader is waiting for a drain event from this
        // specific writer, then it would cause it to never start
        // flowing again.
        // So, if this is awaiting a drain, then we just call it now.
        // If we don't know, then assume that we are waiting for one.
        if (!dest._writableState || dest._writableState.needDrain)
          ondrain();
      }
    
      // if the dest has an error, then stop piping into it.
      // however, don't suppress the throwing behavior for this.
      function onerror(er) {
        unpipe();
        dest.removeListener('error', onerror);
        if (EE.listenerCount(dest, 'error') === 0)
          dest.emit('error', er);
      }
      // This is a brutally ugly hack to make sure that our error handler
      // is attached before any userland ones.  NEVER DO THIS.
      if (!dest._events || !dest._events.error)
        dest.on('error', onerror);
      else if (isArray(dest._events.error))
        dest._events.error.unshift(onerror);
      else
        dest._events.error = [onerror, dest._events.error];
    
    
    
      // Both close and finish should trigger unpipe, but only once.
      function onclose() {
        dest.removeListener('finish', onfinish);
        unpipe();
      }
      dest.once('close', onclose);
      function onfinish() {
        dest.removeListener('close', onclose);
        unpipe();
      }
      dest.once('finish', onfinish);
    
      function unpipe() {
        src.unpipe(dest);
      }
    
      // tell the dest that it's being piped to
      dest.emit('pipe', src);
    
      // start the flow if it hasn't been started already.
      if (!state.flowing) {
        // the handler that waits for readable events after all
        // the data gets sucked out in flow.
        // This would be easier to follow with a .once() handler
        // in flow(), but that is too slow.
        this.on('readable', pipeOnReadable);
    
        state.flowing = true;
        process.nextTick(function() {
          flow(src);
        });
      }
    
      return dest;
    };
    
    function pipeOnDrain(src) {
      return function() {
        var dest = this;
        var state = src._readableState;
        state.awaitDrain--;
        if (state.awaitDrain === 0)
          flow(src);
      };
    }
    
    function flow(src) {
      var state = src._readableState;
      var chunk;
      state.awaitDrain = 0;
    
      function write(dest, i, list) {
        var written = dest.write(chunk);
        if (false === written) {
          state.awaitDrain++;
        }
      }
    
      while (state.pipesCount && null !== (chunk = src.read())) {
    
        if (state.pipesCount === 1)
          write(state.pipes, 0, null);
        else
          forEach(state.pipes, write);
    
        src.emit('data', chunk);
    
        // if anyone needs a drain, then we have to wait for that.
        if (state.awaitDrain > 0)
          return;
      }
    
      // if every destination was unpiped, either before entering this
      // function, or in the while loop, then stop flowing.
      //
      // NB: This is a pretty rare edge case.
      if (state.pipesCount === 0) {
        state.flowing = false;
    
        // if there were data event listeners added, then switch to old mode.
        if (EE.listenerCount(src, 'data') > 0)
          emitDataEvents(src);
        return;
      }
    
      // at this point, no one needed a drain, so we just ran out of data
      // on the next readable event, start it over again.
      state.ranOut = true;
    }
    
    function pipeOnReadable() {
      if (this._readableState.ranOut) {
        this._readableState.ranOut = false;
        flow(this);
      }
    }
    
    
    Readable.prototype.unpipe = function(dest) {
      var state = this._readableState;
    
      // if we're not piping anywhere, then do nothing.
      if (state.pipesCount === 0)
        return this;
    
      // just one destination.  most common case.
      if (state.pipesCount === 1) {
        // passed in one, but it's not the right one.
        if (dest && dest !== state.pipes)
          return this;
    
        if (!dest)
          dest = state.pipes;
    
        // got a match.
        state.pipes = null;
        state.pipesCount = 0;
        this.removeListener('readable', pipeOnReadable);
        state.flowing = false;
        if (dest)
          dest.emit('unpipe', this);
        return this;
      }
    
      // slow case. multiple pipe destinations.
    
      if (!dest) {
        // remove all.
        var dests = state.pipes;
        var len = state.pipesCount;
        state.pipes = null;
        state.pipesCount = 0;
        this.removeListener('readable', pipeOnReadable);
        state.flowing = false;
    
        for (var i = 0; i < len; i++)
          dests[i].emit('unpipe', this);
        return this;
      }
    
      // try to find the right one.
      var i = indexOf(state.pipes, dest);
      if (i === -1)
        return this;
    
      state.pipes.splice(i, 1);
      state.pipesCount -= 1;
      if (state.pipesCount === 1)
        state.pipes = state.pipes[0];
    
      dest.emit('unpipe', this);
    
      return this;
    };
    
    // set up data events if they are asked for
    // Ensure readable listeners eventually get something
    Readable.prototype.on = function(ev, fn) {
      var res = Stream.prototype.on.call(this, ev, fn);
    
      if (ev === 'data' && !this._readableState.flowing)
        emitDataEvents(this);
    
      if (ev === 'readable' && this.readable) {
        var state = this._readableState;
        if (!state.readableListening) {
          state.readableListening = true;
          state.emittedReadable = false;
          state.needReadable = true;
          if (!state.reading) {
            this.read(0);
          } else if (state.length) {
            emitReadable(this, state);
          }
        }
      }
    
      return res;
    };
    Readable.prototype.addListener = Readable.prototype.on;
    
    // pause() and resume() are remnants of the legacy readable stream API
    // If the user uses them, then switch into old mode.
    Readable.prototype.resume = function() {
      emitDataEvents(this);
      this.read(0);
      this.emit('resume');
    };
    
    Readable.prototype.pause = function() {
      emitDataEvents(this, true);
      this.emit('pause');
    };
    
    function emitDataEvents(stream, startPaused) {
      var state = stream._readableState;
    
      if (state.flowing) {
        // https://github.com/isaacs/readable-stream/issues/16
        throw new Error('Cannot switch to old mode now.');
      }
    
      var paused = startPaused || false;
      var readable = false;
    
      // convert to an old-style stream.
      stream.readable = true;
      stream.pipe = Stream.prototype.pipe;
      stream.on = stream.addListener = Stream.prototype.on;
    
      stream.on('readable', function() {
        readable = true;
    
        var c;
        while (!paused && (null !== (c = stream.read())))
          stream.emit('data', c);
    
        if (c === null) {
          readable = false;
          stream._readableState.needReadable = true;
        }
      });
    
      stream.pause = function() {
        paused = true;
        this.emit('pause');
      };
    
      stream.resume = function() {
        paused = false;
        if (readable)
          process.nextTick(function() {
            stream.emit('readable');
          });
        else
          this.read(0);
        this.emit('resume');
      };
    
      // now make it start, just in case it hadn't already.
      stream.emit('readable');
    }
    
    // wrap an old-style stream as the async data source.
    // This is *not* part of the readable stream interface.
    // It is an ugly unfortunate mess of history.
    Readable.prototype.wrap = function(stream) {
      var state = this._readableState;
      var paused = false;
    
      var self = this;
      stream.on('end', function() {
        if (state.decoder && !state.ended) {
          var chunk = state.decoder.end();
          if (chunk && chunk.length)
            self.push(chunk);
        }
    
        self.push(null);
      });
    
      stream.on('data', function(chunk) {
        if (state.decoder)
          chunk = state.decoder.write(chunk);
    
        // don't skip over falsy values in objectMode
        //if (state.objectMode && util.isNullOrUndefined(chunk))
        if (state.objectMode && (chunk === null || chunk === undefined))
          return;
        else if (!state.objectMode && (!chunk || !chunk.length))
          return;
    
        var ret = self.push(chunk);
        if (!ret) {
          paused = true;
          stream.pause();
        }
      });
    
      // proxy all the other methods.
      // important when wrapping filters and duplexes.
      for (var i in stream) {
        if (typeof stream[i] === 'function' &&
            typeof this[i] === 'undefined') {
          this[i] = function(method) { return function() {
            return stream[method].apply(stream, arguments);
          }}(i);
        }
      }
    
      // proxy certain important events.
      var events = ['error', 'close', 'destroy', 'pause', 'resume'];
      forEach(events, function(ev) {
        stream.on(ev, self.emit.bind(self, ev));
      });
    
      // when we try to consume some more bytes, simply unpause the
      // underlying stream.
      self._read = function(n) {
        if (paused) {
          paused = false;
          stream.resume();
        }
      };
    
      return self;
    };
    
    
    
    // exposed for testing purposes only.
    Readable._fromList = fromList;
    
    // Pluck off n bytes from an array of buffers.
    // Length is the combined lengths of all the buffers in the list.
    function fromList(n, state) {
      var list = state.buffer;
      var length = state.length;
      var stringMode = !!state.decoder;
      var objectMode = !!state.objectMode;
      var ret;
    
      // nothing in the list, definitely empty.
      if (list.length === 0)
        return null;
    
      if (length === 0)
        ret = null;
      else if (objectMode)
        ret = list.shift();
      else if (!n || n >= length) {
        // read it all, truncate the array.
        if (stringMode)
          ret = list.join('');
        else
          ret = Buffer.concat(list, length);
        list.length = 0;
      } else {
        // read just some of it.
        if (n < list[0].length) {
          // just take a part of the first list item.
          // slice is the same for buffers and strings.
          var buf = list[0];
          ret = buf.slice(0, n);
          list[0] = buf.slice(n);
        } else if (n === list[0].length) {
          // first list is a perfect match
          ret = list.shift();
        } else {
          // complex case.
          // we have enough to cover it, but it spans past the first buffer.
          if (stringMode)
            ret = '';
          else
            ret = new Buffer(n);
    
          var c = 0;
          for (var i = 0, l = list.length; i < l && c < n; i++) {
            var buf = list[0];
            var cpy = Math.min(n - c, buf.length);
    
            if (stringMode)
              ret += buf.slice(0, cpy);
            else
              buf.copy(ret, c, 0, cpy);
    
            if (cpy < buf.length)
              list[0] = buf.slice(cpy);
            else
              list.shift();
    
            c += cpy;
          }
        }
      }
    
      return ret;
    }
    
    function endReadable(stream) {
      var state = stream._readableState;
    
      // If we get here before consuming all the bytes, then that is a
      // bug in node.  Should never happen.
      if (state.length > 0)
        throw new Error('endReadable called on non-empty stream');
    
      if (!state.endEmitted && state.calledRead) {
        state.ended = true;
        process.nextTick(function() {
          // Check that we didn't get one last unshift.
          if (!state.endEmitted && state.length === 0) {
            state.endEmitted = true;
            stream.readable = false;
            stream.emit('end');
          }
        });
      }
    }
    
    function forEach (xs, f) {
      for (var i = 0, l = xs.length; i < l; i++) {
        f(xs[i], i);
      }
    }
    
    function indexOf (xs, x) {
      for (var i = 0, l = xs.length; i < l; i++) {
        if (xs[i] === x) return i;
      }
      return -1;
    }
    
  provide("readable-stream/lib/_stream_readable.js", module.exports);
}(global));

// pakmanager:readable-stream/lib/_stream_writable.js
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright Joyent, Inc. and other Node contributors.
    //
    // Permission is hereby granted, free of charge, to any person obtaining a
    // copy of this software and associated documentation files (the
    // "Software"), to deal in the Software without restriction, including
    // without limitation the rights to use, copy, modify, merge, publish,
    // distribute, sublicense, and/or sell copies of the Software, and to permit
    // persons to whom the Software is furnished to do so, subject to the
    // following conditions:
    //
    // The above copyright notice and this permission notice shall be included
    // in all copies or substantial portions of the Software.
    //
    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
    // NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    // DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    // OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
    // USE OR OTHER DEALINGS IN THE SOFTWARE.
    
    // A bit simpler than readable streams.
    // Implement an async ._write(chunk, cb), and it'll handle all
    // the drain event emission and buffering.
    
    module.exports = Writable;
    
    /*<replacement>*/
    var Buffer = require('buffer').Buffer;
    /*</replacement>*/
    
    Writable.WritableState = WritableState;
    
    
    /*<replacement>*/
    var util = require('core-util-is');
    util.inherits = require('inherits');
    /*</replacement>*/
    
    var Stream = require('stream');
    
    util.inherits(Writable, Stream);
    
    function WriteReq(chunk, encoding, cb) {
      this.chunk = chunk;
      this.encoding = encoding;
      this.callback = cb;
    }
    
    function WritableState(options, stream) {
      options = options || {};
    
      // the point at which write() starts returning false
      // Note: 0 is a valid value, means that we always return false if
      // the entire buffer is not flushed immediately on write()
      var hwm = options.highWaterMark;
      this.highWaterMark = (hwm || hwm === 0) ? hwm : 16 * 1024;
    
      // object stream flag to indicate whether or not this stream
      // contains buffers or objects.
      this.objectMode = !!options.objectMode;
    
      // cast to ints.
      this.highWaterMark = ~~this.highWaterMark;
    
      this.needDrain = false;
      // at the start of calling end()
      this.ending = false;
      // when end() has been called, and returned
      this.ended = false;
      // when 'finish' is emitted
      this.finished = false;
    
      // should we decode strings into buffers before passing to _write?
      // this is here so that some node-core streams can optimize string
      // handling at a lower level.
      var noDecode = options.decodeStrings === false;
      this.decodeStrings = !noDecode;
    
      // Crypto is kind of old and crusty.  Historically, its default string
      // encoding is 'binary' so we have to make this configurable.
      // Everything else in the universe uses 'utf8', though.
      this.defaultEncoding = options.defaultEncoding || 'utf8';
    
      // not an actual buffer we keep track of, but a measurement
      // of how much we're waiting to get pushed to some underlying
      // socket or file.
      this.length = 0;
    
      // a flag to see when we're in the middle of a write.
      this.writing = false;
    
      // a flag to be able to tell if the onwrite cb is called immediately,
      // or on a later tick.  We set this to true at first, becuase any
      // actions that shouldn't happen until "later" should generally also
      // not happen before the first write call.
      this.sync = true;
    
      // a flag to know if we're processing previously buffered items, which
      // may call the _write() callback in the same tick, so that we don't
      // end up in an overlapped onwrite situation.
      this.bufferProcessing = false;
    
      // the callback that's passed to _write(chunk,cb)
      this.onwrite = function(er) {
        onwrite(stream, er);
      };
    
      // the callback that the user supplies to write(chunk,encoding,cb)
      this.writecb = null;
    
      // the amount that is being written when _write is called.
      this.writelen = 0;
    
      this.buffer = [];
    
      // True if the error was already emitted and should not be thrown again
      this.errorEmitted = false;
    }
    
    function Writable(options) {
      var Duplex =  require('readable-stream/lib/_stream_duplex');
    
      // Writable ctor is applied to Duplexes, though they're not
      // instanceof Writable, they're instanceof Readable.
      if (!(this instanceof Writable) && !(this instanceof Duplex))
        return new Writable(options);
    
      this._writableState = new WritableState(options, this);
    
      // legacy.
      this.writable = true;
    
      Stream.call(this);
    }
    
    // Otherwise people can pipe Writable streams, which is just wrong.
    Writable.prototype.pipe = function() {
      this.emit('error', new Error('Cannot pipe. Not readable.'));
    };
    
    
    function writeAfterEnd(stream, state, cb) {
      var er = new Error('write after end');
      // TODO: defer error events consistently everywhere, not just the cb
      stream.emit('error', er);
      process.nextTick(function() {
        cb(er);
      });
    }
    
    // If we get something that is not a buffer, string, null, or undefined,
    // and we're not in objectMode, then that's an error.
    // Otherwise stream chunks are all considered to be of length=1, and the
    // watermarks determine how many objects to keep in the buffer, rather than
    // how many bytes or characters.
    function validChunk(stream, state, chunk, cb) {
      var valid = true;
      if (!Buffer.isBuffer(chunk) &&
          'string' !== typeof chunk &&
          chunk !== null &&
          chunk !== undefined &&
          !state.objectMode) {
        var er = new TypeError('Invalid non-string/buffer chunk');
        stream.emit('error', er);
        process.nextTick(function() {
          cb(er);
        });
        valid = false;
      }
      return valid;
    }
    
    Writable.prototype.write = function(chunk, encoding, cb) {
      var state = this._writableState;
      var ret = false;
    
      if (typeof encoding === 'function') {
        cb = encoding;
        encoding = null;
      }
    
      if (Buffer.isBuffer(chunk))
        encoding = 'buffer';
      else if (!encoding)
        encoding = state.defaultEncoding;
    
      if (typeof cb !== 'function')
        cb = function() {};
    
      if (state.ended)
        writeAfterEnd(this, state, cb);
      else if (validChunk(this, state, chunk, cb))
        ret = writeOrBuffer(this, state, chunk, encoding, cb);
    
      return ret;
    };
    
    function decodeChunk(state, chunk, encoding) {
      if (!state.objectMode &&
          state.decodeStrings !== false &&
          typeof chunk === 'string') {
        chunk = new Buffer(chunk, encoding);
      }
      return chunk;
    }
    
    // if we're already writing something, then just put this
    // in the queue, and wait our turn.  Otherwise, call _write
    // If we return false, then we need a drain event, so set that flag.
    function writeOrBuffer(stream, state, chunk, encoding, cb) {
      chunk = decodeChunk(state, chunk, encoding);
      if (Buffer.isBuffer(chunk))
        encoding = 'buffer';
      var len = state.objectMode ? 1 : chunk.length;
    
      state.length += len;
    
      var ret = state.length < state.highWaterMark;
      // we must ensure that previous needDrain will not be reset to false.
      if (!ret)
        state.needDrain = true;
    
      if (state.writing)
        state.buffer.push(new WriteReq(chunk, encoding, cb));
      else
        doWrite(stream, state, len, chunk, encoding, cb);
    
      return ret;
    }
    
    function doWrite(stream, state, len, chunk, encoding, cb) {
      state.writelen = len;
      state.writecb = cb;
      state.writing = true;
      state.sync = true;
      stream._write(chunk, encoding, state.onwrite);
      state.sync = false;
    }
    
    function onwriteError(stream, state, sync, er, cb) {
      if (sync)
        process.nextTick(function() {
          cb(er);
        });
      else
        cb(er);
    
      stream._writableState.errorEmitted = true;
      stream.emit('error', er);
    }
    
    function onwriteStateUpdate(state) {
      state.writing = false;
      state.writecb = null;
      state.length -= state.writelen;
      state.writelen = 0;
    }
    
    function onwrite(stream, er) {
      var state = stream._writableState;
      var sync = state.sync;
      var cb = state.writecb;
    
      onwriteStateUpdate(state);
    
      if (er)
        onwriteError(stream, state, sync, er, cb);
      else {
        // Check if we're actually ready to finish, but don't emit yet
        var finished = needFinish(stream, state);
    
        if (!finished && !state.bufferProcessing && state.buffer.length)
          clearBuffer(stream, state);
    
        if (sync) {
          process.nextTick(function() {
            afterWrite(stream, state, finished, cb);
          });
        } else {
          afterWrite(stream, state, finished, cb);
        }
      }
    }
    
    function afterWrite(stream, state, finished, cb) {
      if (!finished)
        onwriteDrain(stream, state);
      cb();
      if (finished)
        finishMaybe(stream, state);
    }
    
    // Must force callback to be called on nextTick, so that we don't
    // emit 'drain' before the write() consumer gets the 'false' return
    // value, and has a chance to attach a 'drain' listener.
    function onwriteDrain(stream, state) {
      if (state.length === 0 && state.needDrain) {
        state.needDrain = false;
        stream.emit('drain');
      }
    }
    
    
    // if there's something in the buffer waiting, then process it
    function clearBuffer(stream, state) {
      state.bufferProcessing = true;
    
      for (var c = 0; c < state.buffer.length; c++) {
        var entry = state.buffer[c];
        var chunk = entry.chunk;
        var encoding = entry.encoding;
        var cb = entry.callback;
        var len = state.objectMode ? 1 : chunk.length;
    
        doWrite(stream, state, len, chunk, encoding, cb);
    
        // if we didn't call the onwrite immediately, then
        // it means that we need to wait until it does.
        // also, that means that the chunk and cb are currently
        // being processed, so move the buffer counter past them.
        if (state.writing) {
          c++;
          break;
        }
      }
    
      state.bufferProcessing = false;
      if (c < state.buffer.length)
        state.buffer = state.buffer.slice(c);
      else
        state.buffer.length = 0;
    }
    
    Writable.prototype._write = function(chunk, encoding, cb) {
      cb(new Error('not implemented'));
    };
    
    Writable.prototype.end = function(chunk, encoding, cb) {
      var state = this._writableState;
    
      if (typeof chunk === 'function') {
        cb = chunk;
        chunk = null;
        encoding = null;
      } else if (typeof encoding === 'function') {
        cb = encoding;
        encoding = null;
      }
    
      if (typeof chunk !== 'undefined' && chunk !== null)
        this.write(chunk, encoding);
    
      // ignore unnecessary end() calls.
      if (!state.ending && !state.finished)
        endWritable(this, state, cb);
    };
    
    
    function needFinish(stream, state) {
      return (state.ending &&
              state.length === 0 &&
              !state.finished &&
              !state.writing);
    }
    
    function finishMaybe(stream, state) {
      var need = needFinish(stream, state);
      if (need) {
        state.finished = true;
        stream.emit('finish');
      }
      return need;
    }
    
    function endWritable(stream, state, cb) {
      state.ending = true;
      finishMaybe(stream, state);
      if (cb) {
        if (state.finished)
          process.nextTick(cb);
        else
          stream.once('finish', cb);
      }
      state.ended = true;
    }
    
  provide("readable-stream/lib/_stream_writable.js", module.exports);
}(global));

// pakmanager:readable-stream/lib/_stream_duplex.js
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright Joyent, Inc. and other Node contributors.
    //
    // Permission is hereby granted, free of charge, to any person obtaining a
    // copy of this software and associated documentation files (the
    // "Software"), to deal in the Software without restriction, including
    // without limitation the rights to use, copy, modify, merge, publish,
    // distribute, sublicense, and/or sell copies of the Software, and to permit
    // persons to whom the Software is furnished to do so, subject to the
    // following conditions:
    //
    // The above copyright notice and this permission notice shall be included
    // in all copies or substantial portions of the Software.
    //
    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
    // NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    // DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    // OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
    // USE OR OTHER DEALINGS IN THE SOFTWARE.
    
    // a duplex stream is just a stream that is both readable and writable.
    // Since JS doesn't have multiple prototypal inheritance, this class
    // prototypally inherits from Readable, and then parasitically from
    // Writable.
    
    module.exports = Duplex;
    
    /*<replacement>*/
    var objectKeys = Object.keys || function (obj) {
      var keys = [];
      for (var key in obj) keys.push(key);
      return keys;
    }
    /*</replacement>*/
    
    
    /*<replacement>*/
    var util = require('core-util-is');
    util.inherits = require('inherits');
    /*</replacement>*/
    
    var Readable =  require('readable-stream/lib/_stream_readable');
    var Writable =  require('readable-stream/lib/_stream_writable');
    
    util.inherits(Duplex, Readable);
    
    forEach(objectKeys(Writable.prototype), function(method) {
      if (!Duplex.prototype[method])
        Duplex.prototype[method] = Writable.prototype[method];
    });
    
    function Duplex(options) {
      if (!(this instanceof Duplex))
        return new Duplex(options);
    
      Readable.call(this, options);
      Writable.call(this, options);
    
      if (options && options.readable === false)
        this.readable = false;
    
      if (options && options.writable === false)
        this.writable = false;
    
      this.allowHalfOpen = true;
      if (options && options.allowHalfOpen === false)
        this.allowHalfOpen = false;
    
      this.once('end', onend);
    }
    
    // the no-half-open enforcer
    function onend() {
      // if we allow half-open state, or if the writable side ended,
      // then we're ok.
      if (this.allowHalfOpen || this._writableState.ended)
        return;
    
      // no more data can be written.
      // But allow more writes to happen in this tick.
      process.nextTick(this.end.bind(this));
    }
    
    function forEach (xs, f) {
      for (var i = 0, l = xs.length; i < l; i++) {
        f(xs[i], i);
      }
    }
    
  provide("readable-stream/lib/_stream_duplex.js", module.exports);
}(global));

// pakmanager:readable-stream/lib/_stream_transform.js
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright Joyent, Inc. and other Node contributors.
    //
    // Permission is hereby granted, free of charge, to any person obtaining a
    // copy of this software and associated documentation files (the
    // "Software"), to deal in the Software without restriction, including
    // without limitation the rights to use, copy, modify, merge, publish,
    // distribute, sublicense, and/or sell copies of the Software, and to permit
    // persons to whom the Software is furnished to do so, subject to the
    // following conditions:
    //
    // The above copyright notice and this permission notice shall be included
    // in all copies or substantial portions of the Software.
    //
    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
    // NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    // DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    // OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
    // USE OR OTHER DEALINGS IN THE SOFTWARE.
    
    
    // a transform stream is a readable/writable stream where you do
    // something with the data.  Sometimes it's called a "filter",
    // but that's not a great name for it, since that implies a thing where
    // some bits pass through, and others are simply ignored.  (That would
    // be a valid example of a transform, of course.)
    //
    // While the output is causally related to the input, it's not a
    // necessarily symmetric or synchronous transformation.  For example,
    // a zlib stream might take multiple plain-text writes(), and then
    // emit a single compressed chunk some time in the future.
    //
    // Here's how this works:
    //
    // The Transform stream has all the aspects of the readable and writable
    // stream classes.  When you write(chunk), that calls _write(chunk,cb)
    // internally, and returns false if there's a lot of pending writes
    // buffered up.  When you call read(), that calls _read(n) until
    // there's enough pending readable data buffered up.
    //
    // In a transform stream, the written data is placed in a buffer.  When
    // _read(n) is called, it transforms the queued up data, calling the
    // buffered _write cb's as it consumes chunks.  If consuming a single
    // written chunk would result in multiple output chunks, then the first
    // outputted bit calls the readcb, and subsequent chunks just go into
    // the read buffer, and will cause it to emit 'readable' if necessary.
    //
    // This way, back-pressure is actually determined by the reading side,
    // since _read has to be called to start processing a new chunk.  However,
    // a pathological inflate type of transform can cause excessive buffering
    // here.  For example, imagine a stream where every byte of input is
    // interpreted as an integer from 0-255, and then results in that many
    // bytes of output.  Writing the 4 bytes {ff,ff,ff,ff} would result in
    // 1kb of data being output.  In this case, you could write a very small
    // amount of input, and end up with a very large amount of output.  In
    // such a pathological inflating mechanism, there'd be no way to tell
    // the system to stop doing the transform.  A single 4MB write could
    // cause the system to run out of memory.
    //
    // However, even in such a pathological case, only a single written chunk
    // would be consumed, and then the rest would wait (un-transformed) until
    // the results of the previous transformed chunk were consumed.
    
    module.exports = Transform;
    
    var Duplex =  require('readable-stream/lib/_stream_duplex');
    
    /*<replacement>*/
    var util = require('core-util-is');
    util.inherits = require('inherits');
    /*</replacement>*/
    
    util.inherits(Transform, Duplex);
    
    
    function TransformState(options, stream) {
      this.afterTransform = function(er, data) {
        return afterTransform(stream, er, data);
      };
    
      this.needTransform = false;
      this.transforming = false;
      this.writecb = null;
      this.writechunk = null;
    }
    
    function afterTransform(stream, er, data) {
      var ts = stream._transformState;
      ts.transforming = false;
    
      var cb = ts.writecb;
    
      if (!cb)
        return stream.emit('error', new Error('no writecb in Transform class'));
    
      ts.writechunk = null;
      ts.writecb = null;
    
      if (data !== null && data !== undefined)
        stream.push(data);
    
      if (cb)
        cb(er);
    
      var rs = stream._readableState;
      rs.reading = false;
      if (rs.needReadable || rs.length < rs.highWaterMark) {
        stream._read(rs.highWaterMark);
      }
    }
    
    
    function Transform(options) {
      if (!(this instanceof Transform))
        return new Transform(options);
    
      Duplex.call(this, options);
    
      var ts = this._transformState = new TransformState(options, this);
    
      // when the writable side finishes, then flush out anything remaining.
      var stream = this;
    
      // start out asking for a readable event once data is transformed.
      this._readableState.needReadable = true;
    
      // we have implemented the _read method, and done the other things
      // that Readable wants before the first _read call, so unset the
      // sync guard flag.
      this._readableState.sync = false;
    
      this.once('finish', function() {
        if ('function' === typeof this._flush)
          this._flush(function(er) {
            done(stream, er);
          });
        else
          done(stream);
      });
    }
    
    Transform.prototype.push = function(chunk, encoding) {
      this._transformState.needTransform = false;
      return Duplex.prototype.push.call(this, chunk, encoding);
    };
    
    // This is the part where you do stuff!
    // override this function in implementation classes.
    // 'chunk' is an input chunk.
    //
    // Call `push(newChunk)` to pass along transformed output
    // to the readable side.  You may call 'push' zero or more times.
    //
    // Call `cb(err)` when you are done with this chunk.  If you pass
    // an error, then that'll put the hurt on the whole operation.  If you
    // never call cb(), then you'll never get another chunk.
    Transform.prototype._transform = function(chunk, encoding, cb) {
      throw new Error('not implemented');
    };
    
    Transform.prototype._write = function(chunk, encoding, cb) {
      var ts = this._transformState;
      ts.writecb = cb;
      ts.writechunk = chunk;
      ts.writeencoding = encoding;
      if (!ts.transforming) {
        var rs = this._readableState;
        if (ts.needTransform ||
            rs.needReadable ||
            rs.length < rs.highWaterMark)
          this._read(rs.highWaterMark);
      }
    };
    
    // Doesn't matter what the args are here.
    // _transform does all the work.
    // That we got here means that the readable side wants more data.
    Transform.prototype._read = function(n) {
      var ts = this._transformState;
    
      if (ts.writechunk !== null && ts.writecb && !ts.transforming) {
        ts.transforming = true;
        this._transform(ts.writechunk, ts.writeencoding, ts.afterTransform);
      } else {
        // mark that we need a transform, so that any data that comes in
        // will get processed, now that we've asked for it.
        ts.needTransform = true;
      }
    };
    
    
    function done(stream, er) {
      if (er)
        return stream.emit('error', er);
    
      // if there's nothing in the write buffer, then that means
      // that nothing more will ever be provided
      var ws = stream._writableState;
      var rs = stream._readableState;
      var ts = stream._transformState;
    
      if (ws.length)
        throw new Error('calling transform done when ws.length != 0');
    
      if (ts.transforming)
        throw new Error('calling transform done when still transforming');
    
      return stream.push(null);
    }
    
  provide("readable-stream/lib/_stream_transform.js", module.exports);
}(global));

// pakmanager:readable-stream/lib/_stream_passthrough.js
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright Joyent, Inc. and other Node contributors.
    //
    // Permission is hereby granted, free of charge, to any person obtaining a
    // copy of this software and associated documentation files (the
    // "Software"), to deal in the Software without restriction, including
    // without limitation the rights to use, copy, modify, merge, publish,
    // distribute, sublicense, and/or sell copies of the Software, and to permit
    // persons to whom the Software is furnished to do so, subject to the
    // following conditions:
    //
    // The above copyright notice and this permission notice shall be included
    // in all copies or substantial portions of the Software.
    //
    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
    // NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    // DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    // OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
    // USE OR OTHER DEALINGS IN THE SOFTWARE.
    
    // a passthrough stream.
    // basically just the most minimal sort of Transform stream.
    // Every written chunk gets output as-is.
    
    module.exports = PassThrough;
    
    var Transform =  require('readable-stream/lib/_stream_transform');
    
    /*<replacement>*/
    var util = require('core-util-is');
    util.inherits = require('inherits');
    /*</replacement>*/
    
    util.inherits(PassThrough, Transform);
    
    function PassThrough(options) {
      if (!(this instanceof PassThrough))
        return new PassThrough(options);
    
      Transform.call(this, options);
    }
    
    PassThrough.prototype._transform = function(chunk, encoding, cb) {
      cb(null, chunk);
    };
    
  provide("readable-stream/lib/_stream_passthrough.js", module.exports);
}(global));

// pakmanager:readable-stream
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  var Stream = require('stream'); // hack to fix a circular dependency issue when used with browserify
    exports = module.exports =  require('readable-stream/lib/_stream_readable.js');
    exports.Stream = Stream;
    exports.Readable = exports;
    exports.Writable =  require('readable-stream/lib/_stream_writable.js');
    exports.Duplex =  require('readable-stream/lib/_stream_duplex.js');
    exports.Transform =  require('readable-stream/lib/_stream_transform.js');
    exports.PassThrough =  require('readable-stream/lib/_stream_passthrough.js');
    
  provide("readable-stream", module.exports);
}(global));

// pakmanager:combined-stream
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  var util = require('util');
    var Stream = require('stream').Stream;
    var DelayedStream = require('delayed-stream');
    
    module.exports = CombinedStream;
    function CombinedStream() {
      this.writable = false;
      this.readable = true;
      this.dataSize = 0;
      this.maxDataSize = 2 * 1024 * 1024;
      this.pauseStreams = true;
    
      this._released = false;
      this._streams = [];
      this._currentStream = null;
    }
    util.inherits(CombinedStream, Stream);
    
    CombinedStream.create = function(options) {
      var combinedStream = new this();
    
      options = options || {};
      for (var option in options) {
        combinedStream[option] = options[option];
      }
    
      return combinedStream;
    };
    
    CombinedStream.isStreamLike = function(stream) {
      return (typeof stream !== 'function')
        && (typeof stream !== 'string')
        && (typeof stream !== 'boolean')
        && (typeof stream !== 'number')
        && (!Buffer.isBuffer(stream));
    };
    
    CombinedStream.prototype.append = function(stream) {
      var isStreamLike = CombinedStream.isStreamLike(stream);
    
      if (isStreamLike) {
        if (!(stream instanceof DelayedStream)) {
          var newStream = DelayedStream.create(stream, {
            maxDataSize: Infinity,
            pauseStream: this.pauseStreams,
          });
          stream.on('data', this._checkDataSize.bind(this));
          stream = newStream;
        }
    
        this._handleErrors(stream);
    
        if (this.pauseStreams) {
          stream.pause();
        }
      }
    
      this._streams.push(stream);
      return this;
    };
    
    CombinedStream.prototype.pipe = function(dest, options) {
      Stream.prototype.pipe.call(this, dest, options);
      this.resume();
      return dest;
    };
    
    CombinedStream.prototype._getNext = function() {
      this._currentStream = null;
      var stream = this._streams.shift();
    
    
      if (typeof stream == 'undefined') {
        this.end();
        return;
      }
    
      if (typeof stream !== 'function') {
        this._pipeNext(stream);
        return;
      }
    
      var getStream = stream;
      getStream(function(stream) {
        var isStreamLike = CombinedStream.isStreamLike(stream);
        if (isStreamLike) {
          stream.on('data', this._checkDataSize.bind(this));
          this._handleErrors(stream);
        }
    
        this._pipeNext(stream);
      }.bind(this));
    };
    
    CombinedStream.prototype._pipeNext = function(stream) {
      this._currentStream = stream;
    
      var isStreamLike = CombinedStream.isStreamLike(stream);
      if (isStreamLike) {
        stream.on('end', this._getNext.bind(this));
        stream.pipe(this, {end: false});
        return;
      }
    
      var value = stream;
      this.write(value);
      this._getNext();
    };
    
    CombinedStream.prototype._handleErrors = function(stream) {
      var self = this;
      stream.on('error', function(err) {
        self._emitError(err);
      });
    };
    
    CombinedStream.prototype.write = function(data) {
      this.emit('data', data);
    };
    
    CombinedStream.prototype.pause = function() {
      if (!this.pauseStreams) {
        return;
      }
    
      if(this.pauseStreams && this._currentStream && typeof(this._currentStream.pause) == 'function') this._currentStream.pause();
      this.emit('pause');
    };
    
    CombinedStream.prototype.resume = function() {
      if (!this._released) {
        this._released = true;
        this.writable = true;
        this._getNext();
      }
    
      if(this.pauseStreams && this._currentStream && typeof(this._currentStream.resume) == 'function') this._currentStream.resume();
      this.emit('resume');
    };
    
    CombinedStream.prototype.end = function() {
      this._reset();
      this.emit('end');
    };
    
    CombinedStream.prototype.destroy = function() {
      this._reset();
      this.emit('close');
    };
    
    CombinedStream.prototype._reset = function() {
      this.writable = false;
      this._streams = [];
      this._currentStream = null;
    };
    
    CombinedStream.prototype._checkDataSize = function() {
      this._updateDataSize();
      if (this.dataSize <= this.maxDataSize) {
        return;
      }
    
      var message =
        'DelayedStream#maxDataSize of ' + this.maxDataSize + ' bytes exceeded.';
      this._emitError(new Error(message));
    };
    
    CombinedStream.prototype._updateDataSize = function() {
      this.dataSize = 0;
    
      var self = this;
      this._streams.forEach(function(stream) {
        if (!stream.dataSize) {
          return;
        }
    
        self.dataSize += stream.dataSize;
      });
    
      if (this._currentStream && this._currentStream.dataSize) {
        this.dataSize += this._currentStream.dataSize;
      }
    };
    
    CombinedStream.prototype._emitError = function(err) {
      this._reset();
      this.emit('error', err);
    };
    
  provide("combined-stream", module.exports);
}(global));

// pakmanager:mime
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  var path = require('path');
    var fs = require('fs');
    
    function Mime() {
      // Map of extension -> mime type
      this.types = Object.create(null);
    
      // Map of mime type -> extension
      this.extensions = Object.create(null);
    }
    
    /**
     * Define mimetype -> extension mappings.  Each key is a mime-type that maps
     * to an array of extensions associated with the type.  The first extension is
     * used as the default extension for the type.
     *
     * e.g. mime.define({'audio/ogg', ['oga', 'ogg', 'spx']});
     *
     * @param map (Object) type definitions
     */
    Mime.prototype.define = function (map) {
      for (var type in map) {
        var exts = map[type];
    
        for (var i = 0; i < exts.length; i++) {
          if (process.env.DEBUG_MIME && this.types[exts]) {
            console.warn(this._loading.replace(/.*\//, ''), 'changes "' + exts[i] + '" extension type from ' +
              this.types[exts] + ' to ' + type);
          }
    
          this.types[exts[i]] = type;
        }
    
        // Default extension is the first one we encounter
        if (!this.extensions[type]) {
          this.extensions[type] = exts[0];
        }
      }
    };
    
    /**
     * Load an Apache2-style ".types" file
     *
     * This may be called multiple times (it's expected).  Where files declare
     * overlapping types/extensions, the last file wins.
     *
     * @param file (String) path of file to load.
     */
    Mime.prototype.load = function(file) {
    
      this._loading = file;
      // Read file and split into lines
      var map = {},
          content = fs.readFileSync(file, 'ascii'),
          lines = content.split(/[\r\n]+/);
    
      lines.forEach(function(line) {
        // Clean up whitespace/comments, and split into fields
        var fields = line.replace(/\s*#.*|^\s*|\s*$/g, '').split(/\s+/);
        map[fields.shift()] = fields;
      });
    
      this.define(map);
    
      this._loading = null;
    };
    
    /**
     * Lookup a mime type based on extension
     */
    Mime.prototype.lookup = function(path, fallback) {
      var ext = path.replace(/.*[\.\/\\]/, '').toLowerCase();
    
      return this.types[ext] || fallback || this.default_type;
    };
    
    /**
     * Return file extension associated with a mime type
     */
    Mime.prototype.extension = function(mimeType) {
      var type = mimeType.match(/^\s*([^;\s]*)(?:;|\s|$)/)[1].toLowerCase();
      return this.extensions[type];
    };
    
    // Default instance
    var mime = new Mime();
    
    // Load local copy of
    // http://svn.apache.org/repos/asf/httpd/httpd/trunk/docs/conf/mime.types
    mime.load(path.join(__dirname, 'types/mime.types'));
    
    // Load additional types from node.js community
    mime.load(path.join(__dirname, 'types/node.types'));
    
    // Default type
    mime.default_type = mime.lookup('bin');
    
    //
    // Additional API specific to the default instance
    //
    
    mime.Mime = Mime;
    
    /**
     * Lookup a charset based on mime type.
     */
    mime.charsets = {
      lookup: function(mimeType, fallback) {
        // Assume text types are utf8
        return (/^text\//).test(mimeType) ? 'UTF-8' : fallback;
      }
    };
    
    module.exports = mime;
    
  provide("mime", module.exports);
}(global));

// pakmanager:async
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  /*!
     * async
     * https://github.com/caolan/async
     *
     * Copyright 2010-2014 Caolan McMahon
     * Released under the MIT license
     */
    /*jshint onevar: false, indent:4 */
    /*global setImmediate: false, setTimeout: false, console: false */
    (function () {
    
        var async = {};
    
        // global on the server, window in the browser
        var root, previous_async;
    
        root = this;
        if (root != null) {
          previous_async = root.async;
        }
    
        async.noConflict = function () {
            root.async = previous_async;
            return async;
        };
    
        function only_once(fn) {
            var called = false;
            return function() {
                if (called) throw new Error("Callback was already called.");
                called = true;
                fn.apply(root, arguments);
            }
        }
    
        //// cross-browser compatiblity functions ////
    
        var _toString = Object.prototype.toString;
    
        var _isArray = Array.isArray || function (obj) {
            return _toString.call(obj) === '[object Array]';
        };
    
        var _each = function (arr, iterator) {
            if (arr.forEach) {
                return arr.forEach(iterator);
            }
            for (var i = 0; i < arr.length; i += 1) {
                iterator(arr[i], i, arr);
            }
        };
    
        var _map = function (arr, iterator) {
            if (arr.map) {
                return arr.map(iterator);
            }
            var results = [];
            _each(arr, function (x, i, a) {
                results.push(iterator(x, i, a));
            });
            return results;
        };
    
        var _reduce = function (arr, iterator, memo) {
            if (arr.reduce) {
                return arr.reduce(iterator, memo);
            }
            _each(arr, function (x, i, a) {
                memo = iterator(memo, x, i, a);
            });
            return memo;
        };
    
        var _keys = function (obj) {
            if (Object.keys) {
                return Object.keys(obj);
            }
            var keys = [];
            for (var k in obj) {
                if (obj.hasOwnProperty(k)) {
                    keys.push(k);
                }
            }
            return keys;
        };
    
        //// exported async module functions ////
    
        //// nextTick implementation with browser-compatible fallback ////
        if (typeof process === 'undefined' || !(process.nextTick)) {
            if (typeof setImmediate === 'function') {
                async.nextTick = function (fn) {
                    // not a direct alias for IE10 compatibility
                    setImmediate(fn);
                };
                async.setImmediate = async.nextTick;
            }
            else {
                async.nextTick = function (fn) {
                    setTimeout(fn, 0);
                };
                async.setImmediate = async.nextTick;
            }
        }
        else {
            async.nextTick = process.nextTick;
            if (typeof setImmediate !== 'undefined') {
                async.setImmediate = function (fn) {
                  // not a direct alias for IE10 compatibility
                  setImmediate(fn);
                };
            }
            else {
                async.setImmediate = async.nextTick;
            }
        }
    
        async.each = function (arr, iterator, callback) {
            callback = callback || function () {};
            if (!arr.length) {
                return callback();
            }
            var completed = 0;
            _each(arr, function (x) {
                iterator(x, only_once(done) );
            });
            function done(err) {
              if (err) {
                  callback(err);
                  callback = function () {};
              }
              else {
                  completed += 1;
                  if (completed >= arr.length) {
                      callback();
                  }
              }
            }
        };
        async.forEach = async.each;
    
        async.eachSeries = function (arr, iterator, callback) {
            callback = callback || function () {};
            if (!arr.length) {
                return callback();
            }
            var completed = 0;
            var iterate = function () {
                iterator(arr[completed], function (err) {
                    if (err) {
                        callback(err);
                        callback = function () {};
                    }
                    else {
                        completed += 1;
                        if (completed >= arr.length) {
                            callback();
                        }
                        else {
                            iterate();
                        }
                    }
                });
            };
            iterate();
        };
        async.forEachSeries = async.eachSeries;
    
        async.eachLimit = function (arr, limit, iterator, callback) {
            var fn = _eachLimit(limit);
            fn.apply(null, [arr, iterator, callback]);
        };
        async.forEachLimit = async.eachLimit;
    
        var _eachLimit = function (limit) {
    
            return function (arr, iterator, callback) {
                callback = callback || function () {};
                if (!arr.length || limit <= 0) {
                    return callback();
                }
                var completed = 0;
                var started = 0;
                var running = 0;
    
                (function replenish () {
                    if (completed >= arr.length) {
                        return callback();
                    }
    
                    while (running < limit && started < arr.length) {
                        started += 1;
                        running += 1;
                        iterator(arr[started - 1], function (err) {
                            if (err) {
                                callback(err);
                                callback = function () {};
                            }
                            else {
                                completed += 1;
                                running -= 1;
                                if (completed >= arr.length) {
                                    callback();
                                }
                                else {
                                    replenish();
                                }
                            }
                        });
                    }
                })();
            };
        };
    
    
        var doParallel = function (fn) {
            return function () {
                var args = Array.prototype.slice.call(arguments);
                return fn.apply(null, [async.each].concat(args));
            };
        };
        var doParallelLimit = function(limit, fn) {
            return function () {
                var args = Array.prototype.slice.call(arguments);
                return fn.apply(null, [_eachLimit(limit)].concat(args));
            };
        };
        var doSeries = function (fn) {
            return function () {
                var args = Array.prototype.slice.call(arguments);
                return fn.apply(null, [async.eachSeries].concat(args));
            };
        };
    
    
        var _asyncMap = function (eachfn, arr, iterator, callback) {
            arr = _map(arr, function (x, i) {
                return {index: i, value: x};
            });
            if (!callback) {
                eachfn(arr, function (x, callback) {
                    iterator(x.value, function (err) {
                        callback(err);
                    });
                });
            } else {
                var results = [];
                eachfn(arr, function (x, callback) {
                    iterator(x.value, function (err, v) {
                        results[x.index] = v;
                        callback(err);
                    });
                }, function (err) {
                    callback(err, results);
                });
            }
        };
        async.map = doParallel(_asyncMap);
        async.mapSeries = doSeries(_asyncMap);
        async.mapLimit = function (arr, limit, iterator, callback) {
            return _mapLimit(limit)(arr, iterator, callback);
        };
    
        var _mapLimit = function(limit) {
            return doParallelLimit(limit, _asyncMap);
        };
    
        // reduce only has a series version, as doing reduce in parallel won't
        // work in many situations.
        async.reduce = function (arr, memo, iterator, callback) {
            async.eachSeries(arr, function (x, callback) {
                iterator(memo, x, function (err, v) {
                    memo = v;
                    callback(err);
                });
            }, function (err) {
                callback(err, memo);
            });
        };
        // inject alias
        async.inject = async.reduce;
        // foldl alias
        async.foldl = async.reduce;
    
        async.reduceRight = function (arr, memo, iterator, callback) {
            var reversed = _map(arr, function (x) {
                return x;
            }).reverse();
            async.reduce(reversed, memo, iterator, callback);
        };
        // foldr alias
        async.foldr = async.reduceRight;
    
        var _filter = function (eachfn, arr, iterator, callback) {
            var results = [];
            arr = _map(arr, function (x, i) {
                return {index: i, value: x};
            });
            eachfn(arr, function (x, callback) {
                iterator(x.value, function (v) {
                    if (v) {
                        results.push(x);
                    }
                    callback();
                });
            }, function (err) {
                callback(_map(results.sort(function (a, b) {
                    return a.index - b.index;
                }), function (x) {
                    return x.value;
                }));
            });
        };
        async.filter = doParallel(_filter);
        async.filterSeries = doSeries(_filter);
        // select alias
        async.select = async.filter;
        async.selectSeries = async.filterSeries;
    
        var _reject = function (eachfn, arr, iterator, callback) {
            var results = [];
            arr = _map(arr, function (x, i) {
                return {index: i, value: x};
            });
            eachfn(arr, function (x, callback) {
                iterator(x.value, function (v) {
                    if (!v) {
                        results.push(x);
                    }
                    callback();
                });
            }, function (err) {
                callback(_map(results.sort(function (a, b) {
                    return a.index - b.index;
                }), function (x) {
                    return x.value;
                }));
            });
        };
        async.reject = doParallel(_reject);
        async.rejectSeries = doSeries(_reject);
    
        var _detect = function (eachfn, arr, iterator, main_callback) {
            eachfn(arr, function (x, callback) {
                iterator(x, function (result) {
                    if (result) {
                        main_callback(x);
                        main_callback = function () {};
                    }
                    else {
                        callback();
                    }
                });
            }, function (err) {
                main_callback();
            });
        };
        async.detect = doParallel(_detect);
        async.detectSeries = doSeries(_detect);
    
        async.some = function (arr, iterator, main_callback) {
            async.each(arr, function (x, callback) {
                iterator(x, function (v) {
                    if (v) {
                        main_callback(true);
                        main_callback = function () {};
                    }
                    callback();
                });
            }, function (err) {
                main_callback(false);
            });
        };
        // any alias
        async.any = async.some;
    
        async.every = function (arr, iterator, main_callback) {
            async.each(arr, function (x, callback) {
                iterator(x, function (v) {
                    if (!v) {
                        main_callback(false);
                        main_callback = function () {};
                    }
                    callback();
                });
            }, function (err) {
                main_callback(true);
            });
        };
        // all alias
        async.all = async.every;
    
        async.sortBy = function (arr, iterator, callback) {
            async.map(arr, function (x, callback) {
                iterator(x, function (err, criteria) {
                    if (err) {
                        callback(err);
                    }
                    else {
                        callback(null, {value: x, criteria: criteria});
                    }
                });
            }, function (err, results) {
                if (err) {
                    return callback(err);
                }
                else {
                    var fn = function (left, right) {
                        var a = left.criteria, b = right.criteria;
                        return a < b ? -1 : a > b ? 1 : 0;
                    };
                    callback(null, _map(results.sort(fn), function (x) {
                        return x.value;
                    }));
                }
            });
        };
    
        async.auto = function (tasks, callback) {
            callback = callback || function () {};
            var keys = _keys(tasks);
            var remainingTasks = keys.length
            if (!remainingTasks) {
                return callback();
            }
    
            var results = {};
    
            var listeners = [];
            var addListener = function (fn) {
                listeners.unshift(fn);
            };
            var removeListener = function (fn) {
                for (var i = 0; i < listeners.length; i += 1) {
                    if (listeners[i] === fn) {
                        listeners.splice(i, 1);
                        return;
                    }
                }
            };
            var taskComplete = function () {
                remainingTasks--
                _each(listeners.slice(0), function (fn) {
                    fn();
                });
            };
    
            addListener(function () {
                if (!remainingTasks) {
                    var theCallback = callback;
                    // prevent final callback from calling itself if it errors
                    callback = function () {};
    
                    theCallback(null, results);
                }
            });
    
            _each(keys, function (k) {
                var task = _isArray(tasks[k]) ? tasks[k]: [tasks[k]];
                var taskCallback = function (err) {
                    var args = Array.prototype.slice.call(arguments, 1);
                    if (args.length <= 1) {
                        args = args[0];
                    }
                    if (err) {
                        var safeResults = {};
                        _each(_keys(results), function(rkey) {
                            safeResults[rkey] = results[rkey];
                        });
                        safeResults[k] = args;
                        callback(err, safeResults);
                        // stop subsequent errors hitting callback multiple times
                        callback = function () {};
                    }
                    else {
                        results[k] = args;
                        async.setImmediate(taskComplete);
                    }
                };
                var requires = task.slice(0, Math.abs(task.length - 1)) || [];
                var ready = function () {
                    return _reduce(requires, function (a, x) {
                        return (a && results.hasOwnProperty(x));
                    }, true) && !results.hasOwnProperty(k);
                };
                if (ready()) {
                    task[task.length - 1](taskCallback, results);
                }
                else {
                    var listener = function () {
                        if (ready()) {
                            removeListener(listener);
                            task[task.length - 1](taskCallback, results);
                        }
                    };
                    addListener(listener);
                }
            });
        };
    
        async.retry = function(times, task, callback) {
            var DEFAULT_TIMES = 5;
            var attempts = [];
            // Use defaults if times not passed
            if (typeof times === 'function') {
                callback = task;
                task = times;
                times = DEFAULT_TIMES;
            }
            // Make sure times is a number
            times = parseInt(times, 10) || DEFAULT_TIMES;
            var wrappedTask = function(wrappedCallback, wrappedResults) {
                var retryAttempt = function(task, finalAttempt) {
                    return function(seriesCallback) {
                        task(function(err, result){
                            seriesCallback(!err || finalAttempt, {err: err, result: result});
                        }, wrappedResults);
                    };
                };
                while (times) {
                    attempts.push(retryAttempt(task, !(times-=1)));
                }
                async.series(attempts, function(done, data){
                    data = data[data.length - 1];
                    (wrappedCallback || callback)(data.err, data.result);
                });
            }
            // If a callback is passed, run this as a controll flow
            return callback ? wrappedTask() : wrappedTask
        };
    
        async.waterfall = function (tasks, callback) {
            callback = callback || function () {};
            if (!_isArray(tasks)) {
              var err = new Error('First argument to waterfall must be an array of functions');
              return callback(err);
            }
            if (!tasks.length) {
                return callback();
            }
            var wrapIterator = function (iterator) {
                return function (err) {
                    if (err) {
                        callback.apply(null, arguments);
                        callback = function () {};
                    }
                    else {
                        var args = Array.prototype.slice.call(arguments, 1);
                        var next = iterator.next();
                        if (next) {
                            args.push(wrapIterator(next));
                        }
                        else {
                            args.push(callback);
                        }
                        async.setImmediate(function () {
                            iterator.apply(null, args);
                        });
                    }
                };
            };
            wrapIterator(async.iterator(tasks))();
        };
    
        var _parallel = function(eachfn, tasks, callback) {
            callback = callback || function () {};
            if (_isArray(tasks)) {
                eachfn.map(tasks, function (fn, callback) {
                    if (fn) {
                        fn(function (err) {
                            var args = Array.prototype.slice.call(arguments, 1);
                            if (args.length <= 1) {
                                args = args[0];
                            }
                            callback.call(null, err, args);
                        });
                    }
                }, callback);
            }
            else {
                var results = {};
                eachfn.each(_keys(tasks), function (k, callback) {
                    tasks[k](function (err) {
                        var args = Array.prototype.slice.call(arguments, 1);
                        if (args.length <= 1) {
                            args = args[0];
                        }
                        results[k] = args;
                        callback(err);
                    });
                }, function (err) {
                    callback(err, results);
                });
            }
        };
    
        async.parallel = function (tasks, callback) {
            _parallel({ map: async.map, each: async.each }, tasks, callback);
        };
    
        async.parallelLimit = function(tasks, limit, callback) {
            _parallel({ map: _mapLimit(limit), each: _eachLimit(limit) }, tasks, callback);
        };
    
        async.series = function (tasks, callback) {
            callback = callback || function () {};
            if (_isArray(tasks)) {
                async.mapSeries(tasks, function (fn, callback) {
                    if (fn) {
                        fn(function (err) {
                            var args = Array.prototype.slice.call(arguments, 1);
                            if (args.length <= 1) {
                                args = args[0];
                            }
                            callback.call(null, err, args);
                        });
                    }
                }, callback);
            }
            else {
                var results = {};
                async.eachSeries(_keys(tasks), function (k, callback) {
                    tasks[k](function (err) {
                        var args = Array.prototype.slice.call(arguments, 1);
                        if (args.length <= 1) {
                            args = args[0];
                        }
                        results[k] = args;
                        callback(err);
                    });
                }, function (err) {
                    callback(err, results);
                });
            }
        };
    
        async.iterator = function (tasks) {
            var makeCallback = function (index) {
                var fn = function () {
                    if (tasks.length) {
                        tasks[index].apply(null, arguments);
                    }
                    return fn.next();
                };
                fn.next = function () {
                    return (index < tasks.length - 1) ? makeCallback(index + 1): null;
                };
                return fn;
            };
            return makeCallback(0);
        };
    
        async.apply = function (fn) {
            var args = Array.prototype.slice.call(arguments, 1);
            return function () {
                return fn.apply(
                    null, args.concat(Array.prototype.slice.call(arguments))
                );
            };
        };
    
        var _concat = function (eachfn, arr, fn, callback) {
            var r = [];
            eachfn(arr, function (x, cb) {
                fn(x, function (err, y) {
                    r = r.concat(y || []);
                    cb(err);
                });
            }, function (err) {
                callback(err, r);
            });
        };
        async.concat = doParallel(_concat);
        async.concatSeries = doSeries(_concat);
    
        async.whilst = function (test, iterator, callback) {
            if (test()) {
                iterator(function (err) {
                    if (err) {
                        return callback(err);
                    }
                    async.whilst(test, iterator, callback);
                });
            }
            else {
                callback();
            }
        };
    
        async.doWhilst = function (iterator, test, callback) {
            iterator(function (err) {
                if (err) {
                    return callback(err);
                }
                var args = Array.prototype.slice.call(arguments, 1);
                if (test.apply(null, args)) {
                    async.doWhilst(iterator, test, callback);
                }
                else {
                    callback();
                }
            });
        };
    
        async.until = function (test, iterator, callback) {
            if (!test()) {
                iterator(function (err) {
                    if (err) {
                        return callback(err);
                    }
                    async.until(test, iterator, callback);
                });
            }
            else {
                callback();
            }
        };
    
        async.doUntil = function (iterator, test, callback) {
            iterator(function (err) {
                if (err) {
                    return callback(err);
                }
                var args = Array.prototype.slice.call(arguments, 1);
                if (!test.apply(null, args)) {
                    async.doUntil(iterator, test, callback);
                }
                else {
                    callback();
                }
            });
        };
    
        async.queue = function (worker, concurrency) {
            if (concurrency === undefined) {
                concurrency = 1;
            }
            function _insert(q, data, pos, callback) {
              if (!q.started){
                q.started = true;
              }
              if (!_isArray(data)) {
                  data = [data];
              }
              if(data.length == 0) {
                 // call drain immediately if there are no tasks
                 return async.setImmediate(function() {
                     if (q.drain) {
                         q.drain();
                     }
                 });
              }
              _each(data, function(task) {
                  var item = {
                      data: task,
                      callback: typeof callback === 'function' ? callback : null
                  };
    
                  if (pos) {
                    q.tasks.unshift(item);
                  } else {
                    q.tasks.push(item);
                  }
    
                  if (q.saturated && q.tasks.length === q.concurrency) {
                      q.saturated();
                  }
                  async.setImmediate(q.process);
              });
            }
    
            var workers = 0;
            var q = {
                tasks: [],
                concurrency: concurrency,
                saturated: null,
                empty: null,
                drain: null,
                started: false,
                paused: false,
                push: function (data, callback) {
                  _insert(q, data, false, callback);
                },
                kill: function () {
                  q.drain = null;
                  q.tasks = [];
                },
                unshift: function (data, callback) {
                  _insert(q, data, true, callback);
                },
                process: function () {
                    if (!q.paused && workers < q.concurrency && q.tasks.length) {
                        var task = q.tasks.shift();
                        if (q.empty && q.tasks.length === 0) {
                            q.empty();
                        }
                        workers += 1;
                        var next = function () {
                            workers -= 1;
                            if (task.callback) {
                                task.callback.apply(task, arguments);
                            }
                            if (q.drain && q.tasks.length + workers === 0) {
                                q.drain();
                            }
                            q.process();
                        };
                        var cb = only_once(next);
                        worker(task.data, cb);
                    }
                },
                length: function () {
                    return q.tasks.length;
                },
                running: function () {
                    return workers;
                },
                idle: function() {
                    return q.tasks.length + workers === 0;
                },
                pause: function () {
                    if (q.paused === true) { return; }
                    q.paused = true;
                    q.process();
                },
                resume: function () {
                    if (q.paused === false) { return; }
                    q.paused = false;
                    q.process();
                }
            };
            return q;
        };
        
        async.priorityQueue = function (worker, concurrency) {
            
            function _compareTasks(a, b){
              return a.priority - b.priority;
            };
            
            function _binarySearch(sequence, item, compare) {
              var beg = -1,
                  end = sequence.length - 1;
              while (beg < end) {
                var mid = beg + ((end - beg + 1) >>> 1);
                if (compare(item, sequence[mid]) >= 0) {
                  beg = mid;
                } else {
                  end = mid - 1;
                }
              }
              return beg;
            }
            
            function _insert(q, data, priority, callback) {
              if (!q.started){
                q.started = true;
              }
              if (!_isArray(data)) {
                  data = [data];
              }
              if(data.length == 0) {
                 // call drain immediately if there are no tasks
                 return async.setImmediate(function() {
                     if (q.drain) {
                         q.drain();
                     }
                 });
              }
              _each(data, function(task) {
                  var item = {
                      data: task,
                      priority: priority,
                      callback: typeof callback === 'function' ? callback : null
                  };
                  
                  q.tasks.splice(_binarySearch(q.tasks, item, _compareTasks) + 1, 0, item);
    
                  if (q.saturated && q.tasks.length === q.concurrency) {
                      q.saturated();
                  }
                  async.setImmediate(q.process);
              });
            }
            
            // Start with a normal queue
            var q = async.queue(worker, concurrency);
            
            // Override push to accept second parameter representing priority
            q.push = function (data, priority, callback) {
              _insert(q, data, priority, callback);
            };
            
            // Remove unshift function
            delete q.unshift;
    
            return q;
        };
    
        async.cargo = function (worker, payload) {
            var working     = false,
                tasks       = [];
    
            var cargo = {
                tasks: tasks,
                payload: payload,
                saturated: null,
                empty: null,
                drain: null,
                drained: true,
                push: function (data, callback) {
                    if (!_isArray(data)) {
                        data = [data];
                    }
                    _each(data, function(task) {
                        tasks.push({
                            data: task,
                            callback: typeof callback === 'function' ? callback : null
                        });
                        cargo.drained = false;
                        if (cargo.saturated && tasks.length === payload) {
                            cargo.saturated();
                        }
                    });
                    async.setImmediate(cargo.process);
                },
                process: function process() {
                    if (working) return;
                    if (tasks.length === 0) {
                        if(cargo.drain && !cargo.drained) cargo.drain();
                        cargo.drained = true;
                        return;
                    }
    
                    var ts = typeof payload === 'number'
                                ? tasks.splice(0, payload)
                                : tasks.splice(0, tasks.length);
    
                    var ds = _map(ts, function (task) {
                        return task.data;
                    });
    
                    if(cargo.empty) cargo.empty();
                    working = true;
                    worker(ds, function () {
                        working = false;
    
                        var args = arguments;
                        _each(ts, function (data) {
                            if (data.callback) {
                                data.callback.apply(null, args);
                            }
                        });
    
                        process();
                    });
                },
                length: function () {
                    return tasks.length;
                },
                running: function () {
                    return working;
                }
            };
            return cargo;
        };
    
        var _console_fn = function (name) {
            return function (fn) {
                var args = Array.prototype.slice.call(arguments, 1);
                fn.apply(null, args.concat([function (err) {
                    var args = Array.prototype.slice.call(arguments, 1);
                    if (typeof console !== 'undefined') {
                        if (err) {
                            if (console.error) {
                                console.error(err);
                            }
                        }
                        else if (console[name]) {
                            _each(args, function (x) {
                                console[name](x);
                            });
                        }
                    }
                }]));
            };
        };
        async.log = _console_fn('log');
        async.dir = _console_fn('dir');
        /*async.info = _console_fn('info');
        async.warn = _console_fn('warn');
        async.error = _console_fn('error');*/
    
        async.memoize = function (fn, hasher) {
            var memo = {};
            var queues = {};
            hasher = hasher || function (x) {
                return x;
            };
            var memoized = function () {
                var args = Array.prototype.slice.call(arguments);
                var callback = args.pop();
                var key = hasher.apply(null, args);
                if (key in memo) {
                    async.nextTick(function () {
                        callback.apply(null, memo[key]);
                    });
                }
                else if (key in queues) {
                    queues[key].push(callback);
                }
                else {
                    queues[key] = [callback];
                    fn.apply(null, args.concat([function () {
                        memo[key] = arguments;
                        var q = queues[key];
                        delete queues[key];
                        for (var i = 0, l = q.length; i < l; i++) {
                          q[i].apply(null, arguments);
                        }
                    }]));
                }
            };
            memoized.memo = memo;
            memoized.unmemoized = fn;
            return memoized;
        };
    
        async.unmemoize = function (fn) {
          return function () {
            return (fn.unmemoized || fn).apply(null, arguments);
          };
        };
    
        async.times = function (count, iterator, callback) {
            var counter = [];
            for (var i = 0; i < count; i++) {
                counter.push(i);
            }
            return async.map(counter, iterator, callback);
        };
    
        async.timesSeries = function (count, iterator, callback) {
            var counter = [];
            for (var i = 0; i < count; i++) {
                counter.push(i);
            }
            return async.mapSeries(counter, iterator, callback);
        };
    
        async.seq = function (/* functions... */) {
            var fns = arguments;
            return function () {
                var that = this;
                var args = Array.prototype.slice.call(arguments);
                var callback = args.pop();
                async.reduce(fns, args, function (newargs, fn, cb) {
                    fn.apply(that, newargs.concat([function () {
                        var err = arguments[0];
                        var nextargs = Array.prototype.slice.call(arguments, 1);
                        cb(err, nextargs);
                    }]))
                },
                function (err, results) {
                    callback.apply(that, [err].concat(results));
                });
            };
        };
    
        async.compose = function (/* functions... */) {
          return async.seq.apply(null, Array.prototype.reverse.call(arguments));
        };
    
        var _applyEach = function (eachfn, fns /*args...*/) {
            var go = function () {
                var that = this;
                var args = Array.prototype.slice.call(arguments);
                var callback = args.pop();
                return eachfn(fns, function (fn, cb) {
                    fn.apply(that, args.concat([cb]));
                },
                callback);
            };
            if (arguments.length > 2) {
                var args = Array.prototype.slice.call(arguments, 2);
                return go.apply(this, args);
            }
            else {
                return go;
            }
        };
        async.applyEach = doParallel(_applyEach);
        async.applyEachSeries = doSeries(_applyEach);
    
        async.forever = function (fn, callback) {
            function next(err) {
                if (err) {
                    if (callback) {
                        return callback(err);
                    }
                    throw err;
                }
                fn(next);
            }
            next();
        };
    
        // Node.js
        if (typeof module !== 'undefined' && module.exports) {
            module.exports = async;
        }
        // AMD / RequireJS
        else if (typeof define !== 'undefined' && define.amd) {
            define([], function () {
                return async;
            });
        }
        // included directly via <script> tag
        else {
            root.async = async;
        }
    
    }());
    
  provide("async", module.exports);
}(global));

// pakmanager:mime-db
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  /*!
     * mime-db
     * Copyright(c) 2014 Jonathan Ong
     * MIT Licensed
     */
    
    /**
     * Module exports.
     */
    
    module.exports = require('./db.json')
    
  provide("mime-db", module.exports);
}(global));

// pakmanager:punycode
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  /*! https://mths.be/punycode v1.3.2 by @mathias */
    ;(function(root) {
    
    	/** Detect free variables */
    	var freeExports = typeof exports == 'object' && exports &&
    		!exports.nodeType && exports;
    	var freeModule = typeof module == 'object' && module &&
    		!module.nodeType && module;
    	var freeGlobal = typeof global == 'object' && global;
    	if (
    		freeGlobal.global === freeGlobal ||
    		freeGlobal.window === freeGlobal ||
    		freeGlobal.self === freeGlobal
    	) {
    		root = freeGlobal;
    	}
    
    	/**
    	 * The `punycode` object.
    	 * @name punycode
    	 * @type Object
    	 */
    	var punycode,
    
    	/** Highest positive signed 32-bit float value */
    	maxInt = 2147483647, // aka. 0x7FFFFFFF or 2^31-1
    
    	/** Bootstring parameters */
    	base = 36,
    	tMin = 1,
    	tMax = 26,
    	skew = 38,
    	damp = 700,
    	initialBias = 72,
    	initialN = 128, // 0x80
    	delimiter = '-', // '\x2D'
    
    	/** Regular expressions */
    	regexPunycode = /^xn--/,
    	regexNonASCII = /[^\x20-\x7E]/, // unprintable ASCII chars + non-ASCII chars
    	regexSeparators = /[\x2E\u3002\uFF0E\uFF61]/g, // RFC 3490 separators
    
    	/** Error messages */
    	errors = {
    		'overflow': 'Overflow: input needs wider integers to process',
    		'not-basic': 'Illegal input >= 0x80 (not a basic code point)',
    		'invalid-input': 'Invalid input'
    	},
    
    	/** Convenience shortcuts */
    	baseMinusTMin = base - tMin,
    	floor = Math.floor,
    	stringFromCharCode = String.fromCharCode,
    
    	/** Temporary variable */
    	key;
    
    	/*--------------------------------------------------------------------------*/
    
    	/**
    	 * A generic error utility function.
    	 * @private
    	 * @param {String} type The error type.
    	 * @returns {Error} Throws a `RangeError` with the applicable error message.
    	 */
    	function error(type) {
    		throw RangeError(errors[type]);
    	}
    
    	/**
    	 * A generic `Array#map` utility function.
    	 * @private
    	 * @param {Array} array The array to iterate over.
    	 * @param {Function} callback The function that gets called for every array
    	 * item.
    	 * @returns {Array} A new array of values returned by the callback function.
    	 */
    	function map(array, fn) {
    		var length = array.length;
    		var result = [];
    		while (length--) {
    			result[length] = fn(array[length]);
    		}
    		return result;
    	}
    
    	/**
    	 * A simple `Array#map`-like wrapper to work with domain name strings or email
    	 * addresses.
    	 * @private
    	 * @param {String} domain The domain name or email address.
    	 * @param {Function} callback The function that gets called for every
    	 * character.
    	 * @returns {Array} A new string of characters returned by the callback
    	 * function.
    	 */
    	function mapDomain(string, fn) {
    		var parts = string.split('@');
    		var result = '';
    		if (parts.length > 1) {
    			// In email addresses, only the domain name should be punycoded. Leave
    			// the local part (i.e. everything up to `@`) intact.
    			result = parts[0] + '@';
    			string = parts[1];
    		}
    		// Avoid `split(regex)` for IE8 compatibility. See #17.
    		string = string.replace(regexSeparators, '\x2E');
    		var labels = string.split('.');
    		var encoded = map(labels, fn).join('.');
    		return result + encoded;
    	}
    
    	/**
    	 * Creates an array containing the numeric code points of each Unicode
    	 * character in the string. While JavaScript uses UCS-2 internally,
    	 * this function will convert a pair of surrogate halves (each of which
    	 * UCS-2 exposes as separate characters) into a single code point,
    	 * matching UTF-16.
    	 * @see `punycode.ucs2.encode`
    	 * @see <https://mathiasbynens.be/notes/javascript-encoding>
    	 * @memberOf punycode.ucs2
    	 * @name decode
    	 * @param {String} string The Unicode input string (UCS-2).
    	 * @returns {Array} The new array of code points.
    	 */
    	function ucs2decode(string) {
    		var output = [],
    		    counter = 0,
    		    length = string.length,
    		    value,
    		    extra;
    		while (counter < length) {
    			value = string.charCodeAt(counter++);
    			if (value >= 0xD800 && value <= 0xDBFF && counter < length) {
    				// high surrogate, and there is a next character
    				extra = string.charCodeAt(counter++);
    				if ((extra & 0xFC00) == 0xDC00) { // low surrogate
    					output.push(((value & 0x3FF) << 10) + (extra & 0x3FF) + 0x10000);
    				} else {
    					// unmatched surrogate; only append this code unit, in case the next
    					// code unit is the high surrogate of a surrogate pair
    					output.push(value);
    					counter--;
    				}
    			} else {
    				output.push(value);
    			}
    		}
    		return output;
    	}
    
    	/**
    	 * Creates a string based on an array of numeric code points.
    	 * @see `punycode.ucs2.decode`
    	 * @memberOf punycode.ucs2
    	 * @name encode
    	 * @param {Array} codePoints The array of numeric code points.
    	 * @returns {String} The new Unicode string (UCS-2).
    	 */
    	function ucs2encode(array) {
    		return map(array, function(value) {
    			var output = '';
    			if (value > 0xFFFF) {
    				value -= 0x10000;
    				output += stringFromCharCode(value >>> 10 & 0x3FF | 0xD800);
    				value = 0xDC00 | value & 0x3FF;
    			}
    			output += stringFromCharCode(value);
    			return output;
    		}).join('');
    	}
    
    	/**
    	 * Converts a basic code point into a digit/integer.
    	 * @see `digitToBasic()`
    	 * @private
    	 * @param {Number} codePoint The basic numeric code point value.
    	 * @returns {Number} The numeric value of a basic code point (for use in
    	 * representing integers) in the range `0` to `base - 1`, or `base` if
    	 * the code point does not represent a value.
    	 */
    	function basicToDigit(codePoint) {
    		if (codePoint - 48 < 10) {
    			return codePoint - 22;
    		}
    		if (codePoint - 65 < 26) {
    			return codePoint - 65;
    		}
    		if (codePoint - 97 < 26) {
    			return codePoint - 97;
    		}
    		return base;
    	}
    
    	/**
    	 * Converts a digit/integer into a basic code point.
    	 * @see `basicToDigit()`
    	 * @private
    	 * @param {Number} digit The numeric value of a basic code point.
    	 * @returns {Number} The basic code point whose value (when used for
    	 * representing integers) is `digit`, which needs to be in the range
    	 * `0` to `base - 1`. If `flag` is non-zero, the uppercase form is
    	 * used; else, the lowercase form is used. The behavior is undefined
    	 * if `flag` is non-zero and `digit` has no uppercase form.
    	 */
    	function digitToBasic(digit, flag) {
    		//  0..25 map to ASCII a..z or A..Z
    		// 26..35 map to ASCII 0..9
    		return digit + 22 + 75 * (digit < 26) - ((flag != 0) << 5);
    	}
    
    	/**
    	 * Bias adaptation function as per section 3.4 of RFC 3492.
    	 * http://tools.ietf.org/html/rfc3492#section-3.4
    	 * @private
    	 */
    	function adapt(delta, numPoints, firstTime) {
    		var k = 0;
    		delta = firstTime ? floor(delta / damp) : delta >> 1;
    		delta += floor(delta / numPoints);
    		for (/* no initialization */; delta > baseMinusTMin * tMax >> 1; k += base) {
    			delta = floor(delta / baseMinusTMin);
    		}
    		return floor(k + (baseMinusTMin + 1) * delta / (delta + skew));
    	}
    
    	/**
    	 * Converts a Punycode string of ASCII-only symbols to a string of Unicode
    	 * symbols.
    	 * @memberOf punycode
    	 * @param {String} input The Punycode string of ASCII-only symbols.
    	 * @returns {String} The resulting string of Unicode symbols.
    	 */
    	function decode(input) {
    		// Don't use UCS-2
    		var output = [],
    		    inputLength = input.length,
    		    out,
    		    i = 0,
    		    n = initialN,
    		    bias = initialBias,
    		    basic,
    		    j,
    		    index,
    		    oldi,
    		    w,
    		    k,
    		    digit,
    		    t,
    		    /** Cached calculation results */
    		    baseMinusT;
    
    		// Handle the basic code points: let `basic` be the number of input code
    		// points before the last delimiter, or `0` if there is none, then copy
    		// the first basic code points to the output.
    
    		basic = input.lastIndexOf(delimiter);
    		if (basic < 0) {
    			basic = 0;
    		}
    
    		for (j = 0; j < basic; ++j) {
    			// if it's not a basic code point
    			if (input.charCodeAt(j) >= 0x80) {
    				error('not-basic');
    			}
    			output.push(input.charCodeAt(j));
    		}
    
    		// Main decoding loop: start just after the last delimiter if any basic code
    		// points were copied; start at the beginning otherwise.
    
    		for (index = basic > 0 ? basic + 1 : 0; index < inputLength; /* no final expression */) {
    
    			// `index` is the index of the next character to be consumed.
    			// Decode a generalized variable-length integer into `delta`,
    			// which gets added to `i`. The overflow checking is easier
    			// if we increase `i` as we go, then subtract off its starting
    			// value at the end to obtain `delta`.
    			for (oldi = i, w = 1, k = base; /* no condition */; k += base) {
    
    				if (index >= inputLength) {
    					error('invalid-input');
    				}
    
    				digit = basicToDigit(input.charCodeAt(index++));
    
    				if (digit >= base || digit > floor((maxInt - i) / w)) {
    					error('overflow');
    				}
    
    				i += digit * w;
    				t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
    
    				if (digit < t) {
    					break;
    				}
    
    				baseMinusT = base - t;
    				if (w > floor(maxInt / baseMinusT)) {
    					error('overflow');
    				}
    
    				w *= baseMinusT;
    
    			}
    
    			out = output.length + 1;
    			bias = adapt(i - oldi, out, oldi == 0);
    
    			// `i` was supposed to wrap around from `out` to `0`,
    			// incrementing `n` each time, so we'll fix that now:
    			if (floor(i / out) > maxInt - n) {
    				error('overflow');
    			}
    
    			n += floor(i / out);
    			i %= out;
    
    			// Insert `n` at position `i` of the output
    			output.splice(i++, 0, n);
    
    		}
    
    		return ucs2encode(output);
    	}
    
    	/**
    	 * Converts a string of Unicode symbols (e.g. a domain name label) to a
    	 * Punycode string of ASCII-only symbols.
    	 * @memberOf punycode
    	 * @param {String} input The string of Unicode symbols.
    	 * @returns {String} The resulting Punycode string of ASCII-only symbols.
    	 */
    	function encode(input) {
    		var n,
    		    delta,
    		    handledCPCount,
    		    basicLength,
    		    bias,
    		    j,
    		    m,
    		    q,
    		    k,
    		    t,
    		    currentValue,
    		    output = [],
    		    /** `inputLength` will hold the number of code points in `input`. */
    		    inputLength,
    		    /** Cached calculation results */
    		    handledCPCountPlusOne,
    		    baseMinusT,
    		    qMinusT;
    
    		// Convert the input in UCS-2 to Unicode
    		input = ucs2decode(input);
    
    		// Cache the length
    		inputLength = input.length;
    
    		// Initialize the state
    		n = initialN;
    		delta = 0;
    		bias = initialBias;
    
    		// Handle the basic code points
    		for (j = 0; j < inputLength; ++j) {
    			currentValue = input[j];
    			if (currentValue < 0x80) {
    				output.push(stringFromCharCode(currentValue));
    			}
    		}
    
    		handledCPCount = basicLength = output.length;
    
    		// `handledCPCount` is the number of code points that have been handled;
    		// `basicLength` is the number of basic code points.
    
    		// Finish the basic string - if it is not empty - with a delimiter
    		if (basicLength) {
    			output.push(delimiter);
    		}
    
    		// Main encoding loop:
    		while (handledCPCount < inputLength) {
    
    			// All non-basic code points < n have been handled already. Find the next
    			// larger one:
    			for (m = maxInt, j = 0; j < inputLength; ++j) {
    				currentValue = input[j];
    				if (currentValue >= n && currentValue < m) {
    					m = currentValue;
    				}
    			}
    
    			// Increase `delta` enough to advance the decoder's <n,i> state to <m,0>,
    			// but guard against overflow
    			handledCPCountPlusOne = handledCPCount + 1;
    			if (m - n > floor((maxInt - delta) / handledCPCountPlusOne)) {
    				error('overflow');
    			}
    
    			delta += (m - n) * handledCPCountPlusOne;
    			n = m;
    
    			for (j = 0; j < inputLength; ++j) {
    				currentValue = input[j];
    
    				if (currentValue < n && ++delta > maxInt) {
    					error('overflow');
    				}
    
    				if (currentValue == n) {
    					// Represent delta as a generalized variable-length integer
    					for (q = delta, k = base; /* no condition */; k += base) {
    						t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
    						if (q < t) {
    							break;
    						}
    						qMinusT = q - t;
    						baseMinusT = base - t;
    						output.push(
    							stringFromCharCode(digitToBasic(t + qMinusT % baseMinusT, 0))
    						);
    						q = floor(qMinusT / baseMinusT);
    					}
    
    					output.push(stringFromCharCode(digitToBasic(q, 0)));
    					bias = adapt(delta, handledCPCountPlusOne, handledCPCount == basicLength);
    					delta = 0;
    					++handledCPCount;
    				}
    			}
    
    			++delta;
    			++n;
    
    		}
    		return output.join('');
    	}
    
    	/**
    	 * Converts a Punycode string representing a domain name or an email address
    	 * to Unicode. Only the Punycoded parts of the input will be converted, i.e.
    	 * it doesn't matter if you call it on a string that has already been
    	 * converted to Unicode.
    	 * @memberOf punycode
    	 * @param {String} input The Punycoded domain name or email address to
    	 * convert to Unicode.
    	 * @returns {String} The Unicode representation of the given Punycode
    	 * string.
    	 */
    	function toUnicode(input) {
    		return mapDomain(input, function(string) {
    			return regexPunycode.test(string)
    				? decode(string.slice(4).toLowerCase())
    				: string;
    		});
    	}
    
    	/**
    	 * Converts a Unicode string representing a domain name or an email address to
    	 * Punycode. Only the non-ASCII parts of the domain name will be converted,
    	 * i.e. it doesn't matter if you call it with a domain that's already in
    	 * ASCII.
    	 * @memberOf punycode
    	 * @param {String} input The domain name or email address to convert, as a
    	 * Unicode string.
    	 * @returns {String} The Punycode representation of the given domain name or
    	 * email address.
    	 */
    	function toASCII(input) {
    		return mapDomain(input, function(string) {
    			return regexNonASCII.test(string)
    				? 'xn--' + encode(string)
    				: string;
    		});
    	}
    
    	/*--------------------------------------------------------------------------*/
    
    	/** Define the public API */
    	punycode = {
    		/**
    		 * A string representing the current Punycode.js version number.
    		 * @memberOf punycode
    		 * @type String
    		 */
    		'version': '1.3.2',
    		/**
    		 * An object of methods to convert from JavaScript's internal character
    		 * representation (UCS-2) to Unicode code points, and back.
    		 * @see <https://mathiasbynens.be/notes/javascript-encoding>
    		 * @memberOf punycode
    		 * @type Object
    		 */
    		'ucs2': {
    			'decode': ucs2decode,
    			'encode': ucs2encode
    		},
    		'decode': decode,
    		'encode': encode,
    		'toASCII': toASCII,
    		'toUnicode': toUnicode
    	};
    
    	/** Expose `punycode` */
    	// Some AMD build optimizers, like r.js, check for specific condition patterns
    	// like the following:
    	if (
    		typeof define == 'function' &&
    		typeof define.amd == 'object' &&
    		define.amd
    	) {
    		define('punycode', function() {
    			return punycode;
    		});
    	} else if (freeExports && freeModule) {
    		if (module.exports == freeExports) { // in Node.js or RingoJS v0.8.0+
    			freeModule.exports = punycode;
    		} else { // in Narwhal or RingoJS v0.7.0-
    			for (key in punycode) {
    				punycode.hasOwnProperty(key) && (freeExports[key] = punycode[key]);
    			}
    		}
    	} else { // in Rhino or a web browser
    		root.punycode = punycode;
    	}
    
    }(this));
    
  provide("punycode", module.exports);
}(global));

// pakmanager:assert-plus
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright (c) 2012, Mark Cavage. All rights reserved.
    
    var assert = require('assert');
    var Stream = require('stream').Stream;
    var util = require('util');
    
    
    
    ///--- Globals
    
    var NDEBUG = process.env.NODE_NDEBUG || false;
    var UUID_REGEXP = /^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/;
    
    
    
    ///--- Messages
    
    var ARRAY_TYPE_REQUIRED = '%s ([%s]) required';
    var TYPE_REQUIRED = '%s (%s) is required';
    
    
    
    ///--- Internal
    
    function capitalize(str) {
            return (str.charAt(0).toUpperCase() + str.slice(1));
    }
    
    function uncapitalize(str) {
            return (str.charAt(0).toLowerCase() + str.slice(1));
    }
    
    function _() {
            return (util.format.apply(util, arguments));
    }
    
    
    function _assert(arg, type, name, stackFunc) {
            if (!NDEBUG) {
                    name = name || type;
                    stackFunc = stackFunc || _assert.caller;
                    var t = typeof (arg);
    
                    if (t !== type) {
                            throw new assert.AssertionError({
                                    message: _(TYPE_REQUIRED, name, type),
                                    actual: t,
                                    expected: type,
                                    operator: '===',
                                    stackStartFunction: stackFunc
                            });
                    }
            }
    }
    
    
    function _instanceof(arg, type, name, stackFunc) {
            if (!NDEBUG) {
                    name = name || type;
                    stackFunc = stackFunc || _instanceof.caller;
    
                    if (!(arg instanceof type)) {
                            throw new assert.AssertionError({
                                    message: _(TYPE_REQUIRED, name, type.name),
                                    actual: _getClass(arg),
                                    expected: type.name,
                                    operator: 'instanceof',
                                    stackStartFunction: stackFunc
                            });
                    }
            }
    }
    
    function _getClass(object) {
            return (Object.prototype.toString.call(object).slice(8, -1));
    };
    
    
    
    ///--- API
    
    function array(arr, type, name) {
            if (!NDEBUG) {
                    name = name || type;
    
                    if (!Array.isArray(arr)) {
                            throw new assert.AssertionError({
                                    message: _(ARRAY_TYPE_REQUIRED, name, type),
                                    actual: typeof (arr),
                                    expected: 'array',
                                    operator: 'Array.isArray',
                                    stackStartFunction: array.caller
                            });
                    }
    
                    for (var i = 0; i < arr.length; i++) {
                            _assert(arr[i], type, name, array);
                    }
            }
    }
    
    
    function bool(arg, name) {
            _assert(arg, 'boolean', name, bool);
    }
    
    
    function buffer(arg, name) {
            if (!Buffer.isBuffer(arg)) {
                    throw new assert.AssertionError({
                            message: _(TYPE_REQUIRED, name || '', 'Buffer'),
                            actual: typeof (arg),
                            expected: 'buffer',
                            operator: 'Buffer.isBuffer',
                            stackStartFunction: buffer
                    });
            }
    }
    
    
    function func(arg, name) {
            _assert(arg, 'function', name);
    }
    
    
    function number(arg, name) {
            _assert(arg, 'number', name);
            if (!NDEBUG && (isNaN(arg) || !isFinite(arg))) {
                    throw new assert.AssertionError({
                            message: _(TYPE_REQUIRED, name, 'number'),
                            actual: arg,
                            expected: 'number',
                            operator: 'isNaN',
                            stackStartFunction: number
                    });
            }
    }
    
    
    function object(arg, name) {
            _assert(arg, 'object', name);
    }
    
    
    function stream(arg, name) {
            _instanceof(arg, Stream, name);
    }
    
    
    function date(arg, name) {
            _instanceof(arg, Date, name);
    }
    
    function regexp(arg, name) {
            _instanceof(arg, RegExp, name);
    }
    
    
    function string(arg, name) {
            _assert(arg, 'string', name);
    }
    
    
    function uuid(arg, name) {
            string(arg, name);
            if (!NDEBUG && !UUID_REGEXP.test(arg)) {
                    throw new assert.AssertionError({
                            message: _(TYPE_REQUIRED, name, 'uuid'),
                            actual: 'string',
                            expected: 'uuid',
                            operator: 'test',
                            stackStartFunction: uuid
                    });
            }
    }
    
    
    ///--- Exports
    
    module.exports = {
            bool: bool,
            buffer: buffer,
            date: date,
            func: func,
            number: number,
            object: object,
            regexp: regexp,
            stream: stream,
            string: string,
            uuid: uuid
    };
    
    
    Object.keys(module.exports).forEach(function (k) {
            if (k === 'buffer')
                    return;
    
            var name = 'arrayOf' + capitalize(k);
    
            if (k === 'bool')
                    k = 'boolean';
            if (k === 'func')
                    k = 'function';
            module.exports[name] = function (arg, name) {
                    array(arg, k, name);
            };
    });
    
    Object.keys(module.exports).forEach(function (k) {
            var _name = 'optional' + capitalize(k);
            var s = uncapitalize(k.replace('arrayOf', ''));
            if (s === 'bool')
                    s = 'boolean';
            if (s === 'func')
                    s = 'function';
    
            if (k.indexOf('arrayOf') !== -1) {
              module.exports[_name] = function (arg, name) {
                      if (!NDEBUG && arg !== undefined) {
                              array(arg, s, name);
                      }
              };
            } else {
              module.exports[_name] = function (arg, name) {
                      if (!NDEBUG && arg !== undefined) {
                              _assert(arg, s, name);
                      }
              };
            }
    });
    
    
    // Reexport built-in assertions
    Object.keys(assert).forEach(function (k) {
            if (k === 'AssertionError') {
                    module.exports[k] = assert[k];
                    return;
            }
    
            module.exports[k] = function () {
                    if (!NDEBUG) {
                            assert[k].apply(assert[k], arguments);
                    }
            };
    });
    
  provide("assert-plus", module.exports);
}(global));

// pakmanager:asn1/lib/ber/types
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright 2011 Mark Cavage <mcavage@gmail.com> All rights reserved.
    
    
    module.exports = {
      EOC: 0,
      Boolean: 1,
      Integer: 2,
      BitString: 3,
      OctetString: 4,
      Null: 5,
      OID: 6,
      ObjectDescriptor: 7,
      External: 8,
      Real: 9, // float
      Enumeration: 10,
      PDV: 11,
      Utf8String: 12,
      RelativeOID: 13,
      Sequence: 16,
      Set: 17,
      NumericString: 18,
      PrintableString: 19,
      T61String: 20,
      VideotexString: 21,
      IA5String: 22,
      UTCTime: 23,
      GeneralizedTime: 24,
      GraphicString: 25,
      VisibleString: 26,
      GeneralString: 28,
      UniversalString: 29,
      CharacterString: 30,
      BMPString: 31,
      Constructor: 32,
      Context: 128
    };
    
  provide("asn1/lib/ber/types", module.exports);
}(global));

// pakmanager:asn1/lib/ber/errors
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright 2011 Mark Cavage <mcavage@gmail.com> All rights reserved.
    
    
    module.exports = {
    
      newInvalidAsn1Error: function(msg) {
        var e = new Error();
        e.name = 'InvalidAsn1Error';
        e.message = msg || '';
        return e;
      }
    
    };
    
  provide("asn1/lib/ber/errors", module.exports);
}(global));

// pakmanager:asn1/lib/ber/reader
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright 2011 Mark Cavage <mcavage@gmail.com> All rights reserved.
    
    var assert = require('assert');
    
    var ASN1 =  require('asn1/lib/ber/types');
    var errors =  require('asn1/lib/ber/errors');
    
    
    ///--- Globals
    
    var newInvalidAsn1Error = errors.newInvalidAsn1Error;
    
    
    
    ///--- API
    
    function Reader(data) {
      if (!data || !Buffer.isBuffer(data))
        throw new TypeError('data must be a node Buffer');
    
      this._buf = data;
      this._size = data.length;
    
      // These hold the "current" state
      this._len = 0;
      this._offset = 0;
    
      var self = this;
      this.__defineGetter__('length', function() { return self._len; });
      this.__defineGetter__('offset', function() { return self._offset; });
      this.__defineGetter__('remain', function() {
        return self._size - self._offset;
      });
      this.__defineGetter__('buffer', function() {
        return self._buf.slice(self._offset);
      });
    }
    
    
    /**
     * Reads a single byte and advances offset; you can pass in `true` to make this
     * a "peek" operation (i.e., get the byte, but don't advance the offset).
     *
     * @param {Boolean} peek true means don't move offset.
     * @return {Number} the next byte, null if not enough data.
     */
    Reader.prototype.readByte = function(peek) {
      if (this._size - this._offset < 1)
        return null;
    
      var b = this._buf[this._offset] & 0xff;
    
      if (!peek)
        this._offset += 1;
    
      return b;
    };
    
    
    Reader.prototype.peek = function() {
      return this.readByte(true);
    };
    
    
    /**
     * Reads a (potentially) variable length off the BER buffer.  This call is
     * not really meant to be called directly, as callers have to manipulate
     * the internal buffer afterwards.
     *
     * As a result of this call, you can call `Reader.length`, until the
     * next thing called that does a readLength.
     *
     * @return {Number} the amount of offset to advance the buffer.
     * @throws {InvalidAsn1Error} on bad ASN.1
     */
    Reader.prototype.readLength = function(offset) {
      if (offset === undefined)
        offset = this._offset;
    
      if (offset >= this._size)
        return null;
    
      var lenB = this._buf[offset++] & 0xff;
      if (lenB === null)
        return null;
    
      if ((lenB & 0x80) == 0x80) {
        lenB &= 0x7f;
    
        if (lenB == 0)
          throw newInvalidAsn1Error('Indefinite length not supported');
    
        if (lenB > 4)
          throw newInvalidAsn1Error('encoding too long');
    
        if (this._size - offset < lenB)
          return null;
    
        this._len = 0;
        for (var i = 0; i < lenB; i++)
          this._len = (this._len << 8) + (this._buf[offset++] & 0xff);
    
      } else {
        // Wasn't a variable length
        this._len = lenB;
      }
    
      return offset;
    };
    
    
    /**
     * Parses the next sequence in this BER buffer.
     *
     * To get the length of the sequence, call `Reader.length`.
     *
     * @return {Number} the sequence's tag.
     */
    Reader.prototype.readSequence = function(tag) {
      var seq = this.peek();
      if (seq === null)
        return null;
      if (tag !== undefined && tag !== seq)
        throw newInvalidAsn1Error('Expected 0x' + tag.toString(16) +
                                  ': got 0x' + seq.toString(16));
    
      var o = this.readLength(this._offset + 1); // stored in `length`
      if (o === null)
        return null;
    
      this._offset = o;
      return seq;
    };
    
    
    Reader.prototype.readInt = function() {
      return this._readTag(ASN1.Integer);
    };
    
    
    Reader.prototype.readBoolean = function() {
      return (this._readTag(ASN1.Boolean) === 0 ? false : true);
    };
    
    
    Reader.prototype.readEnumeration = function() {
      return this._readTag(ASN1.Enumeration);
    };
    
    
    Reader.prototype.readString = function(tag, retbuf) {
      if (!tag)
        tag = ASN1.OctetString;
    
      var b = this.peek();
      if (b === null)
        return null;
    
      if (b !== tag)
        throw newInvalidAsn1Error('Expected 0x' + tag.toString(16) +
                                  ': got 0x' + b.toString(16));
    
      var o = this.readLength(this._offset + 1); // stored in `length`
    
      if (o === null)
        return null;
    
      if (this.length > this._size - o)
        return null;
    
      this._offset = o;
    
      if (this.length === 0)
        return retbuf ? new Buffer(0) : '';
    
      var str = this._buf.slice(this._offset, this._offset + this.length);
      this._offset += this.length;
    
      return retbuf ? str : str.toString('utf8');
    };
    
    Reader.prototype.readOID = function(tag) {
      if (!tag)
        tag = ASN1.OID;
    
      var b = this.readString(tag, true);
      if (b === null)
        return null;
    
      var values = [];
      var value = 0;
    
      for (var i = 0; i < b.length; i++) {
        var byte = b[i] & 0xff;
    
        value <<= 7;
        value += byte & 0x7f;
        if ((byte & 0x80) == 0) {
          values.push(value);
          value = 0;
        }
      }
    
      value = values.shift();
      values.unshift(value % 40);
      values.unshift((value / 40) >> 0);
    
      return values.join('.');
    };
    
    
    Reader.prototype._readTag = function(tag) {
      assert.ok(tag !== undefined);
    
      var b = this.peek();
    
      if (b === null)
        return null;
    
      if (b !== tag)
        throw newInvalidAsn1Error('Expected 0x' + tag.toString(16) +
                                  ': got 0x' + b.toString(16));
    
      var o = this.readLength(this._offset + 1); // stored in `length`
      if (o === null)
        return null;
    
      if (this.length > 4)
        throw newInvalidAsn1Error('Integer too long: ' + this.length);
    
      if (this.length > this._size - o)
        return null;
      this._offset = o;
    
      var fb = this._buf[this._offset];
      var value = 0;
    
      for (var i = 0; i < this.length; i++) {
        value <<= 8;
        value |= (this._buf[this._offset++] & 0xff);
      }
    
      if ((fb & 0x80) == 0x80 && i !== 4)
        value -= (1 << (i * 8));
    
      return value >> 0;
    };
    
    
    
    ///--- Exported API
    
    module.exports = Reader;
    
  provide("asn1/lib/ber/reader", module.exports);
}(global));

// pakmanager:asn1/lib/ber/writer
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright 2011 Mark Cavage <mcavage@gmail.com> All rights reserved.
    
    var assert = require('assert');
    var ASN1 =  require('asn1/lib/ber/types');
    var errors =  require('asn1/lib/ber/errors');
    
    
    ///--- Globals
    
    var newInvalidAsn1Error = errors.newInvalidAsn1Error;
    
    var DEFAULT_OPTS = {
      size: 1024,
      growthFactor: 8
    };
    
    
    ///--- Helpers
    
    function merge(from, to) {
      assert.ok(from);
      assert.equal(typeof(from), 'object');
      assert.ok(to);
      assert.equal(typeof(to), 'object');
    
      var keys = Object.getOwnPropertyNames(from);
      keys.forEach(function(key) {
        if (to[key])
          return;
    
        var value = Object.getOwnPropertyDescriptor(from, key);
        Object.defineProperty(to, key, value);
      });
    
      return to;
    }
    
    
    
    ///--- API
    
    function Writer(options) {
      options = merge(DEFAULT_OPTS, options || {});
    
      this._buf = new Buffer(options.size || 1024);
      this._size = this._buf.length;
      this._offset = 0;
      this._options = options;
    
      // A list of offsets in the buffer where we need to insert
      // sequence tag/len pairs.
      this._seq = [];
    
      var self = this;
      this.__defineGetter__('buffer', function() {
        if (self._seq.length)
          throw new InvalidAsn1Error(self._seq.length + ' unended sequence(s)');
    
        return self._buf.slice(0, self._offset);
      });
    }
    
    
    Writer.prototype.writeByte = function(b) {
      if (typeof(b) !== 'number')
        throw new TypeError('argument must be a Number');
    
      this._ensure(1);
      this._buf[this._offset++] = b;
    };
    
    
    Writer.prototype.writeInt = function(i, tag) {
      if (typeof(i) !== 'number')
        throw new TypeError('argument must be a Number');
      if (typeof(tag) !== 'number')
        tag = ASN1.Integer;
    
      var sz = 4;
    
      while ((((i & 0xff800000) === 0) || ((i & 0xff800000) === 0xff800000 >> 0)) &&
             (sz > 1)) {
        sz--;
        i <<= 8;
      }
    
      if (sz > 4)
        throw new InvalidAsn1Error('BER ints cannot be > 0xffffffff');
    
      this._ensure(2 + sz);
      this._buf[this._offset++] = tag;
      this._buf[this._offset++] = sz;
    
      while (sz-- > 0) {
        this._buf[this._offset++] = ((i & 0xff000000) >>> 24);
        i <<= 8;
      }
    
    };
    
    
    Writer.prototype.writeNull = function() {
      this.writeByte(ASN1.Null);
      this.writeByte(0x00);
    };
    
    
    Writer.prototype.writeEnumeration = function(i, tag) {
      if (typeof(i) !== 'number')
        throw new TypeError('argument must be a Number');
      if (typeof(tag) !== 'number')
        tag = ASN1.Enumeration;
    
      return this.writeInt(i, tag);
    };
    
    
    Writer.prototype.writeBoolean = function(b, tag) {
      if (typeof(b) !== 'boolean')
        throw new TypeError('argument must be a Boolean');
      if (typeof(tag) !== 'number')
        tag = ASN1.Boolean;
    
      this._ensure(3);
      this._buf[this._offset++] = tag;
      this._buf[this._offset++] = 0x01;
      this._buf[this._offset++] = b ? 0xff : 0x00;
    };
    
    
    Writer.prototype.writeString = function(s, tag) {
      if (typeof(s) !== 'string')
        throw new TypeError('argument must be a string (was: ' + typeof(s) + ')');
      if (typeof(tag) !== 'number')
        tag = ASN1.OctetString;
    
      var len = Buffer.byteLength(s);
      this.writeByte(tag);
      this.writeLength(len);
      if (len) {
        this._ensure(len);
        this._buf.write(s, this._offset);
        this._offset += len;
      }
    };
    
    
    Writer.prototype.writeBuffer = function(buf, tag) {
      if (typeof(tag) !== 'number')
        throw new TypeError('tag must be a number');
      if (!Buffer.isBuffer(buf))
        throw new TypeError('argument must be a buffer');
    
      this.writeByte(tag);
      this.writeLength(buf.length);
      this._ensure(buf.length);
      buf.copy(this._buf, this._offset, 0, buf.length);
      this._offset += buf.length;
    };
    
    
    Writer.prototype.writeStringArray = function(strings) {
      if ((!strings instanceof Array))
        throw new TypeError('argument must be an Array[String]');
    
      var self = this;
      strings.forEach(function(s) {
        self.writeString(s);
      });
    };
    
    // This is really to solve DER cases, but whatever for now
    Writer.prototype.writeOID = function(s, tag) {
      if (typeof(s) !== 'string')
        throw new TypeError('argument must be a string');
      if (typeof(tag) !== 'number')
        tag = ASN1.OID;
    
      if (!/^([0-9]+\.){3,}[0-9]+$/.test(s))
        throw new Error('argument is not a valid OID string');
    
      function encodeOctet(bytes, octet) {
        if (octet < 128) {
            bytes.push(octet);
        } else if (octet < 16384) {
            bytes.push((octet >>> 7) | 0x80);
            bytes.push(octet & 0x7F);
        } else if (octet < 2097152) {
          bytes.push((octet >>> 14) | 0x80);
          bytes.push(((octet >>> 7) | 0x80) & 0xFF);
          bytes.push(octet & 0x7F);
        } else if (octet < 268435456) {
          bytes.push((octet >>> 21) | 0x80);
          bytes.push(((octet >>> 14) | 0x80) & 0xFF);
          bytes.push(((octet >>> 7) | 0x80) & 0xFF);
          bytes.push(octet & 0x7F);
        } else {
          bytes.push(((octet >>> 28) | 0x80) & 0xFF);
          bytes.push(((octet >>> 21) | 0x80) & 0xFF);
          bytes.push(((octet >>> 14) | 0x80) & 0xFF);
          bytes.push(((octet >>> 7) | 0x80) & 0xFF);
          bytes.push(octet & 0x7F);
        }
      }
    
      var tmp = s.split('.');
      var bytes = [];
      bytes.push(parseInt(tmp[0], 10) * 40 + parseInt(tmp[1], 10));
      tmp.slice(2).forEach(function(b) {
        encodeOctet(bytes, parseInt(b, 10));
      });
    
      var self = this;
      this._ensure(2 + bytes.length);
      this.writeByte(tag);
      this.writeLength(bytes.length);
      bytes.forEach(function(b) {
        self.writeByte(b);
      });
    };
    
    
    Writer.prototype.writeLength = function(len) {
      if (typeof(len) !== 'number')
        throw new TypeError('argument must be a Number');
    
      this._ensure(4);
    
      if (len <= 0x7f) {
        this._buf[this._offset++] = len;
      } else if (len <= 0xff) {
        this._buf[this._offset++] = 0x81;
        this._buf[this._offset++] = len;
      } else if (len <= 0xffff) {
        this._buf[this._offset++] = 0x82;
        this._buf[this._offset++] = len >> 8;
        this._buf[this._offset++] = len;
      } else if (len <= 0xffffff) {
        this._buf[this._offset++] = 0x83;
        this._buf[this._offset++] = len >> 16;
        this._buf[this._offset++] = len >> 8;
        this._buf[this._offset++] = len;
      } else {
        throw new InvalidAsn1ERror('Length too long (> 4 bytes)');
      }
    };
    
    Writer.prototype.startSequence = function(tag) {
      if (typeof(tag) !== 'number')
        tag = ASN1.Sequence | ASN1.Constructor;
    
      this.writeByte(tag);
      this._seq.push(this._offset);
      this._ensure(3);
      this._offset += 3;
    };
    
    
    Writer.prototype.endSequence = function() {
      var seq = this._seq.pop();
      var start = seq + 3;
      var len = this._offset - start;
    
      if (len <= 0x7f) {
        this._shift(start, len, -2);
        this._buf[seq] = len;
      } else if (len <= 0xff) {
        this._shift(start, len, -1);
        this._buf[seq] = 0x81;
        this._buf[seq + 1] = len;
      } else if (len <= 0xffff) {
        this._buf[seq] = 0x82;
        this._buf[seq + 1] = len >> 8;
        this._buf[seq + 2] = len;
      } else if (len <= 0xffffff) {
        this._shift(start, len, 1);
        this._buf[seq] = 0x83;
        this._buf[seq + 1] = len >> 16;
        this._buf[seq + 2] = len >> 8;
        this._buf[seq + 3] = len;
      } else {
        throw new InvalidAsn1Error('Sequence too long');
      }
    };
    
    
    Writer.prototype._shift = function(start, len, shift) {
      assert.ok(start !== undefined);
      assert.ok(len !== undefined);
      assert.ok(shift);
    
      this._buf.copy(this._buf, start + shift, start, start + len);
      this._offset += shift;
    };
    
    Writer.prototype._ensure = function(len) {
      assert.ok(len);
    
      if (this._size - this._offset < len) {
        var sz = this._size * this._options.growthFactor;
        if (sz - this._offset < len)
          sz += len;
    
        var buf = new Buffer(sz);
    
        this._buf.copy(buf, 0, 0, this._offset);
        this._buf = buf;
        this._size = sz;
      }
    };
    
    
    
    ///--- Exported API
    
    module.exports = Writer;
    
  provide("asn1/lib/ber/writer", module.exports);
}(global));

// pakmanager:asn1/lib/ber/index
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright 2011 Mark Cavage <mcavage@gmail.com> All rights reserved.
    
    var errors =  require('asn1/lib/ber/errors');
    var types =  require('asn1/lib/ber/types');
    
    var Reader =  require('asn1/lib/ber/reader');
    var Writer =  require('asn1/lib/ber/writer');
    
    
    ///--- Exports
    
    module.exports = {
    
      Reader: Reader,
    
      Writer: Writer
    
    };
    
    for (var t in types) {
      if (types.hasOwnProperty(t))
        module.exports[t] = types[t];
    }
    for (var e in errors) {
      if (errors.hasOwnProperty(e))
        module.exports[e] = errors[e];
    }
    
  provide("asn1/lib/ber/index", module.exports);
}(global));

// pakmanager:asn1
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright 2011 Mark Cavage <mcavage@gmail.com> All rights reserved.
    
    // If you have no idea what ASN.1 or BER is, see this:
    // ftp://ftp.rsa.com/pub/pkcs/ascii/layman.asc
    
    var Ber =  require('asn1/lib/ber/index');
    
    
    
    ///--- Exported API
    
    module.exports = {
    
      Ber: Ber,
    
      BerReader: Ber.Reader,
    
      BerWriter: Ber.Writer
    
    };
    
  provide("asn1", module.exports);
}(global));

// pakmanager:ctype/ctf.js
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  /*
     * ctf.js
     *
     * Understand and parse all of the different JSON formats of CTF data and
     * translate that into a series of node-ctype friendly pieces. The reason for
     * the abstraction is to handle different changes in the file format.
     *
     * We have to be careful here that we don't end up using a name that is already
     * a built in type.
     */
    var mod_assert = require('assert');
    var ASSERT = mod_assert.ok;
    
    var ctf_versions = [ '1.0' ];
    var ctf_entries = [ 'integer', 'float', 'typedef', 'struct' ];
    var ctf_deftypes = [ 'int8_t', 'uint8_t', 'int16_t', 'uint16_t', 'int32_t',
        'uint32_t', 'float', 'double' ];
    
    function ctfParseInteger(entry, ctype)
    {
    	var name, sign, len, type;
    
    	name = entry['name'];
    	if (!('signed' in entry['integer']))
    		throw (new Error('Malformed CTF JSON: integer missing ' +
    		    'signed value'));
    
    
    	if (!('length' in entry['integer']))
    		throw (new Error('Malformed CTF JSON: integer missing ' +
    		    'length value'));
    
    	sign = entry['integer']['signed'];
    	len = entry['integer']['length'];
    	type = null;
    
    	if (sign && len == 1)
    		type = 'int8_t';
    	else if (len == 1)
    		type = 'uint8_t';
    	else if (sign && len == 2)
    		type = 'int16_t';
    	else if (len == 2)
    		type = 'uint16_t';
    	else if (sign && len == 4)
    		type = 'int32_t';
    	else if (len == 4)
    		type = 'uint32_t';
    	else if (sign && len == 8)
    		type = 'int64_t';
    	else if (len == 8)
    		type = 'uint64_t';
    
    	if (type === null)
    		throw (new Error('Malformed CTF JSON: integer has ' +
    		    'unsupported length and sign - ' + len + '/' + sign));
    
    	/*
    	 * This means that this is the same as one of our built in types. If
    	 * that's the case defining it would be an error. So instead of trying
    	 * to typedef it, we'll return here.
    	 */
    	if (name == type)
    		return;
    
    	if (name == 'char') {
    		ASSERT(type == 'int8_t');
    		return;
    	}
    
    	ctype.typedef(name, type);
    }
    
    function ctfParseFloat(entry, ctype)
    {
    	var name, len;
    
    	name = entry['name'];
    	if (!('length' in entry['float']))
    		throw (new Error('Malformed CTF JSON: float missing ' +
    		    'length value'));
    
    	len = entry['float']['length'];
    	if (len != 4 && len != 8)
    		throw (new Error('Malformed CTF JSON: float has invalid ' +
    		    'length value'));
    
    	if (len == 4) {
    		if (name == 'float')
    			return;
    		ctype.typedef(name, 'float');
    	} else if (len == 8) {
    		if (name == 'double')
    			return;
    		ctype.typedef(name, 'double');
    	}
    }
    
    function ctfParseTypedef(entry, ctype)
    {
    	var name, type, ii;
    
    	name = entry['name'];
    	if (typeof (entry['typedef']) != 'string')
    		throw (new Error('Malformed CTF JSON: typedef value in not ' +
    		    'a string'));
    
    	type = entry['typedef'];
    
    	/*
    	 * We need to ensure that we're not looking at type that's one of our
    	 * built in types. Traditionally in C a uint32_t would be a typedef to
    	 * some kind of integer. However, those size types are built ins.
    	 */
    	for (ii = 0; ii < ctf_deftypes.length; ii++) {
    		if (name == ctf_deftypes[ii])
    			return;
    	}
    
    	ctype.typedef(name, type);
    }
    
    function ctfParseStruct(entry, ctype)
    {
    	var name, type, ii, val, index, member, push;
    
    	member = [];
    	if (!Array.isArray(entry['struct']))
    		throw (new Error('Malformed CTF JSON: struct value is not ' +
    		    'an array'));
    
    	for (ii = 0; ii < entry['struct'].length; ii++) {
    		val = entry['struct'][ii];
    		if (!('name' in val))
    			throw (new Error('Malformed CTF JSON: struct member ' +
    			    'missing name'));
    
    		if (!('type' in val))
    			throw (new Error('Malformed CTF JSON: struct member ' +
    			    'missing type'));
    
    		if (typeof (val['name']) != 'string')
    			throw (new Error('Malformed CTF JSON: struct member ' +
    			    'name isn\'t a string'));
    
    		if (typeof (val['type']) != 'string')
    			throw (new Error('Malformed CTF JSON: struct member ' +
    			    'type isn\'t a string'));
    
    		/*
    		 * CTF version 2 specifies array names as <type> [<num>] where
    		 * as node-ctype does this as <type>[<num>].
    		 */
    		name = val['name'];
    		type = val['type'];
    		index = type.indexOf(' [');
    		if (index != -1) {
    			type = type.substring(0, index) +
    			    type.substring(index + 1, type.length);
    		}
    		push = {};
    		push[name] = { 'type': type };
    		member.push(push);
    	}
    
    	name = entry['name'];
    	ctype.typedef(name, member);
    }
    
    function ctfParseEntry(entry, ctype)
    {
    	var ii, found;
    
    	if (!('name' in entry))
    		throw (new Error('Malformed CTF JSON: entry missing "name" ' +
    		    'section'));
    
    	for (ii = 0; ii < ctf_entries.length; ii++) {
    		if (ctf_entries[ii] in entry)
    			found++;
    	}
    
    	if (found === 0)
    		throw (new Error('Malformed CTF JSON: found no entries'));
    
    	if (found >= 2)
    		throw (new Error('Malformed CTF JSON: found more than one ' +
    		    'entry'));
    
    	if ('integer' in entry) {
    		ctfParseInteger(entry, ctype);
    		return;
    	}
    
    	if ('float' in entry) {
    		ctfParseFloat(entry, ctype);
    		return;
    	}
    
    	if ('typedef' in entry) {
    		ctfParseTypedef(entry, ctype);
    		return;
    	}
    
    	if ('struct' in entry) {
    		ctfParseStruct(entry, ctype);
    		return;
    	}
    
    	ASSERT(false, 'shouldn\'t reach here');
    }
    
    function ctfParseJson(json, ctype)
    {
    	var version, ii;
    
    	ASSERT(json);
    	ASSERT(ctype);
    	if (!('metadata' in json))
    		throw (new Error('Invalid CTF JSON: missing metadata section'));
    
    	if (!('ctf2json_version' in json['metadata']))
    		throw (new Error('Invalid CTF JSON: missing ctf2json_version'));
    
    	version = json['metadata']['ctf2json_version'];
    	for (ii = 0; ii < ctf_versions.length; ii++) {
    		if (ctf_versions[ii] == version)
    			break;
    	}
    
    	if (ii == ctf_versions.length)
    		throw (new Error('Unsuported ctf2json_version: ' + version));
    
    	if (!('data' in json))
    		throw (new Error('Invalid CTF JSON: missing data section'));
    
    	if (!Array.isArray(json['data']))
    		throw (new Error('Malformed CTF JSON: data section is not ' +
    		    'an array'));
    
    	for (ii = 0; ii < json['data'].length; ii++)
    		ctfParseEntry(json['data'][ii], ctype);
    }
    
    exports.ctfParseJson = ctfParseJson;
    
  provide("ctype/ctf.js", module.exports);
}(global));

// pakmanager:ctype/ctio.js
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  /*
     * rm - Feb 2011
     * ctio.js:
     *
     * A simple way to read and write simple ctypes. Of course, as you'll find the
     * code isn't as simple as it might appear. The following types are currently
     * supported in big and little endian formats:
     *
     * 	uint8_t			int8_t
     * 	uint16_t		int16_t
     * 	uint32_t		int32_t
     *	float (single precision IEEE 754)
     *	double (double precision IEEE 754)
     *
     * This is designed to work in Node and v8. It may in fact work in other
     * Javascript interpreters (that'd be pretty neat), but it hasn't been tested.
     * If you find that it does in fact work, that's pretty cool. Try and pass word
     * back to the original author.
     *
     * Note to the reader: If you're tabstop isn't set to 8, parts of this may look
     * weird.
     */
    
    /*
     * Numbers in Javascript have a secret: all numbers must be represented with an
     * IEEE-754 double. The double has a mantissa with a length of 52 bits with an
     * implicit one. Thus the range of integers that can be represented is limited
     * to the size of the mantissa, this makes reading and writing 64-bit integers
     * difficult, but far from impossible.
     *
     * Another side effect of this representation is what happens when you use the
     * bitwise operators, i.e. shift left, shift right, and, or, etc. In Javascript,
     * each operand and the result is cast to a signed 32-bit number. However, in
     * the case of >>> the values are cast to an unsigned number.
     */
    
    /*
     * A reminder on endian related issues:
     *
     * Big Endian: MSB -> First byte
     * Little Endian: MSB->Last byte
     */
    var mod_assert = require('assert');
    
    /*
     * An 8 bit unsigned integer involves doing no significant work.
     */
    function ruint8(buffer, endian, offset)
    {
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    	if (offset >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	return (buffer[offset]);
    }
    
    /*
     * For 16 bit unsigned numbers we can do all the casting that we want to do.
     */
    function rgint16(buffer, endian, offset)
    {
    	var val = 0;
    
    	if (endian == 'big') {
    		val = buffer[offset] << 8;
    		val |=  buffer[offset+1];
    	} else {
    		val = buffer[offset];
    		val |= buffer[offset+1] << 8;
    	}
    
    	return (val);
    
    }
    
    function ruint16(buffer, endian, offset)
    {
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    	if (offset + 1 >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	return (rgint16(buffer, endian, offset));
    }
    
    /*
     * Because most bitshifting is done using signed numbers, if we would go into
     * the realm where we use that 32nd bit, we'll end up going into the negative
     * range. i.e.:
     * > 200 << 24
     * -939524096
     *
     * Not the value you'd expect. To work around this, we end up having to do some
     * abuse of the JavaScript standard. in this case, we know that a >>> shift is
     * defined to cast our value to an *unsigned* 32-bit number. Because of that, we
     * use that instead to save us some additional math, though it does feel a
     * little weird and it isn't obvious as to why you woul dwant to do this at
     * first.
     */
    function rgint32(buffer, endian, offset)
    {
    	var val = 0;
    
    	if (endian == 'big') {
    		val = buffer[offset+1] << 16;
    		val |= buffer[offset+2] << 8;
    		val |= buffer[offset+3];
    		val = val + (buffer[offset] << 24 >>> 0);
    	} else {
    		val = buffer[offset+2] << 16;
    		val |= buffer[offset+1] << 8;
    		val |= buffer[offset];
    		val = val + (buffer[offset + 3] << 24 >>> 0);
    	}
    
    	return (val);
    }
    
    function ruint32(buffer, endian, offset)
    {
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    	if (offset + 3 >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	return (rgint32(buffer, endian, offset));
    }
    
    /*
     * Reads a 64-bit unsigned number. The astue observer will note that this
     * doesn't quite work. Javascript has chosen to only have numbers that can be
     * represented by a double. A double only has 52 bits of mantissa with an
     * implicit 1, thus we have up to 53 bits to represent an integer. However, 2^53
     * doesn't quite give us what we want. Isn't 53 bits enough for anyone? What
     * could you have possibly wanted to represent that was larger than that? Oh,
     * maybe a size? You mean we bypassed the 4 GB limit on file sizes, when did
     * that happen?
     *
     * To get around this egregious language issue, we're going to instead construct
     * an array of two 32 bit unsigned integers. Where arr[0] << 32 + arr[1] would
     * give the actual number. However, note that the above code probably won't
     * produce the desired results because of the way Javascript numbers are
     * doubles.
     */
    function rgint64(buffer, endian, offset)
    {
    	var val = new Array(2);
    
    	if (endian == 'big') {
    		val[0] = ruint32(buffer, endian, offset);
    		val[1] = ruint32(buffer, endian, offset+4);
    	} else {
    		val[0] = ruint32(buffer, endian, offset+4);
    		val[1] = ruint32(buffer, endian, offset);
    	}
    
    	return (val);
    }
    
    function ruint64(buffer, endian, offset)
    {
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    	if (offset + 7 >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	return (rgint64(buffer, endian, offset));
    }
    
    
    /*
     * Signed integer types, yay team! A reminder on how two's complement actually
     * works. The first bit is the signed bit, i.e. tells us whether or not the
     * number should be positive or negative. If the two's complement value is
     * positive, then we're done, as it's equivalent to the unsigned representation.
     *
     * Now if the number is positive, you're pretty much done, you can just leverage
     * the unsigned translations and return those. Unfortunately, negative numbers
     * aren't quite that straightforward.
     *
     * At first glance, one might be inclined to use the traditional formula to
     * translate binary numbers between the positive and negative values in two's
     * complement. (Though it doesn't quite work for the most negative value)
     * Mainly:
     *  - invert all the bits
     *  - add one to the result
     *
     * Of course, this doesn't quite work in Javascript. Take for example the value
     * of -128. This could be represented in 16 bits (big-endian) as 0xff80. But of
     * course, Javascript will do the following:
     *
     * > ~0xff80
     * -65409
     *
     * Whoh there, Javascript, that's not quite right. But wait, according to
     * Javascript that's perfectly correct. When Javascript ends up seeing the
     * constant 0xff80, it has no notion that it is actually a signed number. It
     * assumes that we've input the unsigned value 0xff80. Thus, when it does the
     * binary negation, it casts it into a signed value, (positive 0xff80). Then
     * when you perform binary negation on that, it turns it into a negative number.
     *
     * Instead, we're going to have to use the following general formula, that works
     * in a rather Javascript friendly way. I'm glad we don't support this kind of
     * weird numbering scheme in the kernel.
     *
     * (BIT-MAX - (unsigned)val + 1) * -1
     *
     * The astute observer, may think that this doesn't make sense for 8-bit numbers
     * (really it isn't necessary for them). However, when you get 16-bit numbers,
     * you do. Let's go back to our prior example and see how this will look:
     *
     * (0xffff - 0xff80 + 1) * -1
     * (0x007f + 1) * -1
     * (0x0080) * -1
     *
     * Doing it this way ends up allowing us to treat it appropriately in
     * Javascript. Sigh, that's really quite ugly for what should just be a few bit
     * shifts, ~ and &.
     */
    
    /*
     * Endianness doesn't matter for 8-bit signed values. We could in fact optimize
     * this case because the more traditional methods work, but for consistency,
     * we'll keep doing this the same way.
     */
    function rsint8(buffer, endian, offset)
    {
    	var neg;
    
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    	if (offset >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	neg = buffer[offset] & 0x80;
    	if (!neg)
    		return (buffer[offset]);
    
    	return ((0xff - buffer[offset] + 1) * -1);
    }
    
    /*
     * The 16-bit version requires a bit more effort. In this case, we can leverage
     * our unsigned code to generate the value we want to return.
     */
    function rsint16(buffer, endian, offset)
    {
    	var neg, val;
    
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    	if (offset + 1 >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	val = rgint16(buffer, endian, offset);
    	neg = val & 0x8000;
    	if (!neg)
    		return (val);
    
    	return ((0xffff - val + 1) * -1);
    }
    
    /*
     * We really shouldn't leverage our 32-bit code here and instead utilize the
     * fact that we know that since these are signed numbers, we can do all the
     * shifting and binary anding to generate the 32-bit number. But, for
     * consistency we'll do the same. If we want to do otherwise, we should instead
     * make the 32 bit unsigned code do the optimization. But as long as there
     * aren't floats secretly under the hood for that, we /should/ be okay.
     */
    function rsint32(buffer, endian, offset)
    {
    	var neg, val;
    
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    	if (offset + 3 >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	val = rgint32(buffer, endian, offset);
    	neg = val & 0x80000000;
    	if (!neg)
    		return (val);
    
    	return ((0xffffffff - val + 1) * -1);
    }
    
    /*
     * The signed version of this code suffers from all of the same problems of the
     * other 64 bit version.
     */
    function rsint64(buffer, endian, offset)
    {
    	var neg, val;
    
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    	if (offset + 3 >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	val = rgint64(buffer, endian, offset);
    	neg = val[0] & 0x80000000;
    
    	if (!neg)
    		return (val);
    
    	val[0] = (0xffffffff - val[0]) * -1;
    	val[1] = (0xffffffff - val[1] + 1) * -1;
    
    	/*
    	 * If we had the key 0x8000000000000000, that would leave the lower 32
    	 * bits as 0xffffffff, however, since we're goint to add one, that would
    	 * actually leave the lower 32-bits as 0x100000000, which would break
    	 * our ability to write back a value that we received. To work around
    	 * this, if we actually get that value, we're going to bump the upper
    	 * portion by 1 and set this to zero.
    	 */
    	mod_assert.ok(val[1] <= 0x100000000);
    	if (val[1] == -0x100000000) {
    		val[1] = 0;
    		val[0]--;
    	}
    
    	return (val);
    }
    
    /*
     * We now move onto IEEE 754: The traditional form for floating point numbers
     * and what is secretly hiding at the heart of everything in this. I really hope
     * that someone is actually using this, as otherwise, this effort is probably
     * going to be more wasted.
     *
     * One might be tempted to use parseFloat here, but that wouldn't work at all
     * for several reasons. Mostly due to the way floats actually work, and
     * parseFloat only actually works in base 10. I don't see base 10 anywhere near
     * this file.
     *
     * In this case we'll implement the single and double precision versions. The
     * quadruple precision, while probably useful, wouldn't really be accepted by
     * Javascript, so let's not even waste our time.
     *
     * So let's review how this format looks like. A single precision value is 32
     * bits and has three parts:
     *   -  Sign bit
     *   -  Exponent (Using bias notation)
     *   -  Mantissa
     *
     * |s|eeeeeeee|mmmmmmmmmmmmmmmmmmmmmmmmm|
     * 31| 30-23  |  22    	-       0       |
     *
     * The exponent is stored in a biased input. The bias in this case 127.
     * Therefore, our exponent is equal to the 8-bit value - 127.
     *
     * By default, a number is normalized in IEEE, that means that the mantissa has
     * an implicit one that we don't see. So really the value stored is 1.m.
     * However, if the exponent is all zeros, then instead we have to shift
     * everything to the right one and there is no more implicit one.
     *
     * Special values:
     *  - Positive Infinity:
     *	Sign:		0
     *	Exponent: 	All 1s
     *	Mantissa:	0
     *  - Negative Infinity:
     *	Sign:		1
     *	Exponent: 	All 1s
     *	Mantissa:	0
     *  - NaN:
     *	Sign:		*
     *	Exponent: 	All 1s
     *	Mantissa:	non-zero
     *  - Zero:
     *	Sign:		*
     *	Exponent:	All 0s
     *	Mantissa:	0
     *
     * In the case of zero, the sign bit determines whether we get a positive or
     * negative zero. However, since Javascript cannot determine the difference
     * between the two: i.e. -0 == 0, we just always return 0.
     *
     */
    function rfloat(buffer, endian, offset)
    {
    	var bytes = [];
    	var sign, exponent, mantissa, val;
    	var bias = 127;
    	var maxexp = 0xff;
    
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    	if (offset + 3 >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	/* Normalize the bytes to be in endian order */
    	if (endian == 'big') {
    		bytes[0] = buffer[offset];
    		bytes[1] = buffer[offset+1];
    		bytes[2] = buffer[offset+2];
    		bytes[3] = buffer[offset+3];
    	} else {
    		bytes[3] = buffer[offset];
    		bytes[2] = buffer[offset+1];
    		bytes[1] = buffer[offset+2];
    		bytes[0] = buffer[offset+3];
    	}
    
    	sign = bytes[0] & 0x80;
    	exponent = (bytes[0] & 0x7f) << 1;
    	exponent |= (bytes[1] & 0x80) >>> 7;
    	mantissa = (bytes[1] & 0x7f) << 16;
    	mantissa |= bytes[2] << 8;
    	mantissa |= bytes[3];
    
    	/* Check for special cases before we do general parsing */
    	if (!sign && exponent == maxexp && mantissa === 0)
    		return (Number.POSITIVE_INFINITY);
    
    	if (sign && exponent == maxexp && mantissa === 0)
    		return (Number.NEGATIVE_INFINITY);
    
    	if (exponent == maxexp && mantissa !== 0)
    		return (Number.NaN);
    
    	/*
    	 * Javascript really doesn't have support for positive or negative zero.
    	 * So we're not going to try and give it to you. That would be just
    	 * plain weird. Besides -0 == 0.
    	 */
    	if (exponent === 0 && mantissa === 0)
    		return (0);
    
    	/*
    	 * Now we can deal with the bias and the determine whether the mantissa
    	 * has the implicit one or not.
    	 */
    	exponent -= bias;
    	if (exponent == -bias) {
    		exponent++;
    		val = 0;
    	} else {
    		val = 1;
    	}
    
    	val = (val + mantissa * Math.pow(2, -23)) * Math.pow(2, exponent);
    
    	if (sign)
    		val *= -1;
    
    	return (val);
    }
    
    /*
     * Doubles in IEEE 754 are like their brothers except for a few changes and
     * increases in size:
     *   - The exponent is now 11 bits
     *   - The mantissa is now 52 bits
     *   - The bias is now 1023
     *
     * |s|eeeeeeeeeee|mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm|
     * 63| 62 - 52   | 	51		-			0     |
     * 63| 62 - 52   |      51              -                       0     |
     *
     * While the size has increased a fair amount, we're going to end up keeping the
     * same general formula for calculating the final value. As a reminder, this
     * formula is:
     *
     * (-1)^s * (n + m) * 2^(e-b)
     *
     * Where:
     *	s	is the sign bit
     *	n	is (exponent > 0) ? 1 : 0 -- Determines whether we're normalized
     *					     or not
     *	m	is the mantissa
     *	e	is the exponent specified
     *	b	is the bias for the exponent
     *
     */
    function rdouble(buffer, endian, offset)
    {
    	var bytes = [];
    	var sign, exponent, mantissa, val, lowmant;
    	var bias = 1023;
    	var maxexp = 0x7ff;
    
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    	if (offset + 7 >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	/* Normalize the bytes to be in endian order */
    	if (endian == 'big') {
    		bytes[0] = buffer[offset];
    		bytes[1] = buffer[offset+1];
    		bytes[2] = buffer[offset+2];
    		bytes[3] = buffer[offset+3];
    		bytes[4] = buffer[offset+4];
    		bytes[5] = buffer[offset+5];
    		bytes[6] = buffer[offset+6];
    		bytes[7] = buffer[offset+7];
    	} else {
    		bytes[7] = buffer[offset];
    		bytes[6] = buffer[offset+1];
    		bytes[5] = buffer[offset+2];
    		bytes[4] = buffer[offset+3];
    		bytes[3] = buffer[offset+4];
    		bytes[2] = buffer[offset+5];
    		bytes[1] = buffer[offset+6];
    		bytes[0] = buffer[offset+7];
    	}
    
    	/*
    	 * We can construct the exponent and mantissa the same way as we did in
    	 * the case of a float, just increase the range of the exponent.
    	 */
    	sign = bytes[0] & 0x80;
    	exponent = (bytes[0] & 0x7f) << 4;
    	exponent |= (bytes[1] & 0xf0) >>> 4;
    
    	/*
    	 * This is going to be ugly but then again, we're dealing with IEEE 754.
    	 * This could probably be done as a node add on in a few lines of C++,
    	 * but oh we'll, we've made it this far so let's be native the rest of
    	 * the way...
    	 *
    	 * What we're going to do is break the mantissa into two parts, the
    	 * lower 24 bits and the upper 28 bits. We'll multiply the upper 28 bits
    	 * by the appropriate power and then add in the lower 24-bits. Not
    	 * really that great. It's pretty much a giant kludge to deal with
    	 * Javascript eccentricities around numbers.
    	 */
    	lowmant = bytes[7];
    	lowmant |= bytes[6] << 8;
    	lowmant |= bytes[5] << 16;
    	mantissa = bytes[4];
    	mantissa |= bytes[3] << 8;
    	mantissa |= bytes[2] << 16;
    	mantissa |= (bytes[1] & 0x0f) << 24;
    	mantissa *= Math.pow(2, 24); /* Equivalent to << 24, but JS compat */
    	mantissa += lowmant;
    
    	/* Check for special cases before we do general parsing */
    	if (!sign && exponent == maxexp && mantissa === 0)
    		return (Number.POSITIVE_INFINITY);
    
    	if (sign && exponent == maxexp && mantissa === 0)
    		return (Number.NEGATIVE_INFINITY);
    
    	if (exponent == maxexp && mantissa !== 0)
    		return (Number.NaN);
    
    	/*
    	 * Javascript really doesn't have support for positive or negative zero.
    	 * So we're not going to try and give it to you. That would be just
    	 * plain weird. Besides -0 == 0.
    	 */
    	if (exponent === 0 && mantissa === 0)
    		return (0);
    
    	/*
    	 * Now we can deal with the bias and the determine whether the mantissa
    	 * has the implicit one or not.
    	 */
    	exponent -= bias;
    	if (exponent == -bias) {
    		exponent++;
    		val = 0;
    	} else {
    		val = 1;
    	}
    
    	val = (val + mantissa * Math.pow(2, -52)) * Math.pow(2, exponent);
    
    	if (sign)
    		val *= -1;
    
    	return (val);
    }
    
    /*
     * Now that we have gone through the pain of reading the individual types, we're
     * probably going to want some way to write these back. None of this is going to
     * be good. But since we have Javascript numbers this should certainly be more
     * interesting. Though we can constrain this end a little bit more in what is
     * valid. For now, let's go back to our friends the unsigned value.
     */
    
    /*
     * Unsigned numbers seem deceptively easy. Here are the general steps and rules
     * that we are going to take:
     *   -  If the number is negative, throw an Error
     *   -  Truncate any floating point portion
     *   -  Take the modulus of the number in our base
     *   -  Write it out to the buffer in the endian format requested at the offset
     */
    
    /*
     * We have to make sure that the value is a valid integer. This means that it is
     * non-negative. It has no fractional component and that it does not exceed the
     * maximum allowed value.
     *
     *	value		The number to check for validity
     *
     *	max		The maximum value
     */
    function prepuint(value, max)
    {
    	if (typeof (value) != 'number')
    		throw (new (Error('cannot write a non-number as a number')));
    
    	if (value < 0)
    		throw (new Error('specified a negative value for writing an ' +
    		    'unsigned value'));
    
    	if (value > max)
    		throw (new Error('value is larger than maximum value for ' +
    		    'type'));
    
    	if (Math.floor(value) !== value)
    		throw (new Error('value has a fractional component'));
    
    	return (value);
    }
    
    /*
     * 8-bit version, classy. We can ignore endianness which is good.
     */
    function wuint8(value, endian, buffer, offset)
    {
    	var val;
    
    	if (value === undefined)
    		throw (new Error('missing value'));
    
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    	if (offset >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	val = prepuint(value, 0xff);
    	buffer[offset] = val;
    }
    
    /*
     * Pretty much the same as the 8-bit version, just this time we need to worry
     * about endian related issues.
     */
    function wgint16(val, endian, buffer, offset)
    {
    	if (endian == 'big') {
    		buffer[offset] = (val & 0xff00) >>> 8;
    		buffer[offset+1] = val & 0x00ff;
    	} else {
    		buffer[offset+1] = (val & 0xff00) >>> 8;
    		buffer[offset] = val & 0x00ff;
    	}
    }
    
    function wuint16(value, endian, buffer, offset)
    {
    	var val;
    
    	if (value === undefined)
    		throw (new Error('missing value'));
    
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    	if (offset + 1 >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	val = prepuint(value, 0xffff);
    	wgint16(val, endian, buffer, offset);
    }
    
    /*
     * The 32-bit version is going to have to be a little different unfortunately.
     * We can't quite bitshift to get the largest byte, because that would end up
     * getting us caught by the signed values.
     *
     * And yes, we do want to subtract out the lower part by default. This means
     * that when we do the division, it will be treated as a bit shift and we won't
     * end up generating a floating point value. If we did generate a floating point
     * value we'd have to truncate it intelligently, this saves us that problem and
     * may even be somewhat faster under the hood.
     */
    function wgint32(val, endian, buffer, offset)
    {
    	if (endian == 'big') {
    		buffer[offset] = (val - (val & 0x00ffffff)) / Math.pow(2, 24);
    		buffer[offset+1] = (val >>> 16) & 0xff;
    		buffer[offset+2] = (val >>> 8) & 0xff;
    		buffer[offset+3] = val & 0xff;
    	} else {
    		buffer[offset+3] = (val - (val & 0x00ffffff)) /
    		    Math.pow(2, 24);
    		buffer[offset+2] = (val >>> 16) & 0xff;
    		buffer[offset+1] = (val >>> 8) & 0xff;
    		buffer[offset] = val & 0xff;
    	}
    }
    
    function wuint32(value, endian, buffer, offset)
    {
    	var val;
    
    	if (value === undefined)
    		throw (new Error('missing value'));
    
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    	if (offset + 3 >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	val = prepuint(value, 0xffffffff);
    	wgint32(val, endian, buffer, offset);
    }
    
    /*
     * Unlike the other versions, we expect the value to be in the form of two
     * arrays where value[0] << 32 + value[1] would result in the value that we
     * want.
     */
    function wgint64(value, endian, buffer, offset)
    {
    	if (endian == 'big') {
    		wgint32(value[0], endian, buffer, offset);
    		wgint32(value[1], endian, buffer, offset+4);
    	} else {
    		wgint32(value[0], endian, buffer, offset+4);
    		wgint32(value[1], endian, buffer, offset);
    	}
    }
    
    function wuint64(value, endian, buffer, offset)
    {
    	if (value === undefined)
    		throw (new Error('missing value'));
    
    	if (!(value instanceof Array))
    		throw (new Error('value must be an array'));
    
    	if (value.length != 2)
    		throw (new Error('value must be an array of length 2'));
    
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    	if (offset + 7 >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	prepuint(value[0], 0xffffffff);
    	prepuint(value[1], 0xffffffff);
    	wgint64(value, endian, buffer, offset);
    }
    
    /*
     * We now move onto our friends in the signed number category. Unlike unsigned
     * numbers, we're going to have to worry a bit more about how we put values into
     * arrays. Since we are only worrying about signed 32-bit values, we're in
     * slightly better shape. Unfortunately, we really can't do our favorite binary
     * & in this system. It really seems to do the wrong thing. For example:
     *
     * > -32 & 0xff
     * 224
     *
     * What's happening above is really: 0xe0 & 0xff = 0xe0. However, the results of
     * this aren't treated as a signed number. Ultimately a bad thing.
     *
     * What we're going to want to do is basically create the unsigned equivalent of
     * our representation and pass that off to the wuint* functions. To do that
     * we're going to do the following:
     *
     *  - if the value is positive
     *	we can pass it directly off to the equivalent wuint
     *  - if the value is negative
     *	we do the following computation:
     *	mb + val + 1, where
     *	mb	is the maximum unsigned value in that byte size
     *	val	is the Javascript negative integer
     *
     *
     * As a concrete value, take -128. In signed 16 bits this would be 0xff80. If
     * you do out the computations:
     *
     * 0xffff - 128 + 1
     * 0xffff - 127
     * 0xff80
     *
     * You can then encode this value as the signed version. This is really rather
     * hacky, but it should work and get the job done which is our goal here.
     *
     * Thus the overall flow is:
     *   -  Truncate the floating point part of the number
     *   -  We don't have to take the modulus, because the unsigned versions will
     *   	take care of that for us. And we don't have to worry about that
     *   	potentially causing bad things to happen because of sign extension
     *   -  Pass it off to the appropriate unsigned version, potentially modifying
     *	the negative portions as necessary.
     */
    
    /*
     * A series of checks to make sure we actually have a signed 32-bit number
     */
    function prepsint(value, max, min)
    {
    	if (typeof (value) != 'number')
    		throw (new (Error('cannot write a non-number as a number')));
    
    	if (value > max)
    		throw (new Error('value larger than maximum allowed value'));
    
    	if (value < min)
    		throw (new Error('value smaller than minimum allowed value'));
    
    	if (Math.floor(value) !== value)
    		throw (new Error('value has a fractional component'));
    
    	return (value);
    }
    
    /*
     * The 8-bit version of the signed value. Overall, fairly straightforward.
     */
    function wsint8(value, endian, buffer, offset)
    {
    	var val;
    
    	if (value === undefined)
    		throw (new Error('missing value'));
    
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    	if (offset >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	val = prepsint(value, 0x7f, -0x80);
    	if (val >= 0)
    		wuint8(val, endian, buffer, offset);
    	else
    		wuint8(0xff + val + 1, endian, buffer, offset);
    }
    
    /*
     * The 16-bit version of the signed value. Also, fairly straightforward.
     */
    function wsint16(value, endian, buffer, offset)
    {
    	var val;
    
    	if (value === undefined)
    		throw (new Error('missing value'));
    
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    	if (offset + 1 >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	val = prepsint(value, 0x7fff, -0x8000);
    	if (val >= 0)
    		wgint16(val, endian, buffer, offset);
    	else
    		wgint16(0xffff + val + 1, endian, buffer, offset);
    
    }
    
    /*
     * We can do this relatively easily by leveraging the code used for 32-bit
     * unsigned code.
     */
    function wsint32(value, endian, buffer, offset)
    {
    	var val;
    
    	if (value === undefined)
    		throw (new Error('missing value'));
    
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    	if (offset + 3 >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	val = prepsint(value, 0x7fffffff, -0x80000000);
    	if (val >= 0)
    		wgint32(val, endian, buffer, offset);
    	else
    		wgint32(0xffffffff + val + 1, endian, buffer, offset);
    }
    
    /*
     * The signed 64 bit integer should by in the same format as when received.
     * Mainly it should ensure that the value is an array of two integers where
     * value[0] << 32 + value[1] is the desired number. Furthermore, the two values
     * need to be equal.
     */
    function wsint64(value, endian, buffer, offset)
    {
    	var vzpos, vopos;
    	var vals = new Array(2);
    
    	if (value === undefined)
    		throw (new Error('missing value'));
    
    	if (!(value instanceof Array))
    		throw (new Error('value must be an array'));
    
    	if (value.length != 2)
    		throw (new Error('value must be an array of length 2'));
    
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    	if (offset + 7 >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	/*
    	 * We need to make sure that we have the same sign on both values. The
    	 * hokiest way to to do this is to multiply the number by +inf. If we do
    	 * this, we'll get either +/-inf depending on the sign of the value.
    	 * Once we have this, we can compare it to +inf to see if the number is
    	 * positive or not.
    	 */
    	vzpos = (value[0] * Number.POSITIVE_INFINITY) ==
    	    Number.POSITIVE_INFINITY;
    	vopos = (value[1] * Number.POSITIVE_INFINITY) ==
    	    Number.POSITIVE_INFINITY;
    
    	/*
    	 * If either of these is zero, then we don't actually need this check.
    	 */
    	if (value[0] != 0 && value[1] != 0 && vzpos != vopos)
    		throw (new Error('Both entries in the array must have ' +
    		    'the same sign'));
    
    	/*
    	 * Doing verification for a signed 64-bit integer is actually a big
    	 * trickier than it appears. We can't quite use our standard techniques
    	 * because we need to compare both sets of values. The first value is
    	 * pretty straightforward. If the first value is beond the extremes than
    	 * we error out. However, the valid range of the second value varies
    	 * based on the first one. If the first value is negative, and *not* the
    	 * largest negative value, than it can be any integer within the range [
    	 * 0, 0xffffffff ]. If it is the largest negative number, it must be
    	 * zero.
    	 *
    	 * If the first number is positive, than it doesn't matter what the
    	 * value is. We just simply have to make sure we have a valid positive
    	 * integer.
    	 */
    	if (vzpos) {
    		prepuint(value[0], 0x7fffffff);
    		prepuint(value[1], 0xffffffff);
    	} else {
    		prepsint(value[0], 0, -0x80000000);
    		prepsint(value[1], 0, -0xffffffff);
    		if (value[0] == -0x80000000 && value[1] != 0)
    			throw (new Error('value smaller than minimum ' +
    			    'allowed value'));
    	}
    
    	/* Fix negative numbers */
    	if (value[0] < 0 || value[1] < 0) {
    		vals[0] = 0xffffffff - Math.abs(value[0]);
    		vals[1] = 0x100000000 - Math.abs(value[1]);
    		if (vals[1] == 0x100000000) {
    			vals[1] = 0;
    			vals[0]++;
    		}
    	} else {
    		vals[0] = value[0];
    		vals[1] = value[1];
    	}
    	wgint64(vals, endian, buffer, offset);
    }
    
    /*
     * Now we are moving onto the weirder of these, the float and double. For this
     * we're going to just have to do something that's pretty weird. First off, we
     * have no way to get at the underlying float representation, at least not
     * easily. But that doesn't mean we can't figure it out, we just have to use our
     * heads.
     *
     * One might propose to use Number.toString(2). Of course, this is not really
     * that good, because the ECMAScript 262 v3 Standard says the following Section
     * 15.7.4.2-Number.prototype.toString (radix):
     *
     * If radix is an integer from 2 to 36, but not 10, the result is a string, the
     * choice of which is implementation-dependent.
     *
     * Well that doesn't really help us one bit now does it? We could use the
     * standard base 10 version of the string, but that's just going to create more
     * errors as we end up trying to convert it back to a binary value. So, really
     * this just means we have to be non-lazy and parse the structure intelligently.
     *
     * First off, we can do the basic checks: NaN, positive and negative infinity.
     *
     * Now that those are done we can work backwards to generate the mantissa and
     * exponent.
     *
     * The first thing we need to do is determine the sign bit, easy to do, check
     * whether the value is less than 0. And convert the number to its absolute
     * value representation. Next, we need to determine if the value is less than
     * one or greater than or equal to one and from there determine what power was
     * used to get there. What follows is now specific to floats, though the general
     * ideas behind this will hold for doubles as well, but the exact numbers
     * involved will change.
     *
     * Once we have that power we can determine the exponent and the mantissa. Call
     * the value that has the number of bits to reach the power ebits. In the
     * general case they have the following values:
     *
     *	exponent	127 + ebits
     *	mantissa	value * 2^(23 - ebits) & 0x7fffff
     *
     * In the case where the value of ebits is <= -127 we are now in the case where
     * we no longer have normalized numbers. In this case the values take on the
     * following values:
     *
     * 	exponent	0
     *	mantissa	value * 2^149 & 0x7fffff
     *
     * Once we have the values for the sign, mantissa, and exponent. We reconstruct
     * the four bytes as follows:
     *
     *	byte0		sign bit and seven most significant bits from the exp
     *			sign << 7 | (exponent & 0xfe) >>> 1
     *
     *	byte1		lsb from the exponent and 7 top bits from the mantissa
     *			(exponent & 0x01) << 7 | (mantissa & 0x7f0000) >>> 16
     *
     *	byte2		bits 8-15 (zero indexing) from mantissa
     *			mantissa & 0xff00 >> 8
     *
     *	byte3		bits 0-7 from mantissa
     *			mantissa & 0xff
     *
     * Once we have this we have to assign them into the buffer in proper endian
     * order.
     */
    
    /*
     * Compute the log base 2 of the value. Now, someone who remembers basic
     * properties of logarithms will point out that we could use the change of base
     * formula for logs, and in fact that would be astute, because that's what we'll
     * do for now. It feels cleaner, albeit it may be less efficient than just
     * iterating and dividing by 2. We may want to come back and revisit that some
     * day.
     */
    function log2(value)
    {
    	return (Math.log(value) / Math.log(2));
    }
    
    /*
     * Helper to determine the exponent of the number we're looking at.
     */
    function intexp(value)
    {
    	return (Math.floor(log2(value)));
    }
    
    /*
     * Helper to determine the exponent of the fractional part of the value.
     */
    function fracexp(value)
    {
    	return (Math.floor(log2(value)));
    }
    
    function wfloat(value, endian, buffer, offset)
    {
    	var sign, exponent, mantissa, ebits;
    	var bytes = [];
    
    	if (value === undefined)
    		throw (new Error('missing value'));
    
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    
    	if (offset + 3 >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	if (isNaN(value)) {
    		sign = 0;
    		exponent = 0xff;
    		mantissa = 23;
    	} else if (value == Number.POSITIVE_INFINITY) {
    		sign = 0;
    		exponent = 0xff;
    		mantissa = 0;
    	} else if (value == Number.NEGATIVE_INFINITY) {
    		sign = 1;
    		exponent = 0xff;
    		mantissa = 0;
    	} else {
    		/* Well we have some work to do */
    
    		/* Thankfully the sign bit is trivial */
    		if (value < 0) {
    			sign = 1;
    			value = Math.abs(value);
    		} else {
    			sign = 0;
    		}
    
    		/* Use the correct function to determine number of bits */
    		if (value < 1)
    			ebits = fracexp(value);
    		else
    			ebits = intexp(value);
    
    		/* Time to deal with the issues surrounding normalization */
    		if (ebits <= -127) {
    			exponent = 0;
    			mantissa = (value * Math.pow(2, 149)) & 0x7fffff;
    		} else {
    			exponent = 127 + ebits;
    			mantissa = value * Math.pow(2, 23 - ebits);
    			mantissa &= 0x7fffff;
    		}
    	}
    
    	bytes[0] = sign << 7 | (exponent & 0xfe) >>> 1;
    	bytes[1] = (exponent & 0x01) << 7 | (mantissa & 0x7f0000) >>> 16;
    	bytes[2] = (mantissa & 0x00ff00) >>> 8;
    	bytes[3] = mantissa & 0x0000ff;
    
    	if (endian == 'big') {
    		buffer[offset] = bytes[0];
    		buffer[offset+1] = bytes[1];
    		buffer[offset+2] = bytes[2];
    		buffer[offset+3] = bytes[3];
    	} else {
    		buffer[offset] = bytes[3];
    		buffer[offset+1] = bytes[2];
    		buffer[offset+2] = bytes[1];
    		buffer[offset+3] = bytes[0];
    	}
    }
    
    /*
     * Now we move onto doubles. Doubles are similar to floats in pretty much all
     * ways except that the processing isn't quite as straightforward because we
     * can't always use shifting, i.e. we have > 32 bit values.
     *
     * We're going to proceed in an identical fashion to floats and utilize the same
     * helper functions. All that really is changing are the specific values that we
     * use to do the calculations. Thus, to review we have to do the following.
     *
     * First get the sign bit and convert the value to its absolute value
     * representation. Next, we determine the number of bits that we used to get to
     * the value, branching whether the value is greater than or less than 1. Once
     * we have that value which we will again call ebits, we have to do the
     * following in the general case:
     *
     *	exponent	1023 + ebits
     *	mantissa	[value * 2^(52 - ebits)] % 2^52
     *
     * In the case where the value of ebits <= -1023 we no longer use normalized
     * numbers, thus like with floats we have to do slightly different processing:
     *
     *	exponent	0
     *	mantissa	[value * 2^1074] % 2^52
     *
     * Once we have determined the sign, exponent and mantissa we can construct the
     * bytes as follows:
     *
     *	byte0		sign bit and seven most significant bits form the exp
     *			sign << 7 | (exponent & 0x7f0) >>> 4
     *
     *	byte1		Remaining 4 bits from the exponent and the four most
     *			significant bits from the mantissa 48-51
     *			(exponent & 0x00f) << 4 | mantissa >>> 48
     *
     *	byte2		Bits 40-47 from the mantissa
     *			(mantissa >>> 40) & 0xff
     *
     *	byte3		Bits 32-39 from the mantissa
     *			(mantissa >>> 32) & 0xff
     *
     *	byte4		Bits 24-31 from the mantissa
     *			(mantissa >>> 24) & 0xff
     *
     *	byte5		Bits 16-23 from the Mantissa
     *			(mantissa >>> 16) & 0xff
     *
     *	byte6		Bits 8-15 from the mantissa
     *			(mantissa >>> 8) & 0xff
     *
     *	byte7		Bits 0-7 from the mantissa
     *			mantissa & 0xff
     *
     * Now we can't quite do the right shifting that we want in bytes 1 - 3, because
     * we'll have extended too far and we'll lose those values when we try and do
     * the shift. Instead we have to use an alternate approach. To try and stay out
     * of floating point, what we'll do is say that mantissa -= bytes[4-7] and then
     * divide by 2^32. Once we've done that we can use binary arithmetic. Oof,
     * that's ugly, but it seems to avoid using floating point (just based on how v8
     * seems to be optimizing for base 2 arithmetic).
     */
    function wdouble(value, endian, buffer, offset)
    {
    	var sign, exponent, mantissa, ebits;
    	var bytes = [];
    
    	if (value === undefined)
    		throw (new Error('missing value'));
    
    	if (endian === undefined)
    		throw (new Error('missing endian'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset'));
    
    
    	if (offset + 7 >= buffer.length)
    		throw (new Error('Trying to read beyond buffer length'));
    
    	if (isNaN(value)) {
    		sign = 0;
    		exponent = 0x7ff;
    		mantissa = 23;
    	} else if (value == Number.POSITIVE_INFINITY) {
    		sign = 0;
    		exponent = 0x7ff;
    		mantissa = 0;
    	} else if (value == Number.NEGATIVE_INFINITY) {
    		sign = 1;
    		exponent = 0x7ff;
    		mantissa = 0;
    	} else {
    		/* Well we have some work to do */
    
    		/* Thankfully the sign bit is trivial */
    		if (value < 0) {
    			sign = 1;
    			value = Math.abs(value);
    		} else {
    			sign = 0;
    		}
    
    		/* Use the correct function to determine number of bits */
    		if (value < 1)
    			ebits = fracexp(value);
    		else
    			ebits = intexp(value);
    
    		/*
    		 * This is a total hack to determine a denormalized value.
    		 * Unfortunately, we sometimes do not get a proper value for
    		 * ebits, i.e. we lose the values that would get rounded off.
    		 *
    		 *
    		 * The astute observer may wonder why we would be
    		 * multiplying by two Math.pows rather than just summing
    		 * them. Well, that's to get around a small bug in the
    		 * way v8 seems to implement the function. On occasion
    		 * doing:
    		 *
    		 * foo * Math.pow(2, 1023 + 51)
    		 *
    		 * Causes us to overflow to infinity, where as doing:
    		 *
    		 * foo * Math.pow(2, 1023) * Math.pow(2, 51)
    		 *
    		 * Does not cause us to overflow. Go figure.
    		 *
    		 */
    		if (value <= 2.225073858507201e-308 || ebits <= -1023) {
    			exponent = 0;
    			mantissa = value * Math.pow(2, 1023) * Math.pow(2, 51);
    			mantissa %= Math.pow(2, 52);
    		} else {
    			/*
    			 * We might have gotten fucked by our floating point
    			 * logarithm magic. This is rather crappy, but that's
    			 * our luck. If we just had a log base 2 or access to
    			 * the stupid underlying representation this would have
    			 * been much easier and we wouldn't have such stupid
    			 * kludges or hacks.
    			 */
    			if (ebits > 1023)
    				ebits = 1023;
    			exponent = 1023 + ebits;
    			mantissa = value * Math.pow(2, -ebits);
    			mantissa *= Math.pow(2, 52);
    			mantissa %= Math.pow(2, 52);
    		}
    	}
    
    	/* Fill the bytes in backwards to deal with the size issues */
    	bytes[7] = mantissa & 0xff;
    	bytes[6] = (mantissa >>> 8) & 0xff;
    	bytes[5] = (mantissa >>> 16) & 0xff;
    	mantissa = (mantissa - (mantissa & 0xffffff)) / Math.pow(2, 24);
    	bytes[4] = mantissa & 0xff;
    	bytes[3] = (mantissa >>> 8) & 0xff;
    	bytes[2] = (mantissa >>> 16) & 0xff;
    	bytes[1] = (exponent & 0x00f) << 4 | mantissa >>> 24;
    	bytes[0] = (sign << 7) | (exponent & 0x7f0) >>> 4;
    
    	if (endian == 'big') {
    		buffer[offset] = bytes[0];
    		buffer[offset+1] = bytes[1];
    		buffer[offset+2] = bytes[2];
    		buffer[offset+3] = bytes[3];
    		buffer[offset+4] = bytes[4];
    		buffer[offset+5] = bytes[5];
    		buffer[offset+6] = bytes[6];
    		buffer[offset+7] = bytes[7];
    	} else {
    		buffer[offset+7] = bytes[0];
    		buffer[offset+6] = bytes[1];
    		buffer[offset+5] = bytes[2];
    		buffer[offset+4] = bytes[3];
    		buffer[offset+3] = bytes[4];
    		buffer[offset+2] = bytes[5];
    		buffer[offset+1] = bytes[6];
    		buffer[offset] = bytes[7];
    	}
    }
    
    /*
     * Actually export our work above. One might argue that we shouldn't expose
     * these interfaces and just force people to use the higher level abstractions
     * around this work. However, unlike say other libraries we've come across, this
     * interface has several properties: it makes sense, it's simple, and it's
     * useful.
     */
    exports.ruint8 = ruint8;
    exports.ruint16 = ruint16;
    exports.ruint32 = ruint32;
    exports.ruint64 = ruint64;
    exports.wuint8 = wuint8;
    exports.wuint16 = wuint16;
    exports.wuint32 = wuint32;
    exports.wuint64 = wuint64;
    
    exports.rsint8 = rsint8;
    exports.rsint16 = rsint16;
    exports.rsint32 = rsint32;
    exports.rsint64 = rsint64;
    exports.wsint8 = wsint8;
    exports.wsint16 = wsint16;
    exports.wsint32 = wsint32;
    exports.wsint64 = wsint64;
    
    exports.rfloat = rfloat;
    exports.rdouble = rdouble;
    exports.wfloat = wfloat;
    exports.wdouble = wdouble;
    
  provide("ctype/ctio.js", module.exports);
}(global));

// pakmanager:ctype
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  /*
     * rm - Feb 2011
     * ctype.js
     *
     * This module provides a simple abstraction towards reading and writing
     * different types of binary data. It is designed to use ctio.js and provide a
     * richer and more expressive API on top of it.
     *
     * By default we support the following as built in basic types:
     *	int8_t
     *	int16_t
     *	int32_t
     *	uint8_t
     *	uint16_t
     *	uint32_t
     *	uint64_t
     *	float
     *	double
     *	char
     *	char[]
     *
     * Each type is returned as a Number, with the exception of char and char[]
     * which are returned as Node Buffers. A char is considered a uint8_t.
     *
     * Requests to read and write data are specified as an array of JSON objects.
     * This is also the same way that one declares structs. Even if just a single
     * value is requested, it must be done as a struct. The array order determines
     * the order that we try and read values. Each entry has the following format
     * with values marked with a * being optional.
     *
     * { key: { type: /type/, value*: /value/, offset*: /offset/ }
     *
     * If offset is defined, we lseek(offset, SEEK_SET) before reading the next
     * value. Value is defined when we're writing out data, otherwise it's ignored.
     *
     */
    
    var mod_ctf =  require('ctype/ctf.js');
    var mod_ctio =  require('ctype/ctio.js');
    var mod_assert = require('assert');
    
    /*
     * This is the set of basic types that we support.
     *
     *	read		The function to call to read in a value from a buffer
     *
     *	write		The function to call to write a value to a buffer
     *
     */
    var deftypes = {
        'uint8_t':  { read: ctReadUint8, write: ctWriteUint8 },
        'uint16_t': { read: ctReadUint16, write: ctWriteUint16 },
        'uint32_t': { read: ctReadUint32, write: ctWriteUint32 },
        'uint64_t': { read: ctReadUint64, write: ctWriteUint64 },
        'int8_t': { read: ctReadSint8, write: ctWriteSint8 },
        'int16_t': { read: ctReadSint16, write: ctWriteSint16 },
        'int32_t': { read: ctReadSint32, write: ctWriteSint32 },
        'int64_t': { read: ctReadSint64, write: ctWriteSint64 },
        'float': { read: ctReadFloat, write: ctWriteFloat },
        'double': { read: ctReadDouble, write: ctWriteDouble },
        'char': { read: ctReadChar, write: ctWriteChar },
        'char[]': { read: ctReadCharArray, write: ctWriteCharArray }
    };
    
    /*
     * The following are wrappers around the CType IO low level API. They encode
     * knowledge about the size and return something in the expected format.
     */
    function ctReadUint8(endian, buffer, offset)
    {
    	var val = mod_ctio.ruint8(buffer, endian, offset);
    	return ({ value: val, size: 1 });
    }
    
    function ctReadUint16(endian, buffer, offset)
    {
    	var val = mod_ctio.ruint16(buffer, endian, offset);
    	return ({ value: val, size: 2 });
    }
    
    function ctReadUint32(endian, buffer, offset)
    {
    	var val = mod_ctio.ruint32(buffer, endian, offset);
    	return ({ value: val, size: 4 });
    }
    
    function ctReadUint64(endian, buffer, offset)
    {
    	var val = mod_ctio.ruint64(buffer, endian, offset);
    	return ({ value: val, size: 8 });
    }
    
    function ctReadSint8(endian, buffer, offset)
    {
    	var val = mod_ctio.rsint8(buffer, endian, offset);
    	return ({ value: val, size: 1 });
    }
    
    function ctReadSint16(endian, buffer, offset)
    {
    	var val = mod_ctio.rsint16(buffer, endian, offset);
    	return ({ value: val, size: 2 });
    }
    
    function ctReadSint32(endian, buffer, offset)
    {
    	var val = mod_ctio.rsint32(buffer, endian, offset);
    	return ({ value: val, size: 4 });
    }
    
    function ctReadSint64(endian, buffer, offset)
    {
    	var val = mod_ctio.rsint64(buffer, endian, offset);
    	return ({ value: val, size: 8 });
    }
    
    function ctReadFloat(endian, buffer, offset)
    {
    	var val = mod_ctio.rfloat(buffer, endian, offset);
    	return ({ value: val, size: 4 });
    }
    
    function ctReadDouble(endian, buffer, offset)
    {
    	var val = mod_ctio.rdouble(buffer, endian, offset);
    	return ({ value: val, size: 8 });
    }
    
    /*
     * Reads a single character into a node buffer
     */
    function ctReadChar(endian, buffer, offset)
    {
    	var res = new Buffer(1);
    	res[0] = mod_ctio.ruint8(buffer, endian, offset);
    	return ({ value: res, size: 1 });
    }
    
    function ctReadCharArray(length, endian, buffer, offset)
    {
    	var ii;
    	var res = new Buffer(length);
    
    	for (ii = 0; ii < length; ii++)
    		res[ii] = mod_ctio.ruint8(buffer, endian, offset + ii);
    
    	return ({ value: res, size: length });
    }
    
    function ctWriteUint8(value, endian, buffer, offset)
    {
    	mod_ctio.wuint8(value, endian, buffer, offset);
    	return (1);
    }
    
    function ctWriteUint16(value, endian, buffer, offset)
    {
    	mod_ctio.wuint16(value, endian, buffer, offset);
    	return (2);
    }
    
    function ctWriteUint32(value, endian, buffer, offset)
    {
    	mod_ctio.wuint32(value, endian, buffer, offset);
    	return (4);
    }
    
    function ctWriteUint64(value, endian, buffer, offset)
    {
    	mod_ctio.wuint64(value, endian, buffer, offset);
    	return (8);
    }
    
    function ctWriteSint8(value, endian, buffer, offset)
    {
    	mod_ctio.wsint8(value, endian, buffer, offset);
    	return (1);
    }
    
    function ctWriteSint16(value, endian, buffer, offset)
    {
    	mod_ctio.wsint16(value, endian, buffer, offset);
    	return (2);
    }
    
    function ctWriteSint32(value, endian, buffer, offset)
    {
    	mod_ctio.wsint32(value, endian, buffer, offset);
    	return (4);
    }
    
    function ctWriteSint64(value, endian, buffer, offset)
    {
    	mod_ctio.wsint64(value, endian, buffer, offset);
    	return (8);
    }
    
    function ctWriteFloat(value, endian, buffer, offset)
    {
    	mod_ctio.wfloat(value, endian, buffer, offset);
    	return (4);
    }
    
    function ctWriteDouble(value, endian, buffer, offset)
    {
    	mod_ctio.wdouble(value, endian, buffer, offset);
    	return (8);
    }
    
    /*
     * Writes a single character into a node buffer
     */
    function ctWriteChar(value, endian, buffer, offset)
    {
    	if (!(value instanceof Buffer))
    		throw (new Error('Input must be a buffer'));
    
    	mod_ctio.ruint8(value[0], endian, buffer, offset);
    	return (1);
    }
    
    /*
     * We're going to write 0s into the buffer if the string is shorter than the
     * length of the array.
     */
    function ctWriteCharArray(value, length, endian, buffer, offset)
    {
    	var ii;
    
    	if (!(value instanceof Buffer))
    		throw (new Error('Input must be a buffer'));
    
    	if (value.length > length)
    		throw (new Error('value length greater than array length'));
    
    	for (ii = 0; ii < value.length && ii < length; ii++)
    		mod_ctio.wuint8(value[ii], endian, buffer, offset + ii);
    
    	for (; ii < length; ii++)
    		mod_ctio.wuint8(0, endian, offset + ii);
    
    
    	return (length);
    }
    
    /*
     * Each parser has their own set of types. We want to make sure that they each
     * get their own copy as they may need to modify it.
     */
    function ctGetBasicTypes()
    {
    	var ret = {};
    	var key;
    	for (key in deftypes)
    		ret[key] = deftypes[key];
    
    	return (ret);
    }
    
    /*
     * Given a string in the form of type[length] we want to split this into an
     * object that extracts that information. We want to note that we could possibly
     * have nested arrays so this should only check the furthest one. It may also be
     * the case that we have no [] pieces, in which case we just return the current
     * type.
     */
    function ctParseType(str)
    {
    	var begInd, endInd;
    	var type, len;
    	if (typeof (str) != 'string')
    		throw (new Error('type must be a Javascript string'));
    
    	endInd = str.lastIndexOf(']');
    	if (endInd == -1) {
    		if (str.lastIndexOf('[') != -1)
    			throw (new Error('found invalid type with \'[\' but ' +
    			    'no corresponding \']\''));
    
    		return ({ type: str });
    	}
    
    	begInd = str.lastIndexOf('[');
    	if (begInd == -1)
    		throw (new Error('found invalid type with \']\' but ' +
    		    'no corresponding \'[\''));
    
    	if (begInd >= endInd)
    		throw (new Error('malformed type, \']\' appears before \'[\''));
    
    	type = str.substring(0, begInd);
    	len = str.substring(begInd + 1, endInd);
    
    	return ({ type: type, len: len });
    }
    
    /*
     * Given a request validate that all of the fields for it are valid and make
     * sense. This includes verifying the following notions:
     *  - Each type requested is present in types
     *  - Only allow a name for a field to be specified once
     *  - If an array is specified, validate that the requested field exists and
     *    comes before it.
     *  - If fields is defined, check that each entry has the occurrence of field
     */
    function ctCheckReq(def, types, fields)
    {
    	var ii, jj;
    	var req, keys, key;
    	var found = {};
    
    	if (!(def instanceof Array))
    		throw (new Error('definition is not an array'));
    
    	if (def.length === 0)
    		throw (new Error('definition must have at least one element'));
    
    	for (ii = 0; ii < def.length; ii++) {
    		req = def[ii];
    		if (!(req instanceof Object))
    			throw (new Error('definition must be an array of' +
    			    'objects'));
    
    		keys = Object.keys(req);
    		if (keys.length != 1)
    			throw (new Error('definition entry must only have ' +
    			    'one key'));
    
    		if (keys[0] in found)
    			throw (new Error('Specified name already ' +
    			    'specified: ' + keys[0]));
    
    		if (!('type' in req[keys[0]]))
    			throw (new Error('missing required type definition'));
    
    		key = ctParseType(req[keys[0]]['type']);
    
    		/*
    		 * We may have nested arrays, we need to check the validity of
    		 * the types until the len field is undefined in key. However,
    		 * each time len is defined we need to verify it is either an
    		 * integer or corresponds to an already seen key.
    		 */
    		while (key['len'] !== undefined) {
    			if (isNaN(parseInt(key['len'], 10))) {
    				if (!(key['len'] in found))
    					throw (new Error('Given an array ' +
    					    'length without a matching type'));
    
    			}
    
    			key = ctParseType(key['type']);
    		}
    
    		/* Now we can validate if the type is valid */
    		if (!(key['type'] in types))
    			throw (new Error('type not found or typdefed: ' +
    			    key['type']));
    
    		/* Check for any required fields */
    		if (fields !== undefined) {
    			for (jj = 0; jj < fields.length; jj++) {
    				if (!(fields[jj] in req[keys[0]]))
    					throw (new Error('Missing required ' +
    					    'field: ' + fields[jj]));
    			}
    		}
    
    		found[keys[0]] = true;
    	}
    }
    
    
    /*
     * Create a new instance of the parser. Each parser has its own store of
     * typedefs and endianness. Conf is an object with the following required
     * values:
     *
     *	endian		Either 'big' or 'little' do determine the endianness we
     *			want to read from or write to.
     *
     * And the following optional values:
     *
     * 	char-type	Valid options here are uint8 and int8. If uint8 is
     * 			specified this changes the default behavior of a single
     * 			char from being a buffer of a single character to being
     * 			a uint8_t. If int8, it becomes an int8_t instead.
     */
    function CTypeParser(conf)
    {
    	if (!conf) throw (new Error('missing required argument'));
    
    	if (!('endian' in conf))
    		throw (new Error('missing required endian value'));
    
    	if (conf['endian'] != 'big' && conf['endian'] != 'little')
    		throw (new Error('Invalid endian type'));
    
    	if ('char-type' in conf && (conf['char-type'] != 'uint8' &&
    	    conf['char-type'] != 'int8'))
    		throw (new Error('invalid option for char-type: ' +
    		    conf['char-type']));
    
    	this.endian = conf['endian'];
    	this.types = ctGetBasicTypes();
    
    	/*
    	 * There may be a more graceful way to do this, but this will have to
    	 * serve.
    	 */
    	if ('char-type' in conf && conf['char-type'] == 'uint8')
    		this.types['char'] = this.types['uint8_t'];
    
    	if ('char-type' in conf && conf['char-type'] == 'int8')
    		this.types['char'] = this.types['int8_t'];
    }
    
    /*
     * Sets the current endian value for the Parser. If the value is not valid,
     * throws an Error.
     *
     *	endian		Either 'big' or 'little' do determine the endianness we
     *			want to read from or write to.
     *
     */
    CTypeParser.prototype.setEndian = function (endian)
    {
    	if (endian != 'big' && endian != 'little')
    		throw (new Error('invalid endian type, must be big or ' +
    		    'little'));
    
    	this.endian = endian;
    };
    
    /*
     * Returns the current value of the endian value for the parser.
     */
    CTypeParser.prototype.getEndian = function ()
    {
    	return (this.endian);
    };
    
    /*
     * A user has requested to add a type, let us honor their request. Yet, if their
     * request doth spurn us, send them unto the Hells which Dante describes.
     *
     * 	name		The string for the type definition we're adding
     *
     *	value		Either a string that is a type/array name or an object
     *			that describes a struct.
     */
    CTypeParser.prototype.typedef = function (name, value)
    {
    	var type;
    
    	if (name === undefined)
    		throw (new (Error('missing required typedef argument: name')));
    
    	if (value === undefined)
    		throw (new (Error('missing required typedef argument: value')));
    
    	if (typeof (name) != 'string')
    		throw (new (Error('the name of a type must be a string')));
    
    	type = ctParseType(name);
    
    	if (type['len'] !== undefined)
    		throw (new Error('Cannot have an array in the typedef name'));
    
    	if (name in this.types)
    		throw (new Error('typedef name already present: ' + name));
    
    	if (typeof (value) != 'string' && !(value instanceof Array))
    		throw (new Error('typedef value must either be a string or ' +
    		    'struct'));
    
    	if (typeof (value) == 'string') {
    		type = ctParseType(value);
    		if (type['len'] !== undefined) {
    			if (isNaN(parseInt(type['len'], 10)))
    				throw (new (Error('typedef value must use ' +
    				    'fixed size array when outside of a ' +
    				    'struct')));
    		}
    
    		this.types[name] = value;
    	} else {
    		/* We have a struct, validate it */
    		ctCheckReq(value, this.types);
    		this.types[name] = value;
    	}
    };
    
    /*
     * Include all of the typedefs, but none of the built in types. This should be
     * treated as read-only.
     */
    CTypeParser.prototype.lstypes = function ()
    {
    	var key;
    	var ret = {};
    
    	for (key in this.types) {
    		if (key in deftypes)
    			continue;
    		ret[key] = this.types[key];
    	}
    
    	return (ret);
    };
    
    /*
     * Given a type string that may have array types that aren't numbers, try and
     * fill them in from the values object. The object should be of the format where
     * indexing into it should return a number for that type.
     *
     *	str		The type string
     *
     *	values		An object that can be used to fulfill type information
     */
    function ctResolveArray(str, values)
    {
    	var ret = '';
    	var type = ctParseType(str);
    
    	while (type['len'] !== undefined) {
    		if (isNaN(parseInt(type['len'], 10))) {
    			if (typeof (values[type['len']]) != 'number')
    				throw (new Error('cannot sawp in non-number ' +
    				    'for array value'));
    			ret = '[' + values[type['len']] + ']' + ret;
    		} else {
    			ret = '[' + type['len'] + ']' + ret;
    		}
    		type = ctParseType(type['type']);
    	}
    
    	ret = type['type'] + ret;
    
    	return (ret);
    }
    
    /*
     * [private] Either the typedef resolves to another type string or to a struct.
     * If it resolves to a struct, we just pass it off to read struct. If not, we
     * can just pass it off to read entry.
     */
    CTypeParser.prototype.resolveTypedef = function (type, dispatch, buffer,
        offset, value)
    {
    	var pt;
    
    	mod_assert.ok(type in this.types);
    	if (typeof (this.types[type]) == 'string') {
    		pt = ctParseType(this.types[type]);
    		if (dispatch == 'read')
    			return (this.readEntry(pt, buffer, offset));
    		else if (dispatch == 'write')
    			return (this.writeEntry(value, pt, buffer, offset));
    		else
    			throw (new Error('invalid dispatch type to ' +
    			    'resolveTypedef'));
    	} else {
    		if (dispatch == 'read')
    			return (this.readStruct(this.types[type], buffer,
    			    offset));
    		else if (dispatch == 'write')
    			return (this.writeStruct(value, this.types[type],
    			    buffer, offset));
    		else
    			throw (new Error('invalid dispatch type to ' +
    			    'resolveTypedef'));
    	}
    
    };
    
    /*
     * [private] Try and read in the specific entry.
     */
    CTypeParser.prototype.readEntry = function (type, buffer, offset)
    {
    	var parse, len;
    
    	/*
    	 * Because we want to special case char[]s this is unfortunately
    	 * a bit uglier than it really should be. We want to special
    	 * case char[]s so that we return a node buffer, thus they are a
    	 * first class type where as all other arrays just call into a
    	 * generic array routine which calls their data-specific routine
    	 * the specified number of times.
    	 *
    	 * The valid dispatch options we have are:
    	 *  - Array and char => char[] handler
    	 *  - Generic array handler
    	 *  - Generic typedef handler
    	 *  - Basic type handler
    	 */
    	if (type['len'] !== undefined) {
    		len = parseInt(type['len'], 10);
    		if (isNaN(len))
    			throw (new Error('somehow got a non-numeric length'));
    
    		if (type['type'] == 'char')
    			parse = this.types['char[]']['read'](len,
    			    this.endian, buffer, offset);
    		else
    			parse = this.readArray(type['type'],
    			    len, buffer, offset);
    	} else {
    		if (type['type'] in deftypes)
    			parse = this.types[type['type']]['read'](this.endian,
    			    buffer, offset);
    		else
    			parse = this.resolveTypedef(type['type'], 'read',
    			    buffer, offset);
    	}
    
    	return (parse);
    };
    
    /*
     * [private] Read an array of data
     */
    CTypeParser.prototype.readArray = function (type, length, buffer, offset)
    {
    	var ii, ent, pt;
    	var baseOffset = offset;
    	var ret = new Array(length);
    	pt = ctParseType(type);
    
    	for (ii = 0; ii < length; ii++) {
    		ent = this.readEntry(pt, buffer, offset);
    		offset += ent['size'];
    		ret[ii] = ent['value'];
    	}
    
    	return ({ value: ret, size: offset - baseOffset });
    };
    
    /*
     * [private] Read a single struct in.
     */
    CTypeParser.prototype.readStruct = function (def, buffer, offset)
    {
    	var parse, ii, type, entry, key;
    	var baseOffset = offset;
    	var ret = {};
    
    	/* Walk it and handle doing what's necessary */
    	for (ii = 0; ii < def.length; ii++) {
    		key = Object.keys(def[ii])[0];
    		entry = def[ii][key];
    
    		/* Resolve all array values */
    		type = ctParseType(ctResolveArray(entry['type'], ret));
    
    		if ('offset' in entry)
    			offset = baseOffset + entry['offset'];
    
    		parse = this.readEntry(type, buffer, offset);
    
    		offset += parse['size'];
    		ret[key] = parse['value'];
    	}
    
    	return ({ value: ret, size: (offset-baseOffset)});
    };
    
    /*
     * This is what we were born to do. We read the data from a buffer and return it
     * in an object whose keys match the values from the object.
     *
     *	def		The array definition of the data to read in
     *
     *	buffer		The buffer to read data from
     *
     *	offset		The offset to start writing to
     *
     * Returns an object where each key corresponds to an entry in def and the value
     * is the read value.
     */
    CTypeParser.prototype.readData = function (def, buffer, offset)
    {
    	/* Sanity check for arguments */
    	if (def === undefined)
    		throw (new Error('missing definition for what we should be' +
    		    'parsing'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer for what we should be ' +
    		    'parsing'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset for what we should be ' +
    		    'parsing'));
    
    	/* Sanity check the object definition */
    	ctCheckReq(def, this.types);
    
    	return (this.readStruct(def, buffer, offset)['value']);
    };
    
    /*
     * [private] Write out an array of data
     */
    CTypeParser.prototype.writeArray = function (value, type, length, buffer,
        offset)
    {
    	var ii, pt;
    	var baseOffset = offset;
    	if (!(value instanceof Array))
    		throw (new Error('asked to write an array, but value is not ' +
    		    'an array'));
    
    	if (value.length != length)
    		throw (new Error('asked to write array of length ' + length +
    		    ' but that does not match value length: ' + value.length));
    
    	pt = ctParseType(type);
    	for (ii = 0; ii < length; ii++)
    		offset += this.writeEntry(value[ii], pt, buffer, offset);
    
    	return (offset - baseOffset);
    };
    
    /*
     * [private] Write the specific entry
     */
    CTypeParser.prototype.writeEntry = function (value, type, buffer, offset)
    {
    	var len, ret;
    
    	if (type['len'] !== undefined) {
    		len = parseInt(type['len'], 10);
    		if (isNaN(len))
    			throw (new Error('somehow got a non-numeric length'));
    
    		if (type['type'] == 'char')
    			ret = this.types['char[]']['write'](value, len,
    			    this.endian, buffer, offset);
    		else
    			ret = this.writeArray(value, type['type'],
    			    len, buffer, offset);
    	} else {
    		if (type['type'] in deftypes)
    			ret = this.types[type['type']]['write'](value,
    			    this.endian, buffer, offset);
    		else
    			ret = this.resolveTypedef(type['type'], 'write',
    			    buffer, offset, value);
    	}
    
    	return (ret);
    };
    
    /*
     * [private] Write a single struct out.
     */
    CTypeParser.prototype.writeStruct = function (value, def, buffer, offset)
    {
    	var ii, entry, type, key;
    	var baseOffset = offset;
    	var vals = {};
    
    	for (ii = 0; ii < def.length; ii++) {
    		key = Object.keys(def[ii])[0];
    		entry = def[ii][key];
    
    		type = ctParseType(ctResolveArray(entry['type'], vals));
    
    		if ('offset' in entry)
    			offset = baseOffset + entry['offset'];
    
    		offset += this.writeEntry(value[ii], type, buffer, offset);
    		/* Now that we've written it out, we can use it for arrays */
    		vals[key] = value[ii];
    	}
    
    	return (offset);
    };
    
    /*
     * Unfortunately, we're stuck with the sins of an initial poor design. Because
     * of that, we are going to have to support the old way of writing data via
     * writeData. There we insert the values that you want to write into the
     * definition. A little baroque. Internally, we use the new model. So we need to
     * just get those values out of there. But to maintain the principle of least
     * surprise, we're not going to modify the input data.
     */
    function getValues(def)
    {
    	var ii, out, key;
    	out = [];
    	for (ii = 0; ii < def.length; ii++) {
    		key = Object.keys(def[ii])[0];
    		mod_assert.ok('value' in def[ii][key]);
    		out.push(def[ii][key]['value']);
    	}
    
    	return (out);
    }
    
    /*
     * This is the second half of what we were born to do, write out the data
     * itself. Historically this function required you to put your values in the
     * definition section. This was not the smartest thing to do and a bit of an
     * oversight to be honest. As such, this function now takes a values argument.
     * If values is non-null and non-undefined, it will be used to determine the
     * values. This means that the old method is still supported, but is no longer
     * acceptable.
     *
     *	def		The array definition of the data to write out with
     *			values
     *
     *	buffer		The buffer to write to
     *
     *	offset		The offset in the buffer to write to
     *
     *	values		An array of values to write.
     */
    CTypeParser.prototype.writeData = function (def, buffer, offset, values)
    {
    	var hv;
    
    	if (def === undefined)
    		throw (new Error('missing definition for what we should be' +
    		    'parsing'));
    
    	if (buffer === undefined)
    		throw (new Error('missing buffer for what we should be ' +
    		    'parsing'));
    
    	if (offset === undefined)
    		throw (new Error('missing offset for what we should be ' +
    		    'parsing'));
    
    	hv = (values != null && values != undefined);
    	if (hv) {
    		if (!Array.isArray(values))
    			throw (new Error('missing values for writing'));
    		ctCheckReq(def, this.types);
    	} else {
    		ctCheckReq(def, this.types, [ 'value' ]);
    	}
    
    	this.writeStruct(hv ? values : getValues(def), def, buffer, offset);
    };
    
    /*
     * Functions to go to and from 64 bit numbers in a way that is compatible with
     * Javascript limitations. There are two sets. One where the user is okay with
     * an approximation and one where they are definitely not okay with an
     * approximation.
     */
    
    /*
     * Attempts to convert an array of two integers returned from rsint64 / ruint64
     * into an absolute 64 bit number. If however the value would exceed 2^52 this
     * will instead throw an error. The mantissa in a double is a 52 bit number and
     * rather than potentially give you a value that is an approximation this will
     * error. If you would rather an approximation, please see toApprox64.
     *
     *	val		An array of two 32-bit integers
     */
    function toAbs64(val)
    {
    	if (val === undefined)
    		throw (new Error('missing required arg: value'));
    
    	if (!Array.isArray(val))
    		throw (new Error('value must be an array'));
    
    	if (val.length != 2)
    		throw (new Error('value must be an array of length 2'));
    
    	/* We have 20 bits worth of precision in this range */
    	if (val[0] >= 0x100000)
    		throw (new Error('value would become approximated'));
    
    	return (val[0] * Math.pow(2, 32) + val[1]);
    }
    
    /*
     * Will return the 64 bit value as returned in an array from rsint64 / ruint64
     * to a value as close as it can. Note that Javascript stores all numbers as a
     * double and the mantissa only has 52 bits. Thus this version may approximate
     * the value.
     *
     *	val		An array of two 32-bit integers
     */
    function toApprox64(val)
    {
    	if (val === undefined)
    		throw (new Error('missing required arg: value'));
    
    	if (!Array.isArray(val))
    		throw (new Error('value must be an array'));
    
    	if (val.length != 2)
    		throw (new Error('value must be an array of length 2'));
    
    	return (Math.pow(2, 32) * val[0] + val[1]);
    }
    
    function parseCTF(json, conf)
    {
    	var ctype = new CTypeParser(conf);
    	mod_ctf.ctfParseJson(json, ctype);
    
    	return (ctype);
    }
    
    /*
     * Export the few things we actually want to. Currently this is just the CType
     * Parser and ctio.
     */
    exports.Parser = CTypeParser;
    exports.toAbs64 = toAbs64;
    exports.toApprox64 = toApprox64;
    
    exports.parseCTF = parseCTF;
    
    exports.ruint8 = mod_ctio.ruint8;
    exports.ruint16 = mod_ctio.ruint16;
    exports.ruint32 = mod_ctio.ruint32;
    exports.ruint64 = mod_ctio.ruint64;
    exports.wuint8 = mod_ctio.wuint8;
    exports.wuint16 = mod_ctio.wuint16;
    exports.wuint32 = mod_ctio.wuint32;
    exports.wuint64 = mod_ctio.wuint64;
    
    exports.rsint8 = mod_ctio.rsint8;
    exports.rsint16 = mod_ctio.rsint16;
    exports.rsint32 = mod_ctio.rsint32;
    exports.rsint64 = mod_ctio.rsint64;
    exports.wsint8 = mod_ctio.wsint8;
    exports.wsint16 = mod_ctio.wsint16;
    exports.wsint32 = mod_ctio.wsint32;
    exports.wsint64 = mod_ctio.wsint64;
    
    exports.rfloat = mod_ctio.rfloat;
    exports.rdouble = mod_ctio.rdouble;
    exports.wfloat = mod_ctio.wfloat;
    exports.wdouble = mod_ctio.wdouble;
    
  provide("ctype", module.exports);
}(global));

// pakmanager:cryptiles/lib
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Load modules
    
    var Crypto = require('crypto');
    var Boom = require('boom');
    
    
    // Declare internals
    
    var internals = {};
    
    
    // Generate a cryptographically strong pseudo-random data
    
    exports.randomString = function (size) {
    
        var buffer = exports.randomBits((size + 1) * 6);
        if (buffer instanceof Error) {
            return buffer;
        }
    
        var string = buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
        return string.slice(0, size);
    };
    
    
    exports.randomBits = function (bits) {
    
        if (!bits ||
            bits < 0) {
    
            return Boom.internal('Invalid random bits count');
        }
    
        var bytes = Math.ceil(bits / 8);
        try {
            return Crypto.randomBytes(bytes);
        }
        catch (err) {
            return Boom.internal('Failed generating random bits: ' + err.message);
        }
    };
    
    
    // Compare two strings using fixed time algorithm (to prevent time-based analysis of MAC digest match)
    
    exports.fixedTimeComparison = function (a, b) {
    
        if (typeof a !== 'string' ||
            typeof b !== 'string') {
    
            return false;
        }
    
        var mismatch = (a.length === b.length ? 0 : 1);
        if (mismatch) {
            b = a;
        }
    
        for (var i = 0, il = a.length; i < il; ++i) {
            var ac = a.charCodeAt(i);
            var bc = b.charCodeAt(i);
            mismatch |= (ac ^ bc);
        }
    
        return (mismatch === 0);
    };
    
    
    
  provide("cryptiles/lib", module.exports);
}(global));

// pakmanager:cryptiles
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  module.exports =  require('cryptiles/lib');
  provide("cryptiles", module.exports);
}(global));

// pakmanager:sntp/lib
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Load modules
    
    var Dgram = require('dgram');
    var Dns = require('dns');
    var Hoek = require('hoek');
    
    
    // Declare internals
    
    var internals = {};
    
    
    exports.time = function (options, callback) {
    
        if (arguments.length !== 2) {
            callback = arguments[0];
            options = {};
        }
    
        var settings = Hoek.clone(options);
        settings.host = settings.host || 'pool.ntp.org';
        settings.port = settings.port || 123;
        settings.resolveReference = settings.resolveReference || false;
    
        // Declare variables used by callback
    
        var timeoutId = 0;
        var sent = 0;
    
        // Ensure callback is only called once
    
        var finish = function (err, result) {
    
            if (timeoutId) {
                clearTimeout(timeoutId);
                timeoutId = 0;
            }
    
            socket.removeAllListeners();
            socket.once('error', internals.ignore);
            socket.close();
            return callback(err, result);
        };
    
        finish = Hoek.once(finish);
    
        // Create UDP socket
    
        var socket = Dgram.createSocket('udp4');
    
        socket.once('error', function (err) {
    
            return finish(err);
        });
    
        // Listen to incoming messages
    
        socket.on('message', function (buffer, rinfo) {
    
            var received = Date.now();
    
            var message = new internals.NtpMessage(buffer);
            if (!message.isValid) {
                return finish(new Error('Invalid server response'), message);
            }
    
            if (message.originateTimestamp !== sent) {
                return finish(new Error('Wrong originate timestamp'), message);
            }
    
            // Timestamp Name          ID   When Generated
            // ------------------------------------------------------------
            // Originate Timestamp     T1   time request sent by client
            // Receive Timestamp       T2   time request received by server
            // Transmit Timestamp      T3   time reply sent by server
            // Destination Timestamp   T4   time reply received by client
            //
            // The roundtrip delay d and system clock offset t are defined as:
            //
            // d = (T4 - T1) - (T3 - T2)     t = ((T2 - T1) + (T3 - T4)) / 2
    
            var T1 = message.originateTimestamp;
            var T2 = message.receiveTimestamp;
            var T3 = message.transmitTimestamp;
            var T4 = received;
    
            message.d = (T4 - T1) - (T3 - T2);
            message.t = ((T2 - T1) + (T3 - T4)) / 2;
            message.receivedLocally = received;
    
            if (!settings.resolveReference ||
                message.stratum !== 'secondary') {
    
                return finish(null, message);
            }
    
            // Resolve reference IP address
    
            Dns.reverse(message.referenceId, function (err, domains) {
    
                if (/* $lab:coverage:off$ */ !err /* $lab:coverage:on$ */) {
                    message.referenceHost = domains[0];
                }
    
                return finish(null, message);
            });
        });
    
        // Set timeout
    
        if (settings.timeout) {
            timeoutId = setTimeout(function () {
    
                timeoutId = 0;
                return finish(new Error('Timeout'));
            }, settings.timeout);
        }
    
        // Construct NTP message
    
        var message = new Buffer(48);
        for (var i = 0; i < 48; i++) {                      // Zero message
            message[i] = 0;
        }
    
        message[0] = (0 << 6) + (4 << 3) + (3 << 0)         // Set version number to 4 and Mode to 3 (client)
        sent = Date.now();
        internals.fromMsecs(sent, message, 40);               // Set transmit timestamp (returns as originate)
    
        // Send NTP request
    
        socket.send(message, 0, message.length, settings.port, settings.host, function (err, bytes) {
    
            if (err ||
                bytes !== 48) {
    
                return finish(err || new Error('Could not send entire message'));
            }
        });
    };
    
    
    internals.NtpMessage = function (buffer) {
    
        this.isValid = false;
    
        // Validate
    
        if (buffer.length !== 48) {
            return;
        }
    
        // Leap indicator
    
        var li = (buffer[0] >> 6);
        switch (li) {
            case 0: this.leapIndicator = 'no-warning'; break;
            case 1: this.leapIndicator = 'last-minute-61'; break;
            case 2: this.leapIndicator = 'last-minute-59'; break;
            case 3: this.leapIndicator = 'alarm'; break;
        }
    
        // Version
    
        var vn = ((buffer[0] & 0x38) >> 3);
        this.version = vn;
    
        // Mode
    
        var mode = (buffer[0] & 0x7);
        switch (mode) {
            case 1: this.mode = 'symmetric-active'; break;
            case 2: this.mode = 'symmetric-passive'; break;
            case 3: this.mode = 'client'; break;
            case 4: this.mode = 'server'; break;
            case 5: this.mode = 'broadcast'; break;
            case 0:
            case 6:
            case 7: this.mode = 'reserved'; break;
        }
    
        // Stratum
    
        var stratum = buffer[1];
        if (stratum === 0) {
            this.stratum = 'death';
        }
        else if (stratum === 1) {
            this.stratum = 'primary';
        }
        else if (stratum <= 15) {
            this.stratum = 'secondary';
        }
        else {
            this.stratum = 'reserved';
        }
    
        // Poll interval (msec)
    
        this.pollInterval = Math.round(Math.pow(2, buffer[2])) * 1000;
    
        // Precision (msecs)
    
        this.precision = Math.pow(2, buffer[3]) * 1000;
    
        // Root delay (msecs)
    
        var rootDelay = 256 * (256 * (256 * buffer[4] + buffer[5]) + buffer[6]) + buffer[7];
        this.rootDelay = 1000 * (rootDelay / 0x10000);
    
        // Root dispersion (msecs)
    
        this.rootDispersion = ((buffer[8] << 8) + buffer[9] + ((buffer[10] << 8) + buffer[11]) / Math.pow(2, 16)) * 1000;
    
        // Reference identifier
    
        this.referenceId = '';
        switch (this.stratum) {
            case 'death':
            case 'primary':
                this.referenceId = String.fromCharCode(buffer[12]) + String.fromCharCode(buffer[13]) + String.fromCharCode(buffer[14]) + String.fromCharCode(buffer[15]);
                break;
            case 'secondary':
                this.referenceId = '' + buffer[12] + '.' + buffer[13] + '.' + buffer[14] + '.' + buffer[15];
                break;
        }
    
        // Reference timestamp
    
        this.referenceTimestamp = internals.toMsecs(buffer, 16);
    
        // Originate timestamp
    
        this.originateTimestamp = internals.toMsecs(buffer, 24);
    
        // Receive timestamp
    
        this.receiveTimestamp = internals.toMsecs(buffer, 32);
    
        // Transmit timestamp
    
        this.transmitTimestamp = internals.toMsecs(buffer, 40);
    
        // Validate
    
        if (this.version === 4 &&
            this.stratum !== 'reserved' &&
            this.mode === 'server' &&
            this.originateTimestamp &&
            this.receiveTimestamp &&
            this.transmitTimestamp) {
    
            this.isValid = true;
        }
    
        return this;
    };
    
    
    internals.toMsecs = function (buffer, offset) {
    
        var seconds = 0;
        var fraction = 0;
    
        for (var i = 0; i < 4; ++i) {
            seconds = (seconds * 256) + buffer[offset + i];
        }
    
        for (i = 4; i < 8; ++i) {
            fraction = (fraction * 256) + buffer[offset + i];
        }
    
        return ((seconds - 2208988800 + (fraction / Math.pow(2, 32))) * 1000);
    };
    
    
    internals.fromMsecs = function (ts, buffer, offset) {
    
        var seconds = Math.floor(ts / 1000) + 2208988800;
        var fraction = Math.round((ts % 1000) / 1000 * Math.pow(2, 32));
    
        buffer[offset + 0] = (seconds & 0xFF000000) >> 24;
        buffer[offset + 1] = (seconds & 0x00FF0000) >> 16;
        buffer[offset + 2] = (seconds & 0x0000FF00) >> 8;
        buffer[offset + 3] = (seconds & 0x000000FF);
    
        buffer[offset + 4] = (fraction & 0xFF000000) >> 24;
        buffer[offset + 5] = (fraction & 0x00FF0000) >> 16;
        buffer[offset + 6] = (fraction & 0x0000FF00) >> 8;
        buffer[offset + 7] = (fraction & 0x000000FF);
    };
    
    
    // Offset singleton
    
    internals.last = {
        offset: 0,
        expires: 0,
        host: '',
        port: 0
    };
    
    
    exports.offset = function (options, callback) {
    
        if (arguments.length !== 2) {
            callback = arguments[0];
            options = {};
        }
    
        var now = Date.now();
        var clockSyncRefresh = options.clockSyncRefresh || 24 * 60 * 60 * 1000;                    // Daily
    
        if (internals.last.offset &&
            internals.last.host === options.host &&
            internals.last.port === options.port &&
            now < internals.last.expires) {
    
            process.nextTick(function () {
    
                callback(null, internals.last.offset);
            });
    
            return;
        }
    
        exports.time(options, function (err, time) {
    
            if (err) {
                return callback(err, 0);
            }
    
            internals.last = {
                offset: Math.round(time.t),
                expires: now + clockSyncRefresh,
                host: options.host,
                port: options.port
            };
    
            return callback(null, internals.last.offset);
        });
    };
    
    
    // Now singleton
    
    internals.now = {
        intervalId: 0
    };
    
    
    exports.start = function (options, callback) {
    
        if (arguments.length !== 2) {
            callback = arguments[0];
            options = {};
        }
    
        if (internals.now.intervalId) {
            process.nextTick(function () {
    
                callback();
            });
    
            return;
        }
    
        exports.offset(options, function (err, offset) {
    
            internals.now.intervalId = setInterval(function () {
    
                exports.offset(options, function () { });
            }, options.clockSyncRefresh || 24 * 60 * 60 * 1000);                                // Daily
    
            return callback();
        });
    };
    
    
    exports.stop = function () {
    
        if (!internals.now.intervalId) {
            return;
        }
    
        clearInterval(internals.now.intervalId);
        internals.now.intervalId = 0;
    };
    
    
    exports.isLive = function () {
    
        return !!internals.now.intervalId;
    };
    
    
    exports.now = function () {
    
        var now = Date.now();
        if (!exports.isLive() ||
            now >= internals.last.expires) {
    
            return now;
        }
    
        return now + internals.last.offset;
    };
    
    
    internals.ignore = function () {
    
    };
    
  provide("sntp/lib", module.exports);
}(global));

// pakmanager:sntp
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  module.exports =  require('sntp/lib');
  provide("sntp", module.exports);
}(global));

// pakmanager:bl
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  var DuplexStream = require('readable-stream').Duplex
      , util         = require('util')
    
    function BufferList (callback) {
      if (!(this instanceof BufferList))
        return new BufferList(callback)
    
      this._bufs  = []
      this.length = 0
    
      if (typeof callback == 'function') {
        this._callback = callback
    
        var piper = function (err) {
          if (this._callback) {
            this._callback(err)
            this._callback = null
          }
        }.bind(this)
    
        this.on('pipe', function (src) {
          src.on('error', piper)
        })
        this.on('unpipe', function (src) {
          src.removeListener('error', piper)
        })
      }
      else if (Buffer.isBuffer(callback))
        this.append(callback)
      else if (Array.isArray(callback)) {
        callback.forEach(function (b) {
          Buffer.isBuffer(b) && this.append(b)
        }.bind(this))
      }
    
      DuplexStream.call(this)
    }
    
    util.inherits(BufferList, DuplexStream)
    
    BufferList.prototype._offset = function (offset) {
      var tot = 0, i = 0, _t
      for (; i < this._bufs.length; i++) {
        _t = tot + this._bufs[i].length
        if (offset < _t)
          return [ i, offset - tot ]
        tot = _t
      }
    }
    
    BufferList.prototype.append = function (buf) {
      var isBuffer = Buffer.isBuffer(buf) ||
                     buf instanceof BufferList
    
      this._bufs.push(isBuffer ? buf : new Buffer(buf))
      this.length += buf.length
      return this
    }
    
    BufferList.prototype._write = function (buf, encoding, callback) {
      this.append(buf)
      if (callback)
        callback()
    }
    
    BufferList.prototype._read = function (size) {
      if (!this.length)
        return this.push(null)
      size = Math.min(size, this.length)
      this.push(this.slice(0, size))
      this.consume(size)
    }
    
    BufferList.prototype.end = function (chunk) {
      DuplexStream.prototype.end.call(this, chunk)
    
      if (this._callback) {
        this._callback(null, this.slice())
        this._callback = null
      }
    }
    
    BufferList.prototype.get = function (index) {
      return this.slice(index, index + 1)[0]
    }
    
    BufferList.prototype.slice = function (start, end) {
      return this.copy(null, 0, start, end)
    }
    
    BufferList.prototype.copy = function (dst, dstStart, srcStart, srcEnd) {
      if (typeof srcStart != 'number' || srcStart < 0)
        srcStart = 0
      if (typeof srcEnd != 'number' || srcEnd > this.length)
        srcEnd = this.length
      if (srcStart >= this.length)
        return dst || new Buffer(0)
      if (srcEnd <= 0)
        return dst || new Buffer(0)
    
      var copy   = !!dst
        , off    = this._offset(srcStart)
        , len    = srcEnd - srcStart
        , bytes  = len
        , bufoff = (copy && dstStart) || 0
        , start  = off[1]
        , l
        , i
    
      // copy/slice everything
      if (srcStart === 0 && srcEnd == this.length) {
        if (!copy) // slice, just return a full concat
          return Buffer.concat(this._bufs)
    
        // copy, need to copy individual buffers
        for (i = 0; i < this._bufs.length; i++) {
          this._bufs[i].copy(dst, bufoff)
          bufoff += this._bufs[i].length
        }
    
        return dst
      }
    
      // easy, cheap case where it's a subset of one of the buffers
      if (bytes <= this._bufs[off[0]].length - start) {
        return copy
          ? this._bufs[off[0]].copy(dst, dstStart, start, start + bytes)
          : this._bufs[off[0]].slice(start, start + bytes)
      }
    
      if (!copy) // a slice, we need something to copy in to
        dst = new Buffer(len)
    
      for (i = off[0]; i < this._bufs.length; i++) {
        l = this._bufs[i].length - start
    
        if (bytes > l) {
          this._bufs[i].copy(dst, bufoff, start)
        } else {
          this._bufs[i].copy(dst, bufoff, start, start + bytes)
          break
        }
    
        bufoff += l
        bytes -= l
    
        if (start)
          start = 0
      }
    
      return dst
    }
    
    BufferList.prototype.toString = function (encoding, start, end) {
      return this.slice(start, end).toString(encoding)
    }
    
    BufferList.prototype.consume = function (bytes) {
      while (this._bufs.length) {
        if (bytes > this._bufs[0].length) {
          bytes -= this._bufs[0].length
          this.length -= this._bufs[0].length
          this._bufs.shift()
        } else {
          this._bufs[0] = this._bufs[0].slice(bytes)
          this.length -= bytes
          break
        }
      }
      return this
    }
    
    BufferList.prototype.duplicate = function () {
      var i = 0
        , copy = new BufferList()
    
      for (; i < this._bufs.length; i++)
        copy.append(this._bufs[i])
    
      return copy
    }
    
    BufferList.prototype.destroy = function () {
      this._bufs.length = 0;
      this.length = 0;
      this.push(null);
    }
    
    ;(function () {
      var methods = {
          'readDoubleBE' : 8
        , 'readDoubleLE' : 8
        , 'readFloatBE'  : 4
        , 'readFloatLE'  : 4
        , 'readInt32BE'  : 4
        , 'readInt32LE'  : 4
        , 'readUInt32BE' : 4
        , 'readUInt32LE' : 4
        , 'readInt16BE'  : 2
        , 'readInt16LE'  : 2
        , 'readUInt16BE' : 2
        , 'readUInt16LE' : 2
        , 'readInt8'     : 1
        , 'readUInt8'    : 1
      }
    
      for (var m in methods) {
        (function (m) {
          BufferList.prototype[m] = function (offset) {
            return this.slice(offset, offset + methods[m])[m](0)
          }
        }(m))
      }
    }())
    
    module.exports = BufferList
    
  provide("bl", module.exports);
}(global));

// pakmanager:caseless
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  function Caseless (dict) {
      this.dict = dict
    }
    Caseless.prototype.set = function (name, value, clobber) {
      if (typeof name === 'object') {
        for (var i in name) {
          this.set(i, name[i], value)
        }
      } else {
        if (typeof clobber === 'undefined') clobber = true
        var has = this.has(name)
    
        if (!clobber && has) this.dict[has] = this.dict[has] + ',' + value
        else this.dict[has || name] = value
        return has
      }
    }
    Caseless.prototype.has = function (name) {
      var keys = Object.keys(this.dict)
        , name = name.toLowerCase()
        ;
      for (var i=0;i<keys.length;i++) {
        if (keys[i].toLowerCase() === name) return keys[i]
      }
      return false
    }
    Caseless.prototype.get = function (name) {
      name = name.toLowerCase()
      var result, _key
      var headers = this.dict
      Object.keys(headers).forEach(function (key) {
        _key = key.toLowerCase()
        if (name === _key) result = headers[key]
      })
      return result
    }
    Caseless.prototype.swap = function (name) {
      var has = this.has(name)
      if (!has) throw new Error('There is no header than matches "'+name+'"')
      this.dict[name] = this.dict[has]
      delete this.dict[has]
    }
    Caseless.prototype.del = function (name) {
      var has = this.has(name)
      return delete this.dict[has || name]
    }
    
    module.exports = function (dict) {return new Caseless(dict)}
    module.exports.httpify = function (resp, headers) {
      var c = new Caseless(headers)
      resp.setHeader = function (key, value, clobber) {
        return c.set(key, value, clobber)
      }
      resp.hasHeader = function (key) {
        return c.has(key)
      }
      resp.getHeader = function (key) {
        return c.get(key)
      }
      resp.removeHeader = function (key) {
        return c.del(key)
      }
      resp.headers = c.dict
      return c
    }
    
  provide("caseless", module.exports);
}(global));

// pakmanager:forever-agent
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  module.exports = ForeverAgent
    ForeverAgent.SSL = ForeverAgentSSL
    
    var util = require('util')
      , Agent = require('http').Agent
      , net = require('net')
      , tls = require('tls')
      , AgentSSL = require('https').Agent
    
    function ForeverAgent(options) {
      var self = this
      self.options = options || {}
      self.requests = {}
      self.sockets = {}
      self.freeSockets = {}
      self.maxSockets = self.options.maxSockets || Agent.defaultMaxSockets
      self.minSockets = self.options.minSockets || ForeverAgent.defaultMinSockets
      self.on('free', function(socket, host, port) {
        var name = host + ':' + port
        if (self.requests[name] && self.requests[name].length) {
          self.requests[name].shift().onSocket(socket)
        } else if (self.sockets[name].length < self.minSockets) {
          if (!self.freeSockets[name]) self.freeSockets[name] = []
          self.freeSockets[name].push(socket)
          
          // if an error happens while we don't use the socket anyway, meh, throw the socket away
          var onIdleError = function() {
            socket.destroy()
          }
          socket._onIdleError = onIdleError
          socket.on('error', onIdleError)
        } else {
          // If there are no pending requests just destroy the
          // socket and it will get removed from the pool. This
          // gets us out of timeout issues and allows us to
          // default to Connection:keep-alive.
          socket.destroy()
        }
      })
    
    }
    util.inherits(ForeverAgent, Agent)
    
    ForeverAgent.defaultMinSockets = 5
    
    
    ForeverAgent.prototype.createConnection = net.createConnection
    ForeverAgent.prototype.addRequestNoreuse = Agent.prototype.addRequest
    ForeverAgent.prototype.addRequest = function(req, host, port) {
      var name = host + ':' + port
      if (this.freeSockets[name] && this.freeSockets[name].length > 0 && !req.useChunkedEncodingByDefault) {
        var idleSocket = this.freeSockets[name].pop()
        idleSocket.removeListener('error', idleSocket._onIdleError)
        delete idleSocket._onIdleError
        req._reusedSocket = true
        req.onSocket(idleSocket)
      } else {
        this.addRequestNoreuse(req, host, port)
      }
    }
    
    ForeverAgent.prototype.removeSocket = function(s, name, host, port) {
      if (this.sockets[name]) {
        var index = this.sockets[name].indexOf(s)
        if (index !== -1) {
          this.sockets[name].splice(index, 1)
        }
      } else if (this.sockets[name] && this.sockets[name].length === 0) {
        // don't leak
        delete this.sockets[name]
        delete this.requests[name]
      }
      
      if (this.freeSockets[name]) {
        var index = this.freeSockets[name].indexOf(s)
        if (index !== -1) {
          this.freeSockets[name].splice(index, 1)
          if (this.freeSockets[name].length === 0) {
            delete this.freeSockets[name]
          }
        }
      }
    
      if (this.requests[name] && this.requests[name].length) {
        // If we have pending requests and a socket gets closed a new one
        // needs to be created to take over in the pool for the one that closed.
        this.createSocket(name, host, port).emit('free')
      }
    }
    
    function ForeverAgentSSL (options) {
      ForeverAgent.call(this, options)
    }
    util.inherits(ForeverAgentSSL, ForeverAgent)
    
    ForeverAgentSSL.prototype.createConnection = createConnectionSSL
    ForeverAgentSSL.prototype.addRequestNoreuse = AgentSSL.prototype.addRequest
    
    function createConnectionSSL (port, host, options) {
      if (typeof port === 'object') {
        options = port;
      } else if (typeof host === 'object') {
        options = host;
      } else if (typeof options === 'object') {
        options = options;
      } else {
        options = {};
      }
    
      if (typeof port === 'number') {
        options.port = port;
      }
    
      if (typeof host === 'string') {
        options.host = host;
      }
    
      return tls.connect(options);
    }
    
  provide("forever-agent", module.exports);
}(global));

// pakmanager:form-data
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  var CombinedStream = require('combined-stream');
    var util = require('util');
    var path = require('path');
    var http = require('http');
    var https = require('https');
    var parseUrl = require('url').parse;
    var fs = require('fs');
    var mime = require('mime');
    var async = require('async');
    
    module.exports = FormData;
    function FormData() {
      this._overheadLength = 0;
      this._valueLength = 0;
      this._lengthRetrievers = [];
    
      CombinedStream.call(this);
    }
    util.inherits(FormData, CombinedStream);
    
    FormData.LINE_BREAK = '\r\n';
    
    FormData.prototype.append = function(field, value, options) {
      options = options || {};
    
      var append = CombinedStream.prototype.append.bind(this);
    
      // all that streamy business can't handle numbers
      if (typeof value == 'number') value = ''+value;
    
      // https://github.com/felixge/node-form-data/issues/38
      if (util.isArray(value)) {
        // Please convert your array into string
        // the way web server expects it
        this._error(new Error('Arrays are not supported.'));
        return;
      }
    
      var header = this._multiPartHeader(field, value, options);
      var footer = this._multiPartFooter(field, value, options);
    
      append(header);
      append(value);
      append(footer);
    
      // pass along options.knownLength
      this._trackLength(header, value, options);
    };
    
    FormData.prototype._trackLength = function(header, value, options) {
      var valueLength = 0;
    
      // used w/ getLengthSync(), when length is known.
      // e.g. for streaming directly from a remote server,
      // w/ a known file a size, and not wanting to wait for
      // incoming file to finish to get its size.
      if (options.knownLength != null) {
        valueLength += +options.knownLength;
      } else if (Buffer.isBuffer(value)) {
        valueLength = value.length;
      } else if (typeof value === 'string') {
        valueLength = Buffer.byteLength(value);
      }
    
      this._valueLength += valueLength;
    
      // @check why add CRLF? does this account for custom/multiple CRLFs?
      this._overheadLength +=
        Buffer.byteLength(header) +
        + FormData.LINE_BREAK.length;
    
      // empty or either doesn't have path or not an http response
      if (!value || ( !value.path && !(value.readable && value.hasOwnProperty('httpVersion')) )) {
        return;
      }
    
      // no need to bother with the length
      if (!options.knownLength)
      this._lengthRetrievers.push(function(next) {
    
        if (value.hasOwnProperty('fd')) {
    
          // take read range into a account
          // `end` = Infinity –> read file till the end
          //
          // TODO: Looks like there is bug in Node fs.createReadStream
          // it doesn't respect `end` options without `start` options
          // Fix it when node fixes it.
          // https://github.com/joyent/node/issues/7819
          if (value.end != undefined && value.end != Infinity && value.start != undefined) {
    
            // when end specified
            // no need to calculate range
            // inclusive, starts with 0
            next(null, value.end+1 - (value.start ? value.start : 0));
    
          // not that fast snoopy
          } else {
            // still need to fetch file size from fs
            fs.stat(value.path, function(err, stat) {
    
              var fileSize;
    
              if (err) {
                next(err);
                return;
              }
    
              // update final size based on the range options
              fileSize = stat.size - (value.start ? value.start : 0);
              next(null, fileSize);
            });
          }
    
        // or http response
        } else if (value.hasOwnProperty('httpVersion')) {
          next(null, +value.headers['content-length']);
    
        // or request stream http://github.com/mikeal/request
        } else if (value.hasOwnProperty('httpModule')) {
          // wait till response come back
          value.on('response', function(response) {
            value.pause();
            next(null, +response.headers['content-length']);
          });
          value.resume();
    
        // something else
        } else {
          next('Unknown stream');
        }
      });
    };
    
    FormData.prototype._multiPartHeader = function(field, value, options) {
      var boundary = this.getBoundary();
      var header = '';
    
      // custom header specified (as string)?
      // it becomes responsible for boundary
      // (e.g. to handle extra CRLFs on .NET servers)
      if (options.header != null) {
        header = options.header;
      } else {
        header += '--' + boundary + FormData.LINE_BREAK +
          'Content-Disposition: form-data; name="' + field + '"';
    
        // fs- and request- streams have path property
        // or use custom filename and/or contentType
        // TODO: Use request's response mime-type
        if (options.filename || value.path) {
          header +=
            '; filename="' + path.basename(options.filename || value.path) + '"' + FormData.LINE_BREAK +
            'Content-Type: ' +  (options.contentType || mime.lookup(options.filename || value.path));
    
        // http response has not
        } else if (value.readable && value.hasOwnProperty('httpVersion')) {
          header +=
            '; filename="' + path.basename(value.client._httpMessage.path) + '"' + FormData.LINE_BREAK +
            'Content-Type: ' + value.headers['content-type'];
        }
    
        header += FormData.LINE_BREAK + FormData.LINE_BREAK;
      }
    
      return header;
    };
    
    FormData.prototype._multiPartFooter = function(field, value, options) {
      return function(next) {
        var footer = FormData.LINE_BREAK;
    
        var lastPart = (this._streams.length === 0);
        if (lastPart) {
          footer += this._lastBoundary();
        }
    
        next(footer);
      }.bind(this);
    };
    
    FormData.prototype._lastBoundary = function() {
      return '--' + this.getBoundary() + '--';
    };
    
    FormData.prototype.getHeaders = function(userHeaders) {
      var formHeaders = {
        'content-type': 'multipart/form-data; boundary=' + this.getBoundary()
      };
    
      for (var header in userHeaders) {
        formHeaders[header.toLowerCase()] = userHeaders[header];
      }
    
      return formHeaders;
    }
    
    FormData.prototype.getCustomHeaders = function(contentType) {
        contentType = contentType ? contentType : 'multipart/form-data';
    
        var formHeaders = {
            'content-type': contentType + '; boundary=' + this.getBoundary(),
            'content-length': this.getLengthSync()
        };
    
        return formHeaders;
    }
    
    FormData.prototype.getBoundary = function() {
      if (!this._boundary) {
        this._generateBoundary();
      }
    
      return this._boundary;
    };
    
    FormData.prototype._generateBoundary = function() {
      // This generates a 50 character boundary similar to those used by Firefox.
      // They are optimized for boyer-moore parsing.
      var boundary = '--------------------------';
      for (var i = 0; i < 24; i++) {
        boundary += Math.floor(Math.random() * 10).toString(16);
      }
    
      this._boundary = boundary;
    };
    
    // Note: getLengthSync DOESN'T calculate streams length
    // As workaround one can calculate file size manually
    // and add it as knownLength option
    FormData.prototype.getLengthSync = function(debug) {
      var knownLength = this._overheadLength + this._valueLength;
    
      // Don't get confused, there are 3 "internal" streams for each keyval pair
      // so it basically checks if there is any value added to the form
      if (this._streams.length) {
        knownLength += this._lastBoundary().length;
      }
    
      // https://github.com/felixge/node-form-data/issues/40
      if (this._lengthRetrievers.length) {
        // Some async length retrivers are present
        // therefore synchronous length calculation is false.
        // Please use getLength(callback) to get proper length
        this._error(new Error('Cannot calculate proper length in synchronous way.'));
      }
    
      return knownLength;
    };
    
    FormData.prototype.getLength = function(cb) {
      var knownLength = this._overheadLength + this._valueLength;
    
      if (this._streams.length) {
        knownLength += this._lastBoundary().length;
      }
    
      if (!this._lengthRetrievers.length) {
        process.nextTick(cb.bind(this, null, knownLength));
        return;
      }
    
      async.parallel(this._lengthRetrievers, function(err, values) {
        if (err) {
          cb(err);
          return;
        }
    
        values.forEach(function(length) {
          knownLength += length;
        });
    
        cb(null, knownLength);
      });
    };
    
    FormData.prototype.submit = function(params, cb) {
    
      var request
        , options
        , defaults = {
            method : 'post'
        };
    
      // parse provided url if it's string
      // or treat it as options object
      if (typeof params == 'string') {
        params = parseUrl(params);
    
        options = populate({
          port: params.port,
          path: params.pathname,
          host: params.hostname
        }, defaults);
      }
      else // use custom params
      {
        options = populate(params, defaults);
        // if no port provided use default one
        if (!options.port) {
          options.port = options.protocol == 'https:' ? 443 : 80;
        }
      }
    
      // put that good code in getHeaders to some use
      options.headers = this.getHeaders(params.headers);
    
      // https if specified, fallback to http in any other case
      if (params.protocol == 'https:') {
        request = https.request(options);
      } else {
        request = http.request(options);
      }
    
      // get content length and fire away
      this.getLength(function(err, length) {
    
        // TODO: Add chunked encoding when no length (if err)
    
        // add content length
        request.setHeader('Content-Length', length);
    
        this.pipe(request);
        if (cb) {
          request.on('error', cb);
          request.on('response', cb.bind(this, null));
        }
      }.bind(this));
    
      return request;
    };
    
    FormData.prototype._error = function(err) {
      if (this.error) return;
    
      this.error = err;
      this.pause();
      this.emit('error', err);
    };
    
    /*
     * Santa's little helpers
     */
    
    // populates missing values
    function populate(dst, src) {
      for (var prop in src) {
        if (!dst[prop]) dst[prop] = src[prop];
      }
      return dst;
    }
    
  provide("form-data", module.exports);
}(global));

// pakmanager:json-stringify-safe
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  module.exports = stringify;
    
    function getSerialize (fn, decycle) {
      var seen = [], keys = [];
      decycle = decycle || function(key, value) {
        return '[Circular ' + getPath(value, seen, keys) + ']'
      };
      return function(key, value) {
        var ret = value;
        if (typeof value === 'object' && value) {
          if (seen.indexOf(value) !== -1)
            ret = decycle(key, value);
          else {
            seen.push(value);
            keys.push(key);
          }
        }
        if (fn) ret = fn(key, ret);
        return ret;
      }
    }
    
    function getPath (value, seen, keys) {
      var index = seen.indexOf(value);
      var path = [ keys[index] ];
      for (index--; index >= 0; index--) {
        if (seen[index][ path[0] ] === value) {
          value = seen[index];
          path.unshift(keys[index]);
        }
      }
      return '~' + path.join('.');
    }
    
    function stringify(obj, fn, spaces, decycle) {
      return JSON.stringify(obj, getSerialize(fn, decycle), spaces);
    }
    
    stringify.getSerialize = getSerialize;
    
  provide("json-stringify-safe", module.exports);
}(global));

// pakmanager:mime-types
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  
    var db = require('mime-db')
    
    // types[extension] = type
    exports.types = Object.create(null)
    // extensions[type] = [extensions]
    exports.extensions = Object.create(null)
    
    Object.keys(db).forEach(function (name) {
      var mime = db[name]
      var exts = mime.extensions
      if (!exts || !exts.length) return
      exports.extensions[name] = exts
      exts.forEach(function (ext) {
        exports.types[ext] = name
      })
    })
    
    exports.lookup = function (string) {
      if (!string || typeof string !== "string") return false
      // remove any leading paths, though we should just use path.basename
      string = string.replace(/.*[\.\/\\]/, '').toLowerCase()
      if (!string) return false
      return exports.types[string] || false
    }
    
    exports.extension = function (type) {
      if (!type || typeof type !== "string") return false
      // to do: use media-typer
      type = type.match(/^\s*([^;\s]*)(?:;|\s|$)/)
      if (!type) return false
      var exts = exports.extensions[type[1].toLowerCase()]
      if (!exts || !exts.length) return false
      return exts[0]
    }
    
    // type has to be an exact mime type
    exports.charset = function (type) {
      var mime = db[type]
      if (mime && mime.charset) return mime.charset
    
      // default text/* to utf-8
      if (/^text\//.test(type)) return 'UTF-8'
    
      return false
    }
    
    // backwards compatibility
    exports.charsets = {
      lookup: exports.charset
    }
    
    // to do: maybe use set-type module or something
    exports.contentType = function (type) {
      if (!type || typeof type !== "string") return false
      if (!~type.indexOf('/')) type = exports.lookup(type)
      if (!type) return false
      if (!~type.indexOf('charset')) {
        var charset = exports.charset(type)
        if (charset) type += '; charset=' + charset.toLowerCase()
      }
      return type
    }
    
  provide("mime-types", module.exports);
}(global));

// pakmanager:node-uuid
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  //     uuid.js
    //
    //     Copyright (c) 2010-2012 Robert Kieffer
    //     MIT License - http://opensource.org/licenses/mit-license.php
    
    (function() {
      var _global = this;
    
      // Unique ID creation requires a high quality random # generator.  We feature
      // detect to determine the best RNG source, normalizing to a function that
      // returns 128-bits of randomness, since that's what's usually required
      var _rng;
    
      // Node.js crypto-based RNG - http://nodejs.org/docs/v0.6.2/api/crypto.html
      //
      // Moderately fast, high quality
      if (typeof(require) == 'function') {
        try {
          var _rb = require('crypto').randomBytes;
          _rng = _rb && function() {return _rb(16);};
        } catch(e) {}
      }
    
      if (!_rng && _global.crypto && crypto.getRandomValues) {
        // WHATWG crypto-based RNG - http://wiki.whatwg.org/wiki/Crypto
        //
        // Moderately fast, high quality
        var _rnds8 = new Uint8Array(16);
        _rng = function whatwgRNG() {
          crypto.getRandomValues(_rnds8);
          return _rnds8;
        };
      }
    
      if (!_rng) {
        // Math.random()-based (RNG)
        //
        // If all else fails, use Math.random().  It's fast, but is of unspecified
        // quality.
        var  _rnds = new Array(16);
        _rng = function() {
          for (var i = 0, r; i < 16; i++) {
            if ((i & 0x03) === 0) r = Math.random() * 0x100000000;
            _rnds[i] = r >>> ((i & 0x03) << 3) & 0xff;
          }
    
          return _rnds;
        };
      }
    
      // Buffer class to use
      var BufferClass = typeof(Buffer) == 'function' ? Buffer : Array;
    
      // Maps for number <-> hex string conversion
      var _byteToHex = [];
      var _hexToByte = {};
      for (var i = 0; i < 256; i++) {
        _byteToHex[i] = (i + 0x100).toString(16).substr(1);
        _hexToByte[_byteToHex[i]] = i;
      }
    
      // **`parse()` - Parse a UUID into it's component bytes**
      function parse(s, buf, offset) {
        var i = (buf && offset) || 0, ii = 0;
    
        buf = buf || [];
        s.toLowerCase().replace(/[0-9a-f]{2}/g, function(oct) {
          if (ii < 16) { // Don't overflow!
            buf[i + ii++] = _hexToByte[oct];
          }
        });
    
        // Zero out remaining bytes if string was short
        while (ii < 16) {
          buf[i + ii++] = 0;
        }
    
        return buf;
      }
    
      // **`unparse()` - Convert UUID byte array (ala parse()) into a string**
      function unparse(buf, offset) {
        var i = offset || 0, bth = _byteToHex;
        return  bth[buf[i++]] + bth[buf[i++]] +
                bth[buf[i++]] + bth[buf[i++]] + '-' +
                bth[buf[i++]] + bth[buf[i++]] + '-' +
                bth[buf[i++]] + bth[buf[i++]] + '-' +
                bth[buf[i++]] + bth[buf[i++]] + '-' +
                bth[buf[i++]] + bth[buf[i++]] +
                bth[buf[i++]] + bth[buf[i++]] +
                bth[buf[i++]] + bth[buf[i++]];
      }
    
      // **`v1()` - Generate time-based UUID**
      //
      // Inspired by https://github.com/LiosK/UUID.js
      // and http://docs.python.org/library/uuid.html
    
      // random #'s we need to init node and clockseq
      var _seedBytes = _rng();
    
      // Per 4.5, create and 48-bit node id, (47 random bits + multicast bit = 1)
      var _nodeId = [
        _seedBytes[0] | 0x01,
        _seedBytes[1], _seedBytes[2], _seedBytes[3], _seedBytes[4], _seedBytes[5]
      ];
    
      // Per 4.2.2, randomize (14 bit) clockseq
      var _clockseq = (_seedBytes[6] << 8 | _seedBytes[7]) & 0x3fff;
    
      // Previous uuid creation time
      var _lastMSecs = 0, _lastNSecs = 0;
    
      // See https://github.com/broofa/node-uuid for API details
      function v1(options, buf, offset) {
        var i = buf && offset || 0;
        var b = buf || [];
    
        options = options || {};
    
        var clockseq = options.clockseq != null ? options.clockseq : _clockseq;
    
        // UUID timestamps are 100 nano-second units since the Gregorian epoch,
        // (1582-10-15 00:00).  JSNumbers aren't precise enough for this, so
        // time is handled internally as 'msecs' (integer milliseconds) and 'nsecs'
        // (100-nanoseconds offset from msecs) since unix epoch, 1970-01-01 00:00.
        var msecs = options.msecs != null ? options.msecs : new Date().getTime();
    
        // Per 4.2.1.2, use count of uuid's generated during the current clock
        // cycle to simulate higher resolution clock
        var nsecs = options.nsecs != null ? options.nsecs : _lastNSecs + 1;
    
        // Time since last uuid creation (in msecs)
        var dt = (msecs - _lastMSecs) + (nsecs - _lastNSecs)/10000;
    
        // Per 4.2.1.2, Bump clockseq on clock regression
        if (dt < 0 && options.clockseq == null) {
          clockseq = clockseq + 1 & 0x3fff;
        }
    
        // Reset nsecs if clock regresses (new clockseq) or we've moved onto a new
        // time interval
        if ((dt < 0 || msecs > _lastMSecs) && options.nsecs == null) {
          nsecs = 0;
        }
    
        // Per 4.2.1.2 Throw error if too many uuids are requested
        if (nsecs >= 10000) {
          throw new Error('uuid.v1(): Can\'t create more than 10M uuids/sec');
        }
    
        _lastMSecs = msecs;
        _lastNSecs = nsecs;
        _clockseq = clockseq;
    
        // Per 4.1.4 - Convert from unix epoch to Gregorian epoch
        msecs += 12219292800000;
    
        // `time_low`
        var tl = ((msecs & 0xfffffff) * 10000 + nsecs) % 0x100000000;
        b[i++] = tl >>> 24 & 0xff;
        b[i++] = tl >>> 16 & 0xff;
        b[i++] = tl >>> 8 & 0xff;
        b[i++] = tl & 0xff;
    
        // `time_mid`
        var tmh = (msecs / 0x100000000 * 10000) & 0xfffffff;
        b[i++] = tmh >>> 8 & 0xff;
        b[i++] = tmh & 0xff;
    
        // `time_high_and_version`
        b[i++] = tmh >>> 24 & 0xf | 0x10; // include version
        b[i++] = tmh >>> 16 & 0xff;
    
        // `clock_seq_hi_and_reserved` (Per 4.2.2 - include variant)
        b[i++] = clockseq >>> 8 | 0x80;
    
        // `clock_seq_low`
        b[i++] = clockseq & 0xff;
    
        // `node`
        var node = options.node || _nodeId;
        for (var n = 0; n < 6; n++) {
          b[i + n] = node[n];
        }
    
        return buf ? buf : unparse(b);
      }
    
      // **`v4()` - Generate random UUID**
    
      // See https://github.com/broofa/node-uuid for API details
      function v4(options, buf, offset) {
        // Deprecated - 'format' argument, as supported in v1.2
        var i = buf && offset || 0;
    
        if (typeof(options) == 'string') {
          buf = options == 'binary' ? new BufferClass(16) : null;
          options = null;
        }
        options = options || {};
    
        var rnds = options.random || (options.rng || _rng)();
    
        // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`
        rnds[6] = (rnds[6] & 0x0f) | 0x40;
        rnds[8] = (rnds[8] & 0x3f) | 0x80;
    
        // Copy bytes to buffer, if provided
        if (buf) {
          for (var ii = 0; ii < 16; ii++) {
            buf[i + ii] = rnds[ii];
          }
        }
    
        return buf || unparse(rnds);
      }
    
      // Export public API
      var uuid = v4;
      uuid.v1 = v1;
      uuid.v4 = v4;
      uuid.parse = parse;
      uuid.unparse = unparse;
      uuid.BufferClass = BufferClass;
    
      if (typeof define === 'function' && define.amd) {
        // Publish as AMD module
        define(function() {return uuid;});
      } else if (typeof(module) != 'undefined' && module.exports) {
        // Publish as node.js module
        module.exports = uuid;
      } else {
        // Publish as global (in browsers)
        var _previousRoot = _global.uuid;
    
        // **`noConflict()` - (browser only) to reset global 'uuid' var**
        uuid.noConflict = function() {
          _global.uuid = _previousRoot;
          return uuid;
        };
    
        _global.uuid = uuid;
      }
    }).call(this);
    
  provide("node-uuid", module.exports);
}(global));

// pakmanager:qs
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  module.exports = require('./lib/');
    
  provide("qs", module.exports);
}(global));

// pakmanager:tunnel-agent
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  'use strict'
    
    var net = require('net')
      , tls = require('tls')
      , http = require('http')
      , https = require('https')
      , events = require('events')
      , assert = require('assert')
      , util = require('util')
      ;
    
    exports.httpOverHttp = httpOverHttp
    exports.httpsOverHttp = httpsOverHttp
    exports.httpOverHttps = httpOverHttps
    exports.httpsOverHttps = httpsOverHttps
    
    
    function httpOverHttp(options) {
      var agent = new TunnelingAgent(options)
      agent.request = http.request
      return agent
    }
    
    function httpsOverHttp(options) {
      var agent = new TunnelingAgent(options)
      agent.request = http.request
      agent.createSocket = createSecureSocket
      return agent
    }
    
    function httpOverHttps(options) {
      var agent = new TunnelingAgent(options)
      agent.request = https.request
      return agent
    }
    
    function httpsOverHttps(options) {
      var agent = new TunnelingAgent(options)
      agent.request = https.request
      agent.createSocket = createSecureSocket
      return agent
    }
    
    
    function TunnelingAgent(options) {
      var self = this
      self.options = options || {}
      self.proxyOptions = self.options.proxy || {}
      self.maxSockets = self.options.maxSockets || http.Agent.defaultMaxSockets
      self.requests = []
      self.sockets = []
    
      self.on('free', function onFree(socket, host, port) {
        for (var i = 0, len = self.requests.length; i < len; ++i) {
          var pending = self.requests[i]
          if (pending.host === host && pending.port === port) {
            // Detect the request to connect same origin server,
            // reuse the connection.
            self.requests.splice(i, 1)
            pending.request.onSocket(socket)
            return
          }
        }
        socket.destroy()
        self.removeSocket(socket)
      })
    }
    util.inherits(TunnelingAgent, events.EventEmitter)
    
    TunnelingAgent.prototype.addRequest = function addRequest(req, options) {
      var self = this
    
       // Legacy API: addRequest(req, host, port, path)
      if (typeof options === 'string') {
        options = {
          host: options,
          port: arguments[2],
          path: arguments[3]
        };
      }
    
      if (self.sockets.length >= this.maxSockets) {
        // We are over limit so we'll add it to the queue.
        self.requests.push({host: host, port: port, request: req})
        return
      }
    
      // If we are under maxSockets create a new one.
      self.createSocket({host: options.host, port: options.port, request: req}, function(socket) {
        socket.on('free', onFree)
        socket.on('close', onCloseOrRemove)
        socket.on('agentRemove', onCloseOrRemove)
        req.onSocket(socket)
    
        function onFree() {
          self.emit('free', socket, options.host, options.port)
        }
    
        function onCloseOrRemove(err) {
          self.removeSocket()
          socket.removeListener('free', onFree)
          socket.removeListener('close', onCloseOrRemove)
          socket.removeListener('agentRemove', onCloseOrRemove)
        }
      })
    }
    
    TunnelingAgent.prototype.createSocket = function createSocket(options, cb) {
      var self = this
      var placeholder = {}
      self.sockets.push(placeholder)
    
      var connectOptions = mergeOptions({}, self.proxyOptions, 
        { method: 'CONNECT'
        , path: options.host + ':' + options.port
        , agent: false
        }
      )
      if (connectOptions.proxyAuth) {
        connectOptions.headers = connectOptions.headers || {}
        connectOptions.headers['Proxy-Authorization'] = 'Basic ' +
            new Buffer(connectOptions.proxyAuth).toString('base64')
      }
    
      debug('making CONNECT request')
      var connectReq = self.request(connectOptions)
      connectReq.useChunkedEncodingByDefault = false // for v0.6
      connectReq.once('response', onResponse) // for v0.6
      connectReq.once('upgrade', onUpgrade)   // for v0.6
      connectReq.once('connect', onConnect)   // for v0.7 or later
      connectReq.once('error', onError)
      connectReq.end()
    
      function onResponse(res) {
        // Very hacky. This is necessary to avoid http-parser leaks.
        res.upgrade = true
      }
    
      function onUpgrade(res, socket, head) {
        // Hacky.
        process.nextTick(function() {
          onConnect(res, socket, head)
        })
      }
    
      function onConnect(res, socket, head) {
        connectReq.removeAllListeners()
        socket.removeAllListeners()
    
        if (res.statusCode === 200) {
          assert.equal(head.length, 0)
          debug('tunneling connection has established')
          self.sockets[self.sockets.indexOf(placeholder)] = socket
          cb(socket)
        } else {
          debug('tunneling socket could not be established, statusCode=%d', res.statusCode)
          var error = new Error('tunneling socket could not be established, ' + 'statusCode=' + res.statusCode)
          error.code = 'ECONNRESET'
          options.request.emit('error', error)
          self.removeSocket(placeholder)
        }
      }
    
      function onError(cause) {
        connectReq.removeAllListeners()
    
        debug('tunneling socket could not be established, cause=%s\n', cause.message, cause.stack)
        var error = new Error('tunneling socket could not be established, ' + 'cause=' + cause.message)
        error.code = 'ECONNRESET'
        options.request.emit('error', error)
        self.removeSocket(placeholder)
      }
    }
    
    TunnelingAgent.prototype.removeSocket = function removeSocket(socket) {
      var pos = this.sockets.indexOf(socket)
      if (pos === -1) return
      
      this.sockets.splice(pos, 1)
    
      var pending = this.requests.shift()
      if (pending) {
        // If we have pending requests and a socket gets closed a new one
        // needs to be created to take over in the pool for the one that closed.
        this.createSocket(pending, function(socket) {
          pending.request.onSocket(socket)
        })
      }
    }
    
    function createSecureSocket(options, cb) {
      var self = this
      TunnelingAgent.prototype.createSocket.call(self, options, function(socket) {
        // 0 is dummy port for v0.6
        var secureSocket = tls.connect(0, mergeOptions({}, self.options, 
          { servername: options.host
          , socket: socket
          }
        ))
        cb(secureSocket)
      })
    }
    
    
    function mergeOptions(target) {
      for (var i = 1, len = arguments.length; i < len; ++i) {
        var overrides = arguments[i]
        if (typeof overrides === 'object') {
          var keys = Object.keys(overrides)
          for (var j = 0, keyLen = keys.length; j < keyLen; ++j) {
            var k = keys[j]
            if (overrides[k] !== undefined) {
              target[k] = overrides[k]
            }
          }
        }
      }
      return target
    }
    
    
    var debug
    if (process.env.NODE_DEBUG && /\btunnel\b/.test(process.env.NODE_DEBUG)) {
      debug = function() {
        var args = Array.prototype.slice.call(arguments)
        if (typeof args[0] === 'string') {
          args[0] = 'TUNNEL: ' + args[0]
        } else {
          args.unshift('TUNNEL:')
        }
        console.error.apply(console, args)
      }
    } else {
      debug = function() {}
    }
    exports.debug = debug // for test
    
  provide("tunnel-agent", module.exports);
}(global));

// pakmanager:tough-cookie/lib/pubsuffix
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  /****************************************************
     * AUTOMATICALLY GENERATED by generate-pubsuffix.js *
     *                  DO NOT EDIT!                    *
     ****************************************************/
    
    module.exports.getPublicSuffix = function getPublicSuffix(domain) {
      /*
       * Copyright GoInstant, Inc. and other contributors. All rights reserved.
       * Permission is hereby granted, free of charge, to any person obtaining a copy
       * of this software and associated documentation files (the "Software"), to
       * deal in the Software without restriction, including without limitation the
       * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
       * sell copies of the Software, and to permit persons to whom the Software is
       * furnished to do so, subject to the following conditions:
       *
       * The above copyright notice and this permission notice shall be included in
       * all copies or substantial portions of the Software.
       *
       * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
       * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
       * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
       * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
       * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
       * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
       * IN THE SOFTWARE.
       */
      if (!domain) return null;
      if (domain.match(/^\./)) return null;
    
      domain = domain.toLowerCase();
      var parts = domain.split('.').reverse();
    
      var suffix = '';
      var suffixLen = 0;
      for (var i=0; i<parts.length; i++) {
        var part = parts[i];
        var starstr = '*'+suffix;
        var partstr = part+suffix;
    
        if (index[starstr]) { // star rule matches
          suffixLen = i+1;
          if (index[partstr] === false) { // exception rule matches (NB: false, not undefined)
            suffixLen--;
          }
        } else if (index[partstr]) { // exact match, not exception
          suffixLen = i+1;
        }
    
        suffix = '.'+part+suffix;
      }
    
      if (index['*'+suffix]) { // *.domain exists (e.g. *.kyoto.jp for domain='kyoto.jp');
        return null;
      }
    
      if (suffixLen && parts.length > suffixLen) {
        return parts.slice(0,suffixLen+1).reverse().join('.');
      }
    
      return null;
    };
    
    // The following generated structure is used under the MPL version 1.1
    // See public-suffix.txt for more information
    
    var index = module.exports.index = Object.freeze(
    {"ac":true,"com.ac":true,"edu.ac":true,"gov.ac":true,"net.ac":true,"mil.ac":true,"org.ac":true,"ad":true,"nom.ad":true,"ae":true,"co.ae":true,"net.ae":true,"org.ae":true,"sch.ae":true,"ac.ae":true,"gov.ae":true,"mil.ae":true,"aero":true,"accident-investigation.aero":true,"accident-prevention.aero":true,"aerobatic.aero":true,"aeroclub.aero":true,"aerodrome.aero":true,"agents.aero":true,"aircraft.aero":true,"airline.aero":true,"airport.aero":true,"air-surveillance.aero":true,"airtraffic.aero":true,"air-traffic-control.aero":true,"ambulance.aero":true,"amusement.aero":true,"association.aero":true,"author.aero":true,"ballooning.aero":true,"broker.aero":true,"caa.aero":true,"cargo.aero":true,"catering.aero":true,"certification.aero":true,"championship.aero":true,"charter.aero":true,"civilaviation.aero":true,"club.aero":true,"conference.aero":true,"consultant.aero":true,"consulting.aero":true,"control.aero":true,"council.aero":true,"crew.aero":true,"design.aero":true,"dgca.aero":true,"educator.aero":true,"emergency.aero":true,"engine.aero":true,"engineer.aero":true,"entertainment.aero":true,"equipment.aero":true,"exchange.aero":true,"express.aero":true,"federation.aero":true,"flight.aero":true,"freight.aero":true,"fuel.aero":true,"gliding.aero":true,"government.aero":true,"groundhandling.aero":true,"group.aero":true,"hanggliding.aero":true,"homebuilt.aero":true,"insurance.aero":true,"journal.aero":true,"journalist.aero":true,"leasing.aero":true,"logistics.aero":true,"magazine.aero":true,"maintenance.aero":true,"marketplace.aero":true,"media.aero":true,"microlight.aero":true,"modelling.aero":true,"navigation.aero":true,"parachuting.aero":true,"paragliding.aero":true,"passenger-association.aero":true,"pilot.aero":true,"press.aero":true,"production.aero":true,"recreation.aero":true,"repbody.aero":true,"res.aero":true,"research.aero":true,"rotorcraft.aero":true,"safety.aero":true,"scientist.aero":true,"services.aero":true,"show.aero":true,"skydiving.aero":true,"software.aero":true,"student.aero":true,"taxi.aero":true,"trader.aero":true,"trading.aero":true,"trainer.aero":true,"union.aero":true,"workinggroup.aero":true,"works.aero":true,"af":true,"gov.af":true,"com.af":true,"org.af":true,"net.af":true,"edu.af":true,"ag":true,"com.ag":true,"org.ag":true,"net.ag":true,"co.ag":true,"nom.ag":true,"ai":true,"off.ai":true,"com.ai":true,"net.ai":true,"org.ai":true,"al":true,"com.al":true,"edu.al":true,"gov.al":true,"mil.al":true,"net.al":true,"org.al":true,"am":true,"an":true,"com.an":true,"net.an":true,"org.an":true,"edu.an":true,"ao":true,"ed.ao":true,"gv.ao":true,"og.ao":true,"co.ao":true,"pb.ao":true,"it.ao":true,"aq":true,"*.ar":true,"congresodelalengua3.ar":false,"educ.ar":false,"gobiernoelectronico.ar":false,"mecon.ar":false,"nacion.ar":false,"nic.ar":false,"promocion.ar":false,"retina.ar":false,"uba.ar":false,"e164.arpa":true,"in-addr.arpa":true,"ip6.arpa":true,"iris.arpa":true,"uri.arpa":true,"urn.arpa":true,"as":true,"gov.as":true,"asia":true,"at":true,"ac.at":true,"co.at":true,"gv.at":true,"or.at":true,"com.au":true,"net.au":true,"org.au":true,"edu.au":true,"gov.au":true,"csiro.au":true,"asn.au":true,"id.au":true,"info.au":true,"conf.au":true,"oz.au":true,"act.au":true,"nsw.au":true,"nt.au":true,"qld.au":true,"sa.au":true,"tas.au":true,"vic.au":true,"wa.au":true,"act.edu.au":true,"nsw.edu.au":true,"nt.edu.au":true,"qld.edu.au":true,"sa.edu.au":true,"tas.edu.au":true,"vic.edu.au":true,"wa.edu.au":true,"act.gov.au":true,"nt.gov.au":true,"qld.gov.au":true,"sa.gov.au":true,"tas.gov.au":true,"vic.gov.au":true,"wa.gov.au":true,"aw":true,"com.aw":true,"ax":true,"az":true,"com.az":true,"net.az":true,"int.az":true,"gov.az":true,"org.az":true,"edu.az":true,"info.az":true,"pp.az":true,"mil.az":true,"name.az":true,"pro.az":true,"biz.az":true,"ba":true,"org.ba":true,"net.ba":true,"edu.ba":true,"gov.ba":true,"mil.ba":true,"unsa.ba":true,"unbi.ba":true,"co.ba":true,"com.ba":true,"rs.ba":true,"bb":true,"biz.bb":true,"com.bb":true,"edu.bb":true,"gov.bb":true,"info.bb":true,"net.bb":true,"org.bb":true,"store.bb":true,"*.bd":true,"be":true,"ac.be":true,"bf":true,"gov.bf":true,"bg":true,"a.bg":true,"b.bg":true,"c.bg":true,"d.bg":true,"e.bg":true,"f.bg":true,"g.bg":true,"h.bg":true,"i.bg":true,"j.bg":true,"k.bg":true,"l.bg":true,"m.bg":true,"n.bg":true,"o.bg":true,"p.bg":true,"q.bg":true,"r.bg":true,"s.bg":true,"t.bg":true,"u.bg":true,"v.bg":true,"w.bg":true,"x.bg":true,"y.bg":true,"z.bg":true,"0.bg":true,"1.bg":true,"2.bg":true,"3.bg":true,"4.bg":true,"5.bg":true,"6.bg":true,"7.bg":true,"8.bg":true,"9.bg":true,"bh":true,"com.bh":true,"edu.bh":true,"net.bh":true,"org.bh":true,"gov.bh":true,"bi":true,"co.bi":true,"com.bi":true,"edu.bi":true,"or.bi":true,"org.bi":true,"biz":true,"bj":true,"asso.bj":true,"barreau.bj":true,"gouv.bj":true,"bm":true,"com.bm":true,"edu.bm":true,"gov.bm":true,"net.bm":true,"org.bm":true,"*.bn":true,"bo":true,"com.bo":true,"edu.bo":true,"gov.bo":true,"gob.bo":true,"int.bo":true,"org.bo":true,"net.bo":true,"mil.bo":true,"tv.bo":true,"br":true,"adm.br":true,"adv.br":true,"agr.br":true,"am.br":true,"arq.br":true,"art.br":true,"ato.br":true,"b.br":true,"bio.br":true,"blog.br":true,"bmd.br":true,"can.br":true,"cim.br":true,"cng.br":true,"cnt.br":true,"com.br":true,"coop.br":true,"ecn.br":true,"edu.br":true,"emp.br":true,"eng.br":true,"esp.br":true,"etc.br":true,"eti.br":true,"far.br":true,"flog.br":true,"fm.br":true,"fnd.br":true,"fot.br":true,"fst.br":true,"g12.br":true,"ggf.br":true,"gov.br":true,"imb.br":true,"ind.br":true,"inf.br":true,"jor.br":true,"jus.br":true,"lel.br":true,"mat.br":true,"med.br":true,"mil.br":true,"mus.br":true,"net.br":true,"nom.br":true,"not.br":true,"ntr.br":true,"odo.br":true,"org.br":true,"ppg.br":true,"pro.br":true,"psc.br":true,"psi.br":true,"qsl.br":true,"radio.br":true,"rec.br":true,"slg.br":true,"srv.br":true,"taxi.br":true,"teo.br":true,"tmp.br":true,"trd.br":true,"tur.br":true,"tv.br":true,"vet.br":true,"vlog.br":true,"wiki.br":true,"zlg.br":true,"bs":true,"com.bs":true,"net.bs":true,"org.bs":true,"edu.bs":true,"gov.bs":true,"bt":true,"com.bt":true,"edu.bt":true,"gov.bt":true,"net.bt":true,"org.bt":true,"bw":true,"co.bw":true,"org.bw":true,"by":true,"gov.by":true,"mil.by":true,"com.by":true,"of.by":true,"bz":true,"com.bz":true,"net.bz":true,"org.bz":true,"edu.bz":true,"gov.bz":true,"ca":true,"ab.ca":true,"bc.ca":true,"mb.ca":true,"nb.ca":true,"nf.ca":true,"nl.ca":true,"ns.ca":true,"nt.ca":true,"nu.ca":true,"on.ca":true,"pe.ca":true,"qc.ca":true,"sk.ca":true,"yk.ca":true,"gc.ca":true,"cat":true,"cc":true,"cd":true,"gov.cd":true,"cf":true,"cg":true,"ch":true,"ci":true,"org.ci":true,"or.ci":true,"com.ci":true,"co.ci":true,"edu.ci":true,"ed.ci":true,"ac.ci":true,"net.ci":true,"go.ci":true,"asso.ci":true,"xn--aroport-bya.ci":true,"int.ci":true,"presse.ci":true,"md.ci":true,"gouv.ci":true,"*.ck":true,"www.ck":false,"cl":true,"gov.cl":true,"gob.cl":true,"co.cl":true,"mil.cl":true,"cm":true,"gov.cm":true,"cn":true,"ac.cn":true,"com.cn":true,"edu.cn":true,"gov.cn":true,"net.cn":true,"org.cn":true,"mil.cn":true,"xn--55qx5d.cn":true,"xn--io0a7i.cn":true,"xn--od0alg.cn":true,"ah.cn":true,"bj.cn":true,"cq.cn":true,"fj.cn":true,"gd.cn":true,"gs.cn":true,"gz.cn":true,"gx.cn":true,"ha.cn":true,"hb.cn":true,"he.cn":true,"hi.cn":true,"hl.cn":true,"hn.cn":true,"jl.cn":true,"js.cn":true,"jx.cn":true,"ln.cn":true,"nm.cn":true,"nx.cn":true,"qh.cn":true,"sc.cn":true,"sd.cn":true,"sh.cn":true,"sn.cn":true,"sx.cn":true,"tj.cn":true,"xj.cn":true,"xz.cn":true,"yn.cn":true,"zj.cn":true,"hk.cn":true,"mo.cn":true,"tw.cn":true,"co":true,"arts.co":true,"com.co":true,"edu.co":true,"firm.co":true,"gov.co":true,"info.co":true,"int.co":true,"mil.co":true,"net.co":true,"nom.co":true,"org.co":true,"rec.co":true,"web.co":true,"com":true,"coop":true,"cr":true,"ac.cr":true,"co.cr":true,"ed.cr":true,"fi.cr":true,"go.cr":true,"or.cr":true,"sa.cr":true,"cu":true,"com.cu":true,"edu.cu":true,"org.cu":true,"net.cu":true,"gov.cu":true,"inf.cu":true,"cv":true,"cx":true,"gov.cx":true,"*.cy":true,"cz":true,"de":true,"dj":true,"dk":true,"dm":true,"com.dm":true,"net.dm":true,"org.dm":true,"edu.dm":true,"gov.dm":true,"do":true,"art.do":true,"com.do":true,"edu.do":true,"gob.do":true,"gov.do":true,"mil.do":true,"net.do":true,"org.do":true,"sld.do":true,"web.do":true,"dz":true,"com.dz":true,"org.dz":true,"net.dz":true,"gov.dz":true,"edu.dz":true,"asso.dz":true,"pol.dz":true,"art.dz":true,"ec":true,"com.ec":true,"info.ec":true,"net.ec":true,"fin.ec":true,"k12.ec":true,"med.ec":true,"pro.ec":true,"org.ec":true,"edu.ec":true,"gov.ec":true,"gob.ec":true,"mil.ec":true,"edu":true,"ee":true,"edu.ee":true,"gov.ee":true,"riik.ee":true,"lib.ee":true,"med.ee":true,"com.ee":true,"pri.ee":true,"aip.ee":true,"org.ee":true,"fie.ee":true,"eg":true,"com.eg":true,"edu.eg":true,"eun.eg":true,"gov.eg":true,"mil.eg":true,"name.eg":true,"net.eg":true,"org.eg":true,"sci.eg":true,"*.er":true,"es":true,"com.es":true,"nom.es":true,"org.es":true,"gob.es":true,"edu.es":true,"*.et":true,"eu":true,"fi":true,"aland.fi":true,"*.fj":true,"*.fk":true,"fm":true,"fo":true,"fr":true,"com.fr":true,"asso.fr":true,"nom.fr":true,"prd.fr":true,"presse.fr":true,"tm.fr":true,"aeroport.fr":true,"assedic.fr":true,"avocat.fr":true,"avoues.fr":true,"cci.fr":true,"chambagri.fr":true,"chirurgiens-dentistes.fr":true,"experts-comptables.fr":true,"geometre-expert.fr":true,"gouv.fr":true,"greta.fr":true,"huissier-justice.fr":true,"medecin.fr":true,"notaires.fr":true,"pharmacien.fr":true,"port.fr":true,"veterinaire.fr":true,"ga":true,"gd":true,"ge":true,"com.ge":true,"edu.ge":true,"gov.ge":true,"org.ge":true,"mil.ge":true,"net.ge":true,"pvt.ge":true,"gf":true,"gg":true,"co.gg":true,"org.gg":true,"net.gg":true,"sch.gg":true,"gov.gg":true,"gh":true,"com.gh":true,"edu.gh":true,"gov.gh":true,"org.gh":true,"mil.gh":true,"gi":true,"com.gi":true,"ltd.gi":true,"gov.gi":true,"mod.gi":true,"edu.gi":true,"org.gi":true,"gl":true,"gm":true,"ac.gn":true,"com.gn":true,"edu.gn":true,"gov.gn":true,"org.gn":true,"net.gn":true,"gov":true,"gp":true,"com.gp":true,"net.gp":true,"mobi.gp":true,"edu.gp":true,"org.gp":true,"asso.gp":true,"gq":true,"gr":true,"com.gr":true,"edu.gr":true,"net.gr":true,"org.gr":true,"gov.gr":true,"gs":true,"*.gt":true,"www.gt":false,"*.gu":true,"gw":true,"gy":true,"co.gy":true,"com.gy":true,"net.gy":true,"hk":true,"com.hk":true,"edu.hk":true,"gov.hk":true,"idv.hk":true,"net.hk":true,"org.hk":true,"xn--55qx5d.hk":true,"xn--wcvs22d.hk":true,"xn--lcvr32d.hk":true,"xn--mxtq1m.hk":true,"xn--gmqw5a.hk":true,"xn--ciqpn.hk":true,"xn--gmq050i.hk":true,"xn--zf0avx.hk":true,"xn--io0a7i.hk":true,"xn--mk0axi.hk":true,"xn--od0alg.hk":true,"xn--od0aq3b.hk":true,"xn--tn0ag.hk":true,"xn--uc0atv.hk":true,"xn--uc0ay4a.hk":true,"hm":true,"hn":true,"com.hn":true,"edu.hn":true,"org.hn":true,"net.hn":true,"mil.hn":true,"gob.hn":true,"hr":true,"iz.hr":true,"from.hr":true,"name.hr":true,"com.hr":true,"ht":true,"com.ht":true,"shop.ht":true,"firm.ht":true,"info.ht":true,"adult.ht":true,"net.ht":true,"pro.ht":true,"org.ht":true,"med.ht":true,"art.ht":true,"coop.ht":true,"pol.ht":true,"asso.ht":true,"edu.ht":true,"rel.ht":true,"gouv.ht":true,"perso.ht":true,"hu":true,"co.hu":true,"info.hu":true,"org.hu":true,"priv.hu":true,"sport.hu":true,"tm.hu":true,"2000.hu":true,"agrar.hu":true,"bolt.hu":true,"casino.hu":true,"city.hu":true,"erotica.hu":true,"erotika.hu":true,"film.hu":true,"forum.hu":true,"games.hu":true,"hotel.hu":true,"ingatlan.hu":true,"jogasz.hu":true,"konyvelo.hu":true,"lakas.hu":true,"media.hu":true,"news.hu":true,"reklam.hu":true,"sex.hu":true,"shop.hu":true,"suli.hu":true,"szex.hu":true,"tozsde.hu":true,"utazas.hu":true,"video.hu":true,"id":true,"ac.id":true,"co.id":true,"go.id":true,"mil.id":true,"net.id":true,"or.id":true,"sch.id":true,"web.id":true,"ie":true,"gov.ie":true,"*.il":true,"im":true,"co.im":true,"ltd.co.im":true,"plc.co.im":true,"net.im":true,"gov.im":true,"org.im":true,"nic.im":true,"ac.im":true,"in":true,"co.in":true,"firm.in":true,"net.in":true,"org.in":true,"gen.in":true,"ind.in":true,"nic.in":true,"ac.in":true,"edu.in":true,"res.in":true,"gov.in":true,"mil.in":true,"info":true,"int":true,"eu.int":true,"io":true,"com.io":true,"iq":true,"gov.iq":true,"edu.iq":true,"mil.iq":true,"com.iq":true,"org.iq":true,"net.iq":true,"ir":true,"ac.ir":true,"co.ir":true,"gov.ir":true,"id.ir":true,"net.ir":true,"org.ir":true,"sch.ir":true,"xn--mgba3a4f16a.ir":true,"xn--mgba3a4fra.ir":true,"is":true,"net.is":true,"com.is":true,"edu.is":true,"gov.is":true,"org.is":true,"int.is":true,"it":true,"gov.it":true,"edu.it":true,"agrigento.it":true,"ag.it":true,"alessandria.it":true,"al.it":true,"ancona.it":true,"an.it":true,"aosta.it":true,"aoste.it":true,"ao.it":true,"arezzo.it":true,"ar.it":true,"ascoli-piceno.it":true,"ascolipiceno.it":true,"ap.it":true,"asti.it":true,"at.it":true,"avellino.it":true,"av.it":true,"bari.it":true,"ba.it":true,"andria-barletta-trani.it":true,"andriabarlettatrani.it":true,"trani-barletta-andria.it":true,"tranibarlettaandria.it":true,"barletta-trani-andria.it":true,"barlettatraniandria.it":true,"andria-trani-barletta.it":true,"andriatranibarletta.it":true,"trani-andria-barletta.it":true,"traniandriabarletta.it":true,"bt.it":true,"belluno.it":true,"bl.it":true,"benevento.it":true,"bn.it":true,"bergamo.it":true,"bg.it":true,"biella.it":true,"bi.it":true,"bologna.it":true,"bo.it":true,"bolzano.it":true,"bozen.it":true,"balsan.it":true,"alto-adige.it":true,"altoadige.it":true,"suedtirol.it":true,"bz.it":true,"brescia.it":true,"bs.it":true,"brindisi.it":true,"br.it":true,"cagliari.it":true,"ca.it":true,"caltanissetta.it":true,"cl.it":true,"campobasso.it":true,"cb.it":true,"carboniaiglesias.it":true,"carbonia-iglesias.it":true,"iglesias-carbonia.it":true,"iglesiascarbonia.it":true,"ci.it":true,"caserta.it":true,"ce.it":true,"catania.it":true,"ct.it":true,"catanzaro.it":true,"cz.it":true,"chieti.it":true,"ch.it":true,"como.it":true,"co.it":true,"cosenza.it":true,"cs.it":true,"cremona.it":true,"cr.it":true,"crotone.it":true,"kr.it":true,"cuneo.it":true,"cn.it":true,"dell-ogliastra.it":true,"dellogliastra.it":true,"ogliastra.it":true,"og.it":true,"enna.it":true,"en.it":true,"ferrara.it":true,"fe.it":true,"fermo.it":true,"fm.it":true,"firenze.it":true,"florence.it":true,"fi.it":true,"foggia.it":true,"fg.it":true,"forli-cesena.it":true,"forlicesena.it":true,"cesena-forli.it":true,"cesenaforli.it":true,"fc.it":true,"frosinone.it":true,"fr.it":true,"genova.it":true,"genoa.it":true,"ge.it":true,"gorizia.it":true,"go.it":true,"grosseto.it":true,"gr.it":true,"imperia.it":true,"im.it":true,"isernia.it":true,"is.it":true,"laquila.it":true,"aquila.it":true,"aq.it":true,"la-spezia.it":true,"laspezia.it":true,"sp.it":true,"latina.it":true,"lt.it":true,"lecce.it":true,"le.it":true,"lecco.it":true,"lc.it":true,"livorno.it":true,"li.it":true,"lodi.it":true,"lo.it":true,"lucca.it":true,"lu.it":true,"macerata.it":true,"mc.it":true,"mantova.it":true,"mn.it":true,"massa-carrara.it":true,"massacarrara.it":true,"carrara-massa.it":true,"carraramassa.it":true,"ms.it":true,"matera.it":true,"mt.it":true,"medio-campidano.it":true,"mediocampidano.it":true,"campidano-medio.it":true,"campidanomedio.it":true,"vs.it":true,"messina.it":true,"me.it":true,"milano.it":true,"milan.it":true,"mi.it":true,"modena.it":true,"mo.it":true,"monza.it":true,"monza-brianza.it":true,"monzabrianza.it":true,"monzaebrianza.it":true,"monzaedellabrianza.it":true,"monza-e-della-brianza.it":true,"mb.it":true,"napoli.it":true,"naples.it":true,"na.it":true,"novara.it":true,"no.it":true,"nuoro.it":true,"nu.it":true,"oristano.it":true,"or.it":true,"padova.it":true,"padua.it":true,"pd.it":true,"palermo.it":true,"pa.it":true,"parma.it":true,"pr.it":true,"pavia.it":true,"pv.it":true,"perugia.it":true,"pg.it":true,"pescara.it":true,"pe.it":true,"pesaro-urbino.it":true,"pesarourbino.it":true,"urbino-pesaro.it":true,"urbinopesaro.it":true,"pu.it":true,"piacenza.it":true,"pc.it":true,"pisa.it":true,"pi.it":true,"pistoia.it":true,"pt.it":true,"pordenone.it":true,"pn.it":true,"potenza.it":true,"pz.it":true,"prato.it":true,"po.it":true,"ragusa.it":true,"rg.it":true,"ravenna.it":true,"ra.it":true,"reggio-calabria.it":true,"reggiocalabria.it":true,"rc.it":true,"reggio-emilia.it":true,"reggioemilia.it":true,"re.it":true,"rieti.it":true,"ri.it":true,"rimini.it":true,"rn.it":true,"roma.it":true,"rome.it":true,"rm.it":true,"rovigo.it":true,"ro.it":true,"salerno.it":true,"sa.it":true,"sassari.it":true,"ss.it":true,"savona.it":true,"sv.it":true,"siena.it":true,"si.it":true,"siracusa.it":true,"sr.it":true,"sondrio.it":true,"so.it":true,"taranto.it":true,"ta.it":true,"tempio-olbia.it":true,"tempioolbia.it":true,"olbia-tempio.it":true,"olbiatempio.it":true,"ot.it":true,"teramo.it":true,"te.it":true,"terni.it":true,"tr.it":true,"torino.it":true,"turin.it":true,"to.it":true,"trapani.it":true,"tp.it":true,"trento.it":true,"trentino.it":true,"tn.it":true,"treviso.it":true,"tv.it":true,"trieste.it":true,"ts.it":true,"udine.it":true,"ud.it":true,"varese.it":true,"va.it":true,"venezia.it":true,"venice.it":true,"ve.it":true,"verbania.it":true,"vb.it":true,"vercelli.it":true,"vc.it":true,"verona.it":true,"vr.it":true,"vibo-valentia.it":true,"vibovalentia.it":true,"vv.it":true,"vicenza.it":true,"vi.it":true,"viterbo.it":true,"vt.it":true,"je":true,"co.je":true,"org.je":true,"net.je":true,"sch.je":true,"gov.je":true,"*.jm":true,"jo":true,"com.jo":true,"org.jo":true,"net.jo":true,"edu.jo":true,"sch.jo":true,"gov.jo":true,"mil.jo":true,"name.jo":true,"jobs":true,"jp":true,"ac.jp":true,"ad.jp":true,"co.jp":true,"ed.jp":true,"go.jp":true,"gr.jp":true,"lg.jp":true,"ne.jp":true,"or.jp":true,"*.aichi.jp":true,"*.akita.jp":true,"*.aomori.jp":true,"*.chiba.jp":true,"*.ehime.jp":true,"*.fukui.jp":true,"*.fukuoka.jp":true,"*.fukushima.jp":true,"*.gifu.jp":true,"*.gunma.jp":true,"*.hiroshima.jp":true,"*.hokkaido.jp":true,"*.hyogo.jp":true,"*.ibaraki.jp":true,"*.ishikawa.jp":true,"*.iwate.jp":true,"*.kagawa.jp":true,"*.kagoshima.jp":true,"*.kanagawa.jp":true,"*.kawasaki.jp":true,"*.kitakyushu.jp":true,"*.kobe.jp":true,"*.kochi.jp":true,"*.kumamoto.jp":true,"*.kyoto.jp":true,"*.mie.jp":true,"*.miyagi.jp":true,"*.miyazaki.jp":true,"*.nagano.jp":true,"*.nagasaki.jp":true,"*.nagoya.jp":true,"*.nara.jp":true,"*.niigata.jp":true,"*.oita.jp":true,"*.okayama.jp":true,"*.okinawa.jp":true,"*.osaka.jp":true,"*.saga.jp":true,"*.saitama.jp":true,"*.sapporo.jp":true,"*.sendai.jp":true,"*.shiga.jp":true,"*.shimane.jp":true,"*.shizuoka.jp":true,"*.tochigi.jp":true,"*.tokushima.jp":true,"*.tokyo.jp":true,"*.tottori.jp":true,"*.toyama.jp":true,"*.wakayama.jp":true,"*.yamagata.jp":true,"*.yamaguchi.jp":true,"*.yamanashi.jp":true,"*.yokohama.jp":true,"metro.tokyo.jp":false,"pref.aichi.jp":false,"pref.akita.jp":false,"pref.aomori.jp":false,"pref.chiba.jp":false,"pref.ehime.jp":false,"pref.fukui.jp":false,"pref.fukuoka.jp":false,"pref.fukushima.jp":false,"pref.gifu.jp":false,"pref.gunma.jp":false,"pref.hiroshima.jp":false,"pref.hokkaido.jp":false,"pref.hyogo.jp":false,"pref.ibaraki.jp":false,"pref.ishikawa.jp":false,"pref.iwate.jp":false,"pref.kagawa.jp":false,"pref.kagoshima.jp":false,"pref.kanagawa.jp":false,"pref.kochi.jp":false,"pref.kumamoto.jp":false,"pref.kyoto.jp":false,"pref.mie.jp":false,"pref.miyagi.jp":false,"pref.miyazaki.jp":false,"pref.nagano.jp":false,"pref.nagasaki.jp":false,"pref.nara.jp":false,"pref.niigata.jp":false,"pref.oita.jp":false,"pref.okayama.jp":false,"pref.okinawa.jp":false,"pref.osaka.jp":false,"pref.saga.jp":false,"pref.saitama.jp":false,"pref.shiga.jp":false,"pref.shimane.jp":false,"pref.shizuoka.jp":false,"pref.tochigi.jp":false,"pref.tokushima.jp":false,"pref.tottori.jp":false,"pref.toyama.jp":false,"pref.wakayama.jp":false,"pref.yamagata.jp":false,"pref.yamaguchi.jp":false,"pref.yamanashi.jp":false,"city.chiba.jp":false,"city.fukuoka.jp":false,"city.hiroshima.jp":false,"city.kawasaki.jp":false,"city.kitakyushu.jp":false,"city.kobe.jp":false,"city.kyoto.jp":false,"city.nagoya.jp":false,"city.niigata.jp":false,"city.okayama.jp":false,"city.osaka.jp":false,"city.saitama.jp":false,"city.sapporo.jp":false,"city.sendai.jp":false,"city.shizuoka.jp":false,"city.yokohama.jp":false,"*.ke":true,"kg":true,"org.kg":true,"net.kg":true,"com.kg":true,"edu.kg":true,"gov.kg":true,"mil.kg":true,"*.kh":true,"ki":true,"edu.ki":true,"biz.ki":true,"net.ki":true,"org.ki":true,"gov.ki":true,"info.ki":true,"com.ki":true,"km":true,"org.km":true,"nom.km":true,"gov.km":true,"prd.km":true,"tm.km":true,"edu.km":true,"mil.km":true,"ass.km":true,"com.km":true,"coop.km":true,"asso.km":true,"presse.km":true,"medecin.km":true,"notaires.km":true,"pharmaciens.km":true,"veterinaire.km":true,"gouv.km":true,"kn":true,"net.kn":true,"org.kn":true,"edu.kn":true,"gov.kn":true,"com.kp":true,"edu.kp":true,"gov.kp":true,"org.kp":true,"rep.kp":true,"tra.kp":true,"kr":true,"ac.kr":true,"co.kr":true,"es.kr":true,"go.kr":true,"hs.kr":true,"kg.kr":true,"mil.kr":true,"ms.kr":true,"ne.kr":true,"or.kr":true,"pe.kr":true,"re.kr":true,"sc.kr":true,"busan.kr":true,"chungbuk.kr":true,"chungnam.kr":true,"daegu.kr":true,"daejeon.kr":true,"gangwon.kr":true,"gwangju.kr":true,"gyeongbuk.kr":true,"gyeonggi.kr":true,"gyeongnam.kr":true,"incheon.kr":true,"jeju.kr":true,"jeonbuk.kr":true,"jeonnam.kr":true,"seoul.kr":true,"ulsan.kr":true,"*.kw":true,"ky":true,"edu.ky":true,"gov.ky":true,"com.ky":true,"org.ky":true,"net.ky":true,"kz":true,"org.kz":true,"edu.kz":true,"net.kz":true,"gov.kz":true,"mil.kz":true,"com.kz":true,"la":true,"int.la":true,"net.la":true,"info.la":true,"edu.la":true,"gov.la":true,"per.la":true,"com.la":true,"org.la":true,"com.lb":true,"edu.lb":true,"gov.lb":true,"net.lb":true,"org.lb":true,"lc":true,"com.lc":true,"net.lc":true,"co.lc":true,"org.lc":true,"edu.lc":true,"gov.lc":true,"li":true,"lk":true,"gov.lk":true,"sch.lk":true,"net.lk":true,"int.lk":true,"com.lk":true,"org.lk":true,"edu.lk":true,"ngo.lk":true,"soc.lk":true,"web.lk":true,"ltd.lk":true,"assn.lk":true,"grp.lk":true,"hotel.lk":true,"com.lr":true,"edu.lr":true,"gov.lr":true,"org.lr":true,"net.lr":true,"ls":true,"co.ls":true,"org.ls":true,"lt":true,"gov.lt":true,"lu":true,"lv":true,"com.lv":true,"edu.lv":true,"gov.lv":true,"org.lv":true,"mil.lv":true,"id.lv":true,"net.lv":true,"asn.lv":true,"conf.lv":true,"ly":true,"com.ly":true,"net.ly":true,"gov.ly":true,"plc.ly":true,"edu.ly":true,"sch.ly":true,"med.ly":true,"org.ly":true,"id.ly":true,"ma":true,"co.ma":true,"net.ma":true,"gov.ma":true,"org.ma":true,"ac.ma":true,"press.ma":true,"mc":true,"tm.mc":true,"asso.mc":true,"md":true,"me":true,"co.me":true,"net.me":true,"org.me":true,"edu.me":true,"ac.me":true,"gov.me":true,"its.me":true,"priv.me":true,"mg":true,"org.mg":true,"nom.mg":true,"gov.mg":true,"prd.mg":true,"tm.mg":true,"edu.mg":true,"mil.mg":true,"com.mg":true,"mh":true,"mil":true,"mk":true,"com.mk":true,"org.mk":true,"net.mk":true,"edu.mk":true,"gov.mk":true,"inf.mk":true,"name.mk":true,"ml":true,"com.ml":true,"edu.ml":true,"gouv.ml":true,"gov.ml":true,"net.ml":true,"org.ml":true,"presse.ml":true,"*.mm":true,"mn":true,"gov.mn":true,"edu.mn":true,"org.mn":true,"mo":true,"com.mo":true,"net.mo":true,"org.mo":true,"edu.mo":true,"gov.mo":true,"mobi":true,"mp":true,"mq":true,"mr":true,"gov.mr":true,"ms":true,"*.mt":true,"mu":true,"com.mu":true,"net.mu":true,"org.mu":true,"gov.mu":true,"ac.mu":true,"co.mu":true,"or.mu":true,"museum":true,"academy.museum":true,"agriculture.museum":true,"air.museum":true,"airguard.museum":true,"alabama.museum":true,"alaska.museum":true,"amber.museum":true,"ambulance.museum":true,"american.museum":true,"americana.museum":true,"americanantiques.museum":true,"americanart.museum":true,"amsterdam.museum":true,"and.museum":true,"annefrank.museum":true,"anthro.museum":true,"anthropology.museum":true,"antiques.museum":true,"aquarium.museum":true,"arboretum.museum":true,"archaeological.museum":true,"archaeology.museum":true,"architecture.museum":true,"art.museum":true,"artanddesign.museum":true,"artcenter.museum":true,"artdeco.museum":true,"arteducation.museum":true,"artgallery.museum":true,"arts.museum":true,"artsandcrafts.museum":true,"asmatart.museum":true,"assassination.museum":true,"assisi.museum":true,"association.museum":true,"astronomy.museum":true,"atlanta.museum":true,"austin.museum":true,"australia.museum":true,"automotive.museum":true,"aviation.museum":true,"axis.museum":true,"badajoz.museum":true,"baghdad.museum":true,"bahn.museum":true,"bale.museum":true,"baltimore.museum":true,"barcelona.museum":true,"baseball.museum":true,"basel.museum":true,"baths.museum":true,"bauern.museum":true,"beauxarts.museum":true,"beeldengeluid.museum":true,"bellevue.museum":true,"bergbau.museum":true,"berkeley.museum":true,"berlin.museum":true,"bern.museum":true,"bible.museum":true,"bilbao.museum":true,"bill.museum":true,"birdart.museum":true,"birthplace.museum":true,"bonn.museum":true,"boston.museum":true,"botanical.museum":true,"botanicalgarden.museum":true,"botanicgarden.museum":true,"botany.museum":true,"brandywinevalley.museum":true,"brasil.museum":true,"bristol.museum":true,"british.museum":true,"britishcolumbia.museum":true,"broadcast.museum":true,"brunel.museum":true,"brussel.museum":true,"brussels.museum":true,"bruxelles.museum":true,"building.museum":true,"burghof.museum":true,"bus.museum":true,"bushey.museum":true,"cadaques.museum":true,"california.museum":true,"cambridge.museum":true,"can.museum":true,"canada.museum":true,"capebreton.museum":true,"carrier.museum":true,"cartoonart.museum":true,"casadelamoneda.museum":true,"castle.museum":true,"castres.museum":true,"celtic.museum":true,"center.museum":true,"chattanooga.museum":true,"cheltenham.museum":true,"chesapeakebay.museum":true,"chicago.museum":true,"children.museum":true,"childrens.museum":true,"childrensgarden.museum":true,"chiropractic.museum":true,"chocolate.museum":true,"christiansburg.museum":true,"cincinnati.museum":true,"cinema.museum":true,"circus.museum":true,"civilisation.museum":true,"civilization.museum":true,"civilwar.museum":true,"clinton.museum":true,"clock.museum":true,"coal.museum":true,"coastaldefence.museum":true,"cody.museum":true,"coldwar.museum":true,"collection.museum":true,"colonialwilliamsburg.museum":true,"coloradoplateau.museum":true,"columbia.museum":true,"columbus.museum":true,"communication.museum":true,"communications.museum":true,"community.museum":true,"computer.museum":true,"computerhistory.museum":true,"xn--comunicaes-v6a2o.museum":true,"contemporary.museum":true,"contemporaryart.museum":true,"convent.museum":true,"copenhagen.museum":true,"corporation.museum":true,"xn--correios-e-telecomunicaes-ghc29a.museum":true,"corvette.museum":true,"costume.museum":true,"countryestate.museum":true,"county.museum":true,"crafts.museum":true,"cranbrook.museum":true,"creation.museum":true,"cultural.museum":true,"culturalcenter.museum":true,"culture.museum":true,"cyber.museum":true,"cymru.museum":true,"dali.museum":true,"dallas.museum":true,"database.museum":true,"ddr.museum":true,"decorativearts.museum":true,"delaware.museum":true,"delmenhorst.museum":true,"denmark.museum":true,"depot.museum":true,"design.museum":true,"detroit.museum":true,"dinosaur.museum":true,"discovery.museum":true,"dolls.museum":true,"donostia.museum":true,"durham.museum":true,"eastafrica.museum":true,"eastcoast.museum":true,"education.museum":true,"educational.museum":true,"egyptian.museum":true,"eisenbahn.museum":true,"elburg.museum":true,"elvendrell.museum":true,"embroidery.museum":true,"encyclopedic.museum":true,"england.museum":true,"entomology.museum":true,"environment.museum":true,"environmentalconservation.museum":true,"epilepsy.museum":true,"essex.museum":true,"estate.museum":true,"ethnology.museum":true,"exeter.museum":true,"exhibition.museum":true,"family.museum":true,"farm.museum":true,"farmequipment.museum":true,"farmers.museum":true,"farmstead.museum":true,"field.museum":true,"figueres.museum":true,"filatelia.museum":true,"film.museum":true,"fineart.museum":true,"finearts.museum":true,"finland.museum":true,"flanders.museum":true,"florida.museum":true,"force.museum":true,"fortmissoula.museum":true,"fortworth.museum":true,"foundation.museum":true,"francaise.museum":true,"frankfurt.museum":true,"franziskaner.museum":true,"freemasonry.museum":true,"freiburg.museum":true,"fribourg.museum":true,"frog.museum":true,"fundacio.museum":true,"furniture.museum":true,"gallery.museum":true,"garden.museum":true,"gateway.museum":true,"geelvinck.museum":true,"gemological.museum":true,"geology.museum":true,"georgia.museum":true,"giessen.museum":true,"glas.museum":true,"glass.museum":true,"gorge.museum":true,"grandrapids.museum":true,"graz.museum":true,"guernsey.museum":true,"halloffame.museum":true,"hamburg.museum":true,"handson.museum":true,"harvestcelebration.museum":true,"hawaii.museum":true,"health.museum":true,"heimatunduhren.museum":true,"hellas.museum":true,"helsinki.museum":true,"hembygdsforbund.museum":true,"heritage.museum":true,"histoire.museum":true,"historical.museum":true,"historicalsociety.museum":true,"historichouses.museum":true,"historisch.museum":true,"historisches.museum":true,"history.museum":true,"historyofscience.museum":true,"horology.museum":true,"house.museum":true,"humanities.museum":true,"illustration.museum":true,"imageandsound.museum":true,"indian.museum":true,"indiana.museum":true,"indianapolis.museum":true,"indianmarket.museum":true,"intelligence.museum":true,"interactive.museum":true,"iraq.museum":true,"iron.museum":true,"isleofman.museum":true,"jamison.museum":true,"jefferson.museum":true,"jerusalem.museum":true,"jewelry.museum":true,"jewish.museum":true,"jewishart.museum":true,"jfk.museum":true,"journalism.museum":true,"judaica.museum":true,"judygarland.museum":true,"juedisches.museum":true,"juif.museum":true,"karate.museum":true,"karikatur.museum":true,"kids.museum":true,"koebenhavn.museum":true,"koeln.museum":true,"kunst.museum":true,"kunstsammlung.museum":true,"kunstunddesign.museum":true,"labor.museum":true,"labour.museum":true,"lajolla.museum":true,"lancashire.museum":true,"landes.museum":true,"lans.museum":true,"xn--lns-qla.museum":true,"larsson.museum":true,"lewismiller.museum":true,"lincoln.museum":true,"linz.museum":true,"living.museum":true,"livinghistory.museum":true,"localhistory.museum":true,"london.museum":true,"losangeles.museum":true,"louvre.museum":true,"loyalist.museum":true,"lucerne.museum":true,"luxembourg.museum":true,"luzern.museum":true,"mad.museum":true,"madrid.museum":true,"mallorca.museum":true,"manchester.museum":true,"mansion.museum":true,"mansions.museum":true,"manx.museum":true,"marburg.museum":true,"maritime.museum":true,"maritimo.museum":true,"maryland.museum":true,"marylhurst.museum":true,"media.museum":true,"medical.museum":true,"medizinhistorisches.museum":true,"meeres.museum":true,"memorial.museum":true,"mesaverde.museum":true,"michigan.museum":true,"midatlantic.museum":true,"military.museum":true,"mill.museum":true,"miners.museum":true,"mining.museum":true,"minnesota.museum":true,"missile.museum":true,"missoula.museum":true,"modern.museum":true,"moma.museum":true,"money.museum":true,"monmouth.museum":true,"monticello.museum":true,"montreal.museum":true,"moscow.museum":true,"motorcycle.museum":true,"muenchen.museum":true,"muenster.museum":true,"mulhouse.museum":true,"muncie.museum":true,"museet.museum":true,"museumcenter.museum":true,"museumvereniging.museum":true,"music.museum":true,"national.museum":true,"nationalfirearms.museum":true,"nationalheritage.museum":true,"nativeamerican.museum":true,"naturalhistory.museum":true,"naturalhistorymuseum.museum":true,"naturalsciences.museum":true,"nature.museum":true,"naturhistorisches.museum":true,"natuurwetenschappen.museum":true,"naumburg.museum":true,"naval.museum":true,"nebraska.museum":true,"neues.museum":true,"newhampshire.museum":true,"newjersey.museum":true,"newmexico.museum":true,"newport.museum":true,"newspaper.museum":true,"newyork.museum":true,"niepce.museum":true,"norfolk.museum":true,"north.museum":true,"nrw.museum":true,"nuernberg.museum":true,"nuremberg.museum":true,"nyc.museum":true,"nyny.museum":true,"oceanographic.museum":true,"oceanographique.museum":true,"omaha.museum":true,"online.museum":true,"ontario.museum":true,"openair.museum":true,"oregon.museum":true,"oregontrail.museum":true,"otago.museum":true,"oxford.museum":true,"pacific.museum":true,"paderborn.museum":true,"palace.museum":true,"paleo.museum":true,"palmsprings.museum":true,"panama.museum":true,"paris.museum":true,"pasadena.museum":true,"pharmacy.museum":true,"philadelphia.museum":true,"philadelphiaarea.museum":true,"philately.museum":true,"phoenix.museum":true,"photography.museum":true,"pilots.museum":true,"pittsburgh.museum":true,"planetarium.museum":true,"plantation.museum":true,"plants.museum":true,"plaza.museum":true,"portal.museum":true,"portland.museum":true,"portlligat.museum":true,"posts-and-telecommunications.museum":true,"preservation.museum":true,"presidio.museum":true,"press.museum":true,"project.museum":true,"public.museum":true,"pubol.museum":true,"quebec.museum":true,"railroad.museum":true,"railway.museum":true,"research.museum":true,"resistance.museum":true,"riodejaneiro.museum":true,"rochester.museum":true,"rockart.museum":true,"roma.museum":true,"russia.museum":true,"saintlouis.museum":true,"salem.museum":true,"salvadordali.museum":true,"salzburg.museum":true,"sandiego.museum":true,"sanfrancisco.museum":true,"santabarbara.museum":true,"santacruz.museum":true,"santafe.museum":true,"saskatchewan.museum":true,"satx.museum":true,"savannahga.museum":true,"schlesisches.museum":true,"schoenbrunn.museum":true,"schokoladen.museum":true,"school.museum":true,"schweiz.museum":true,"science.museum":true,"scienceandhistory.museum":true,"scienceandindustry.museum":true,"sciencecenter.museum":true,"sciencecenters.museum":true,"science-fiction.museum":true,"sciencehistory.museum":true,"sciences.museum":true,"sciencesnaturelles.museum":true,"scotland.museum":true,"seaport.museum":true,"settlement.museum":true,"settlers.museum":true,"shell.museum":true,"sherbrooke.museum":true,"sibenik.museum":true,"silk.museum":true,"ski.museum":true,"skole.museum":true,"society.museum":true,"sologne.museum":true,"soundandvision.museum":true,"southcarolina.museum":true,"southwest.museum":true,"space.museum":true,"spy.museum":true,"square.museum":true,"stadt.museum":true,"stalbans.museum":true,"starnberg.museum":true,"state.museum":true,"stateofdelaware.museum":true,"station.museum":true,"steam.museum":true,"steiermark.museum":true,"stjohn.museum":true,"stockholm.museum":true,"stpetersburg.museum":true,"stuttgart.museum":true,"suisse.museum":true,"surgeonshall.museum":true,"surrey.museum":true,"svizzera.museum":true,"sweden.museum":true,"sydney.museum":true,"tank.museum":true,"tcm.museum":true,"technology.museum":true,"telekommunikation.museum":true,"television.museum":true,"texas.museum":true,"textile.museum":true,"theater.museum":true,"time.museum":true,"timekeeping.museum":true,"topology.museum":true,"torino.museum":true,"touch.museum":true,"town.museum":true,"transport.museum":true,"tree.museum":true,"trolley.museum":true,"trust.museum":true,"trustee.museum":true,"uhren.museum":true,"ulm.museum":true,"undersea.museum":true,"university.museum":true,"usa.museum":true,"usantiques.museum":true,"usarts.museum":true,"uscountryestate.museum":true,"usculture.museum":true,"usdecorativearts.museum":true,"usgarden.museum":true,"ushistory.museum":true,"ushuaia.museum":true,"uslivinghistory.museum":true,"utah.museum":true,"uvic.museum":true,"valley.museum":true,"vantaa.museum":true,"versailles.museum":true,"viking.museum":true,"village.museum":true,"virginia.museum":true,"virtual.museum":true,"virtuel.museum":true,"vlaanderen.museum":true,"volkenkunde.museum":true,"wales.museum":true,"wallonie.museum":true,"war.museum":true,"washingtondc.museum":true,"watchandclock.museum":true,"watch-and-clock.museum":true,"western.museum":true,"westfalen.museum":true,"whaling.museum":true,"wildlife.museum":true,"williamsburg.museum":true,"windmill.museum":true,"workshop.museum":true,"york.museum":true,"yorkshire.museum":true,"yosemite.museum":true,"youth.museum":true,"zoological.museum":true,"zoology.museum":true,"xn--9dbhblg6di.museum":true,"xn--h1aegh.museum":true,"mv":true,"aero.mv":true,"biz.mv":true,"com.mv":true,"coop.mv":true,"edu.mv":true,"gov.mv":true,"info.mv":true,"int.mv":true,"mil.mv":true,"museum.mv":true,"name.mv":true,"net.mv":true,"org.mv":true,"pro.mv":true,"mw":true,"ac.mw":true,"biz.mw":true,"co.mw":true,"com.mw":true,"coop.mw":true,"edu.mw":true,"gov.mw":true,"int.mw":true,"museum.mw":true,"net.mw":true,"org.mw":true,"mx":true,"com.mx":true,"org.mx":true,"gob.mx":true,"edu.mx":true,"net.mx":true,"my":true,"com.my":true,"net.my":true,"org.my":true,"gov.my":true,"edu.my":true,"mil.my":true,"name.my":true,"*.mz":true,"na":true,"info.na":true,"pro.na":true,"name.na":true,"school.na":true,"or.na":true,"dr.na":true,"us.na":true,"mx.na":true,"ca.na":true,"in.na":true,"cc.na":true,"tv.na":true,"ws.na":true,"mobi.na":true,"co.na":true,"com.na":true,"org.na":true,"name":true,"nc":true,"asso.nc":true,"ne":true,"net":true,"nf":true,"com.nf":true,"net.nf":true,"per.nf":true,"rec.nf":true,"web.nf":true,"arts.nf":true,"firm.nf":true,"info.nf":true,"other.nf":true,"store.nf":true,"ac.ng":true,"com.ng":true,"edu.ng":true,"gov.ng":true,"net.ng":true,"org.ng":true,"*.ni":true,"nl":true,"bv.nl":true,"no":true,"fhs.no":true,"vgs.no":true,"fylkesbibl.no":true,"folkebibl.no":true,"museum.no":true,"idrett.no":true,"priv.no":true,"mil.no":true,"stat.no":true,"dep.no":true,"kommune.no":true,"herad.no":true,"aa.no":true,"ah.no":true,"bu.no":true,"fm.no":true,"hl.no":true,"hm.no":true,"jan-mayen.no":true,"mr.no":true,"nl.no":true,"nt.no":true,"of.no":true,"ol.no":true,"oslo.no":true,"rl.no":true,"sf.no":true,"st.no":true,"svalbard.no":true,"tm.no":true,"tr.no":true,"va.no":true,"vf.no":true,"gs.aa.no":true,"gs.ah.no":true,"gs.bu.no":true,"gs.fm.no":true,"gs.hl.no":true,"gs.hm.no":true,"gs.jan-mayen.no":true,"gs.mr.no":true,"gs.nl.no":true,"gs.nt.no":true,"gs.of.no":true,"gs.ol.no":true,"gs.oslo.no":true,"gs.rl.no":true,"gs.sf.no":true,"gs.st.no":true,"gs.svalbard.no":true,"gs.tm.no":true,"gs.tr.no":true,"gs.va.no":true,"gs.vf.no":true,"akrehamn.no":true,"xn--krehamn-dxa.no":true,"algard.no":true,"xn--lgrd-poac.no":true,"arna.no":true,"brumunddal.no":true,"bryne.no":true,"bronnoysund.no":true,"xn--brnnysund-m8ac.no":true,"drobak.no":true,"xn--drbak-wua.no":true,"egersund.no":true,"fetsund.no":true,"floro.no":true,"xn--flor-jra.no":true,"fredrikstad.no":true,"hokksund.no":true,"honefoss.no":true,"xn--hnefoss-q1a.no":true,"jessheim.no":true,"jorpeland.no":true,"xn--jrpeland-54a.no":true,"kirkenes.no":true,"kopervik.no":true,"krokstadelva.no":true,"langevag.no":true,"xn--langevg-jxa.no":true,"leirvik.no":true,"mjondalen.no":true,"xn--mjndalen-64a.no":true,"mo-i-rana.no":true,"mosjoen.no":true,"xn--mosjen-eya.no":true,"nesoddtangen.no":true,"orkanger.no":true,"osoyro.no":true,"xn--osyro-wua.no":true,"raholt.no":true,"xn--rholt-mra.no":true,"sandnessjoen.no":true,"xn--sandnessjen-ogb.no":true,"skedsmokorset.no":true,"slattum.no":true,"spjelkavik.no":true,"stathelle.no":true,"stavern.no":true,"stjordalshalsen.no":true,"xn--stjrdalshalsen-sqb.no":true,"tananger.no":true,"tranby.no":true,"vossevangen.no":true,"afjord.no":true,"xn--fjord-lra.no":true,"agdenes.no":true,"al.no":true,"xn--l-1fa.no":true,"alesund.no":true,"xn--lesund-hua.no":true,"alstahaug.no":true,"alta.no":true,"xn--lt-liac.no":true,"alaheadju.no":true,"xn--laheadju-7ya.no":true,"alvdal.no":true,"amli.no":true,"xn--mli-tla.no":true,"amot.no":true,"xn--mot-tla.no":true,"andebu.no":true,"andoy.no":true,"xn--andy-ira.no":true,"andasuolo.no":true,"ardal.no":true,"xn--rdal-poa.no":true,"aremark.no":true,"arendal.no":true,"xn--s-1fa.no":true,"aseral.no":true,"xn--seral-lra.no":true,"asker.no":true,"askim.no":true,"askvoll.no":true,"askoy.no":true,"xn--asky-ira.no":true,"asnes.no":true,"xn--snes-poa.no":true,"audnedaln.no":true,"aukra.no":true,"aure.no":true,"aurland.no":true,"aurskog-holand.no":true,"xn--aurskog-hland-jnb.no":true,"austevoll.no":true,"austrheim.no":true,"averoy.no":true,"xn--avery-yua.no":true,"balestrand.no":true,"ballangen.no":true,"balat.no":true,"xn--blt-elab.no":true,"balsfjord.no":true,"bahccavuotna.no":true,"xn--bhccavuotna-k7a.no":true,"bamble.no":true,"bardu.no":true,"beardu.no":true,"beiarn.no":true,"bajddar.no":true,"xn--bjddar-pta.no":true,"baidar.no":true,"xn--bidr-5nac.no":true,"berg.no":true,"bergen.no":true,"berlevag.no":true,"xn--berlevg-jxa.no":true,"bearalvahki.no":true,"xn--bearalvhki-y4a.no":true,"bindal.no":true,"birkenes.no":true,"bjarkoy.no":true,"xn--bjarky-fya.no":true,"bjerkreim.no":true,"bjugn.no":true,"bodo.no":true,"xn--bod-2na.no":true,"badaddja.no":true,"xn--bdddj-mrabd.no":true,"budejju.no":true,"bokn.no":true,"bremanger.no":true,"bronnoy.no":true,"xn--brnny-wuac.no":true,"bygland.no":true,"bykle.no":true,"barum.no":true,"xn--brum-voa.no":true,"bo.telemark.no":true,"xn--b-5ga.telemark.no":true,"bo.nordland.no":true,"xn--b-5ga.nordland.no":true,"bievat.no":true,"xn--bievt-0qa.no":true,"bomlo.no":true,"xn--bmlo-gra.no":true,"batsfjord.no":true,"xn--btsfjord-9za.no":true,"bahcavuotna.no":true,"xn--bhcavuotna-s4a.no":true,"dovre.no":true,"drammen.no":true,"drangedal.no":true,"dyroy.no":true,"xn--dyry-ira.no":true,"donna.no":true,"xn--dnna-gra.no":true,"eid.no":true,"eidfjord.no":true,"eidsberg.no":true,"eidskog.no":true,"eidsvoll.no":true,"eigersund.no":true,"elverum.no":true,"enebakk.no":true,"engerdal.no":true,"etne.no":true,"etnedal.no":true,"evenes.no":true,"evenassi.no":true,"xn--eveni-0qa01ga.no":true,"evje-og-hornnes.no":true,"farsund.no":true,"fauske.no":true,"fuossko.no":true,"fuoisku.no":true,"fedje.no":true,"fet.no":true,"finnoy.no":true,"xn--finny-yua.no":true,"fitjar.no":true,"fjaler.no":true,"fjell.no":true,"flakstad.no":true,"flatanger.no":true,"flekkefjord.no":true,"flesberg.no":true,"flora.no":true,"fla.no":true,"xn--fl-zia.no":true,"folldal.no":true,"forsand.no":true,"fosnes.no":true,"frei.no":true,"frogn.no":true,"froland.no":true,"frosta.no":true,"frana.no":true,"xn--frna-woa.no":true,"froya.no":true,"xn--frya-hra.no":true,"fusa.no":true,"fyresdal.no":true,"forde.no":true,"xn--frde-gra.no":true,"gamvik.no":true,"gangaviika.no":true,"xn--ggaviika-8ya47h.no":true,"gaular.no":true,"gausdal.no":true,"gildeskal.no":true,"xn--gildeskl-g0a.no":true,"giske.no":true,"gjemnes.no":true,"gjerdrum.no":true,"gjerstad.no":true,"gjesdal.no":true,"gjovik.no":true,"xn--gjvik-wua.no":true,"gloppen.no":true,"gol.no":true,"gran.no":true,"grane.no":true,"granvin.no":true,"gratangen.no":true,"grimstad.no":true,"grong.no":true,"kraanghke.no":true,"xn--kranghke-b0a.no":true,"grue.no":true,"gulen.no":true,"hadsel.no":true,"halden.no":true,"halsa.no":true,"hamar.no":true,"hamaroy.no":true,"habmer.no":true,"xn--hbmer-xqa.no":true,"hapmir.no":true,"xn--hpmir-xqa.no":true,"hammerfest.no":true,"hammarfeasta.no":true,"xn--hmmrfeasta-s4ac.no":true,"haram.no":true,"hareid.no":true,"harstad.no":true,"hasvik.no":true,"aknoluokta.no":true,"xn--koluokta-7ya57h.no":true,"hattfjelldal.no":true,"aarborte.no":true,"haugesund.no":true,"hemne.no":true,"hemnes.no":true,"hemsedal.no":true,"heroy.more-og-romsdal.no":true,"xn--hery-ira.xn--mre-og-romsdal-qqb.no":true,"heroy.nordland.no":true,"xn--hery-ira.nordland.no":true,"hitra.no":true,"hjartdal.no":true,"hjelmeland.no":true,"hobol.no":true,"xn--hobl-ira.no":true,"hof.no":true,"hol.no":true,"hole.no":true,"holmestrand.no":true,"holtalen.no":true,"xn--holtlen-hxa.no":true,"hornindal.no":true,"horten.no":true,"hurdal.no":true,"hurum.no":true,"hvaler.no":true,"hyllestad.no":true,"hagebostad.no":true,"xn--hgebostad-g3a.no":true,"hoyanger.no":true,"xn--hyanger-q1a.no":true,"hoylandet.no":true,"xn--hylandet-54a.no":true,"ha.no":true,"xn--h-2fa.no":true,"ibestad.no":true,"inderoy.no":true,"xn--indery-fya.no":true,"iveland.no":true,"jevnaker.no":true,"jondal.no":true,"jolster.no":true,"xn--jlster-bya.no":true,"karasjok.no":true,"karasjohka.no":true,"xn--krjohka-hwab49j.no":true,"karlsoy.no":true,"galsa.no":true,"xn--gls-elac.no":true,"karmoy.no":true,"xn--karmy-yua.no":true,"kautokeino.no":true,"guovdageaidnu.no":true,"klepp.no":true,"klabu.no":true,"xn--klbu-woa.no":true,"kongsberg.no":true,"kongsvinger.no":true,"kragero.no":true,"xn--krager-gya.no":true,"kristiansand.no":true,"kristiansund.no":true,"krodsherad.no":true,"xn--krdsherad-m8a.no":true,"kvalsund.no":true,"rahkkeravju.no":true,"xn--rhkkervju-01af.no":true,"kvam.no":true,"kvinesdal.no":true,"kvinnherad.no":true,"kviteseid.no":true,"kvitsoy.no":true,"xn--kvitsy-fya.no":true,"kvafjord.no":true,"xn--kvfjord-nxa.no":true,"giehtavuoatna.no":true,"kvanangen.no":true,"xn--kvnangen-k0a.no":true,"navuotna.no":true,"xn--nvuotna-hwa.no":true,"kafjord.no":true,"xn--kfjord-iua.no":true,"gaivuotna.no":true,"xn--givuotna-8ya.no":true,"larvik.no":true,"lavangen.no":true,"lavagis.no":true,"loabat.no":true,"xn--loabt-0qa.no":true,"lebesby.no":true,"davvesiida.no":true,"leikanger.no":true,"leirfjord.no":true,"leka.no":true,"leksvik.no":true,"lenvik.no":true,"leangaviika.no":true,"xn--leagaviika-52b.no":true,"lesja.no":true,"levanger.no":true,"lier.no":true,"lierne.no":true,"lillehammer.no":true,"lillesand.no":true,"lindesnes.no":true,"lindas.no":true,"xn--linds-pra.no":true,"lom.no":true,"loppa.no":true,"lahppi.no":true,"xn--lhppi-xqa.no":true,"lund.no":true,"lunner.no":true,"luroy.no":true,"xn--lury-ira.no":true,"luster.no":true,"lyngdal.no":true,"lyngen.no":true,"ivgu.no":true,"lardal.no":true,"lerdal.no":true,"xn--lrdal-sra.no":true,"lodingen.no":true,"xn--ldingen-q1a.no":true,"lorenskog.no":true,"xn--lrenskog-54a.no":true,"loten.no":true,"xn--lten-gra.no":true,"malvik.no":true,"masoy.no":true,"xn--msy-ula0h.no":true,"muosat.no":true,"xn--muost-0qa.no":true,"mandal.no":true,"marker.no":true,"marnardal.no":true,"masfjorden.no":true,"meland.no":true,"meldal.no":true,"melhus.no":true,"meloy.no":true,"xn--mely-ira.no":true,"meraker.no":true,"xn--merker-kua.no":true,"moareke.no":true,"xn--moreke-jua.no":true,"midsund.no":true,"midtre-gauldal.no":true,"modalen.no":true,"modum.no":true,"molde.no":true,"moskenes.no":true,"moss.no":true,"mosvik.no":true,"malselv.no":true,"xn--mlselv-iua.no":true,"malatvuopmi.no":true,"xn--mlatvuopmi-s4a.no":true,"namdalseid.no":true,"aejrie.no":true,"namsos.no":true,"namsskogan.no":true,"naamesjevuemie.no":true,"xn--nmesjevuemie-tcba.no":true,"laakesvuemie.no":true,"nannestad.no":true,"narvik.no":true,"narviika.no":true,"naustdal.no":true,"nedre-eiker.no":true,"nes.akershus.no":true,"nes.buskerud.no":true,"nesna.no":true,"nesodden.no":true,"nesseby.no":true,"unjarga.no":true,"xn--unjrga-rta.no":true,"nesset.no":true,"nissedal.no":true,"nittedal.no":true,"nord-aurdal.no":true,"nord-fron.no":true,"nord-odal.no":true,"norddal.no":true,"nordkapp.no":true,"davvenjarga.no":true,"xn--davvenjrga-y4a.no":true,"nordre-land.no":true,"nordreisa.no":true,"raisa.no":true,"xn--risa-5na.no":true,"nore-og-uvdal.no":true,"notodden.no":true,"naroy.no":true,"xn--nry-yla5g.no":true,"notteroy.no":true,"xn--nttery-byae.no":true,"odda.no":true,"oksnes.no":true,"xn--ksnes-uua.no":true,"oppdal.no":true,"oppegard.no":true,"xn--oppegrd-ixa.no":true,"orkdal.no":true,"orland.no":true,"xn--rland-uua.no":true,"orskog.no":true,"xn--rskog-uua.no":true,"orsta.no":true,"xn--rsta-fra.no":true,"os.hedmark.no":true,"os.hordaland.no":true,"osen.no":true,"osteroy.no":true,"xn--ostery-fya.no":true,"ostre-toten.no":true,"xn--stre-toten-zcb.no":true,"overhalla.no":true,"ovre-eiker.no":true,"xn--vre-eiker-k8a.no":true,"oyer.no":true,"xn--yer-zna.no":true,"oygarden.no":true,"xn--ygarden-p1a.no":true,"oystre-slidre.no":true,"xn--ystre-slidre-ujb.no":true,"porsanger.no":true,"porsangu.no":true,"xn--porsgu-sta26f.no":true,"porsgrunn.no":true,"radoy.no":true,"xn--rady-ira.no":true,"rakkestad.no":true,"rana.no":true,"ruovat.no":true,"randaberg.no":true,"rauma.no":true,"rendalen.no":true,"rennebu.no":true,"rennesoy.no":true,"xn--rennesy-v1a.no":true,"rindal.no":true,"ringebu.no":true,"ringerike.no":true,"ringsaker.no":true,"rissa.no":true,"risor.no":true,"xn--risr-ira.no":true,"roan.no":true,"rollag.no":true,"rygge.no":true,"ralingen.no":true,"xn--rlingen-mxa.no":true,"rodoy.no":true,"xn--rdy-0nab.no":true,"romskog.no":true,"xn--rmskog-bya.no":true,"roros.no":true,"xn--rros-gra.no":true,"rost.no":true,"xn--rst-0na.no":true,"royken.no":true,"xn--ryken-vua.no":true,"royrvik.no":true,"xn--ryrvik-bya.no":true,"rade.no":true,"xn--rde-ula.no":true,"salangen.no":true,"siellak.no":true,"saltdal.no":true,"salat.no":true,"xn--slt-elab.no":true,"xn--slat-5na.no":true,"samnanger.no":true,"sande.more-og-romsdal.no":true,"sande.xn--mre-og-romsdal-qqb.no":true,"sande.vestfold.no":true,"sandefjord.no":true,"sandnes.no":true,"sandoy.no":true,"xn--sandy-yua.no":true,"sarpsborg.no":true,"sauda.no":true,"sauherad.no":true,"sel.no":true,"selbu.no":true,"selje.no":true,"seljord.no":true,"sigdal.no":true,"siljan.no":true,"sirdal.no":true,"skaun.no":true,"skedsmo.no":true,"ski.no":true,"skien.no":true,"skiptvet.no":true,"skjervoy.no":true,"xn--skjervy-v1a.no":true,"skierva.no":true,"xn--skierv-uta.no":true,"skjak.no":true,"xn--skjk-soa.no":true,"skodje.no":true,"skanland.no":true,"xn--sknland-fxa.no":true,"skanit.no":true,"xn--sknit-yqa.no":true,"smola.no":true,"xn--smla-hra.no":true,"snillfjord.no":true,"snasa.no":true,"xn--snsa-roa.no":true,"snoasa.no":true,"snaase.no":true,"xn--snase-nra.no":true,"sogndal.no":true,"sokndal.no":true,"sola.no":true,"solund.no":true,"songdalen.no":true,"sortland.no":true,"spydeberg.no":true,"stange.no":true,"stavanger.no":true,"steigen.no":true,"steinkjer.no":true,"stjordal.no":true,"xn--stjrdal-s1a.no":true,"stokke.no":true,"stor-elvdal.no":true,"stord.no":true,"stordal.no":true,"storfjord.no":true,"omasvuotna.no":true,"strand.no":true,"stranda.no":true,"stryn.no":true,"sula.no":true,"suldal.no":true,"sund.no":true,"sunndal.no":true,"surnadal.no":true,"sveio.no":true,"svelvik.no":true,"sykkylven.no":true,"sogne.no":true,"xn--sgne-gra.no":true,"somna.no":true,"xn--smna-gra.no":true,"sondre-land.no":true,"xn--sndre-land-0cb.no":true,"sor-aurdal.no":true,"xn--sr-aurdal-l8a.no":true,"sor-fron.no":true,"xn--sr-fron-q1a.no":true,"sor-odal.no":true,"xn--sr-odal-q1a.no":true,"sor-varanger.no":true,"xn--sr-varanger-ggb.no":true,"matta-varjjat.no":true,"xn--mtta-vrjjat-k7af.no":true,"sorfold.no":true,"xn--srfold-bya.no":true,"sorreisa.no":true,"xn--srreisa-q1a.no":true,"sorum.no":true,"xn--srum-gra.no":true,"tana.no":true,"deatnu.no":true,"time.no":true,"tingvoll.no":true,"tinn.no":true,"tjeldsund.no":true,"dielddanuorri.no":true,"tjome.no":true,"xn--tjme-hra.no":true,"tokke.no":true,"tolga.no":true,"torsken.no":true,"tranoy.no":true,"xn--trany-yua.no":true,"tromso.no":true,"xn--troms-zua.no":true,"tromsa.no":true,"romsa.no":true,"trondheim.no":true,"troandin.no":true,"trysil.no":true,"trana.no":true,"xn--trna-woa.no":true,"trogstad.no":true,"xn--trgstad-r1a.no":true,"tvedestrand.no":true,"tydal.no":true,"tynset.no":true,"tysfjord.no":true,"divtasvuodna.no":true,"divttasvuotna.no":true,"tysnes.no":true,"tysvar.no":true,"xn--tysvr-vra.no":true,"tonsberg.no":true,"xn--tnsberg-q1a.no":true,"ullensaker.no":true,"ullensvang.no":true,"ulvik.no":true,"utsira.no":true,"vadso.no":true,"xn--vads-jra.no":true,"cahcesuolo.no":true,"xn--hcesuolo-7ya35b.no":true,"vaksdal.no":true,"valle.no":true,"vang.no":true,"vanylven.no":true,"vardo.no":true,"xn--vard-jra.no":true,"varggat.no":true,"xn--vrggt-xqad.no":true,"vefsn.no":true,"vaapste.no":true,"vega.no":true,"vegarshei.no":true,"xn--vegrshei-c0a.no":true,"vennesla.no":true,"verdal.no":true,"verran.no":true,"vestby.no":true,"vestnes.no":true,"vestre-slidre.no":true,"vestre-toten.no":true,"vestvagoy.no":true,"xn--vestvgy-ixa6o.no":true,"vevelstad.no":true,"vik.no":true,"vikna.no":true,"vindafjord.no":true,"volda.no":true,"voss.no":true,"varoy.no":true,"xn--vry-yla5g.no":true,"vagan.no":true,"xn--vgan-qoa.no":true,"voagat.no":true,"vagsoy.no":true,"xn--vgsy-qoa0j.no":true,"vaga.no":true,"xn--vg-yiab.no":true,"valer.ostfold.no":true,"xn--vler-qoa.xn--stfold-9xa.no":true,"valer.hedmark.no":true,"xn--vler-qoa.hedmark.no":true,"*.np":true,"nr":true,"biz.nr":true,"info.nr":true,"gov.nr":true,"edu.nr":true,"org.nr":true,"net.nr":true,"com.nr":true,"nu":true,"*.nz":true,"*.om":true,"mediaphone.om":false,"nawrastelecom.om":false,"nawras.om":false,"omanmobile.om":false,"omanpost.om":false,"omantel.om":false,"rakpetroleum.om":false,"siemens.om":false,"songfest.om":false,"statecouncil.om":false,"org":true,"pa":true,"ac.pa":true,"gob.pa":true,"com.pa":true,"org.pa":true,"sld.pa":true,"edu.pa":true,"net.pa":true,"ing.pa":true,"abo.pa":true,"med.pa":true,"nom.pa":true,"pe":true,"edu.pe":true,"gob.pe":true,"nom.pe":true,"mil.pe":true,"org.pe":true,"com.pe":true,"net.pe":true,"pf":true,"com.pf":true,"org.pf":true,"edu.pf":true,"*.pg":true,"ph":true,"com.ph":true,"net.ph":true,"org.ph":true,"gov.ph":true,"edu.ph":true,"ngo.ph":true,"mil.ph":true,"i.ph":true,"pk":true,"com.pk":true,"net.pk":true,"edu.pk":true,"org.pk":true,"fam.pk":true,"biz.pk":true,"web.pk":true,"gov.pk":true,"gob.pk":true,"gok.pk":true,"gon.pk":true,"gop.pk":true,"gos.pk":true,"info.pk":true,"pl":true,"aid.pl":true,"agro.pl":true,"atm.pl":true,"auto.pl":true,"biz.pl":true,"com.pl":true,"edu.pl":true,"gmina.pl":true,"gsm.pl":true,"info.pl":true,"mail.pl":true,"miasta.pl":true,"media.pl":true,"mil.pl":true,"net.pl":true,"nieruchomosci.pl":true,"nom.pl":true,"org.pl":true,"pc.pl":true,"powiat.pl":true,"priv.pl":true,"realestate.pl":true,"rel.pl":true,"sex.pl":true,"shop.pl":true,"sklep.pl":true,"sos.pl":true,"szkola.pl":true,"targi.pl":true,"tm.pl":true,"tourism.pl":true,"travel.pl":true,"turystyka.pl":true,"6bone.pl":true,"art.pl":true,"mbone.pl":true,"gov.pl":true,"uw.gov.pl":true,"um.gov.pl":true,"ug.gov.pl":true,"upow.gov.pl":true,"starostwo.gov.pl":true,"so.gov.pl":true,"sr.gov.pl":true,"po.gov.pl":true,"pa.gov.pl":true,"ngo.pl":true,"irc.pl":true,"usenet.pl":true,"augustow.pl":true,"babia-gora.pl":true,"bedzin.pl":true,"beskidy.pl":true,"bialowieza.pl":true,"bialystok.pl":true,"bielawa.pl":true,"bieszczady.pl":true,"boleslawiec.pl":true,"bydgoszcz.pl":true,"bytom.pl":true,"cieszyn.pl":true,"czeladz.pl":true,"czest.pl":true,"dlugoleka.pl":true,"elblag.pl":true,"elk.pl":true,"glogow.pl":true,"gniezno.pl":true,"gorlice.pl":true,"grajewo.pl":true,"ilawa.pl":true,"jaworzno.pl":true,"jelenia-gora.pl":true,"jgora.pl":true,"kalisz.pl":true,"kazimierz-dolny.pl":true,"karpacz.pl":true,"kartuzy.pl":true,"kaszuby.pl":true,"katowice.pl":true,"kepno.pl":true,"ketrzyn.pl":true,"klodzko.pl":true,"kobierzyce.pl":true,"kolobrzeg.pl":true,"konin.pl":true,"konskowola.pl":true,"kutno.pl":true,"lapy.pl":true,"lebork.pl":true,"legnica.pl":true,"lezajsk.pl":true,"limanowa.pl":true,"lomza.pl":true,"lowicz.pl":true,"lubin.pl":true,"lukow.pl":true,"malbork.pl":true,"malopolska.pl":true,"mazowsze.pl":true,"mazury.pl":true,"mielec.pl":true,"mielno.pl":true,"mragowo.pl":true,"naklo.pl":true,"nowaruda.pl":true,"nysa.pl":true,"olawa.pl":true,"olecko.pl":true,"olkusz.pl":true,"olsztyn.pl":true,"opoczno.pl":true,"opole.pl":true,"ostroda.pl":true,"ostroleka.pl":true,"ostrowiec.pl":true,"ostrowwlkp.pl":true,"pila.pl":true,"pisz.pl":true,"podhale.pl":true,"podlasie.pl":true,"polkowice.pl":true,"pomorze.pl":true,"pomorskie.pl":true,"prochowice.pl":true,"pruszkow.pl":true,"przeworsk.pl":true,"pulawy.pl":true,"radom.pl":true,"rawa-maz.pl":true,"rybnik.pl":true,"rzeszow.pl":true,"sanok.pl":true,"sejny.pl":true,"siedlce.pl":true,"slask.pl":true,"slupsk.pl":true,"sosnowiec.pl":true,"stalowa-wola.pl":true,"skoczow.pl":true,"starachowice.pl":true,"stargard.pl":true,"suwalki.pl":true,"swidnica.pl":true,"swiebodzin.pl":true,"swinoujscie.pl":true,"szczecin.pl":true,"szczytno.pl":true,"tarnobrzeg.pl":true,"tgory.pl":true,"turek.pl":true,"tychy.pl":true,"ustka.pl":true,"walbrzych.pl":true,"warmia.pl":true,"warszawa.pl":true,"waw.pl":true,"wegrow.pl":true,"wielun.pl":true,"wlocl.pl":true,"wloclawek.pl":true,"wodzislaw.pl":true,"wolomin.pl":true,"wroclaw.pl":true,"zachpomor.pl":true,"zagan.pl":true,"zarow.pl":true,"zgora.pl":true,"zgorzelec.pl":true,"gda.pl":true,"gdansk.pl":true,"gdynia.pl":true,"med.pl":true,"sopot.pl":true,"gliwice.pl":true,"krakow.pl":true,"poznan.pl":true,"wroc.pl":true,"zakopane.pl":true,"pm":true,"pn":true,"gov.pn":true,"co.pn":true,"org.pn":true,"edu.pn":true,"net.pn":true,"pr":true,"com.pr":true,"net.pr":true,"org.pr":true,"gov.pr":true,"edu.pr":true,"isla.pr":true,"pro.pr":true,"biz.pr":true,"info.pr":true,"name.pr":true,"est.pr":true,"prof.pr":true,"ac.pr":true,"pro":true,"aca.pro":true,"bar.pro":true,"cpa.pro":true,"jur.pro":true,"law.pro":true,"med.pro":true,"eng.pro":true,"ps":true,"edu.ps":true,"gov.ps":true,"sec.ps":true,"plo.ps":true,"com.ps":true,"org.ps":true,"net.ps":true,"pt":true,"net.pt":true,"gov.pt":true,"org.pt":true,"edu.pt":true,"int.pt":true,"publ.pt":true,"com.pt":true,"nome.pt":true,"pw":true,"co.pw":true,"ne.pw":true,"or.pw":true,"ed.pw":true,"go.pw":true,"belau.pw":true,"*.py":true,"qa":true,"com.qa":true,"edu.qa":true,"gov.qa":true,"mil.qa":true,"name.qa":true,"net.qa":true,"org.qa":true,"sch.qa":true,"re":true,"com.re":true,"asso.re":true,"nom.re":true,"ro":true,"com.ro":true,"org.ro":true,"tm.ro":true,"nt.ro":true,"nom.ro":true,"info.ro":true,"rec.ro":true,"arts.ro":true,"firm.ro":true,"store.ro":true,"www.ro":true,"rs":true,"co.rs":true,"org.rs":true,"edu.rs":true,"ac.rs":true,"gov.rs":true,"in.rs":true,"ru":true,"ac.ru":true,"com.ru":true,"edu.ru":true,"int.ru":true,"net.ru":true,"org.ru":true,"pp.ru":true,"adygeya.ru":true,"altai.ru":true,"amur.ru":true,"arkhangelsk.ru":true,"astrakhan.ru":true,"bashkiria.ru":true,"belgorod.ru":true,"bir.ru":true,"bryansk.ru":true,"buryatia.ru":true,"cbg.ru":true,"chel.ru":true,"chelyabinsk.ru":true,"chita.ru":true,"chukotka.ru":true,"chuvashia.ru":true,"dagestan.ru":true,"dudinka.ru":true,"e-burg.ru":true,"grozny.ru":true,"irkutsk.ru":true,"ivanovo.ru":true,"izhevsk.ru":true,"jar.ru":true,"joshkar-ola.ru":true,"kalmykia.ru":true,"kaluga.ru":true,"kamchatka.ru":true,"karelia.ru":true,"kazan.ru":true,"kchr.ru":true,"kemerovo.ru":true,"khabarovsk.ru":true,"khakassia.ru":true,"khv.ru":true,"kirov.ru":true,"koenig.ru":true,"komi.ru":true,"kostroma.ru":true,"krasnoyarsk.ru":true,"kuban.ru":true,"kurgan.ru":true,"kursk.ru":true,"lipetsk.ru":true,"magadan.ru":true,"mari.ru":true,"mari-el.ru":true,"marine.ru":true,"mordovia.ru":true,"mosreg.ru":true,"msk.ru":true,"murmansk.ru":true,"nalchik.ru":true,"nnov.ru":true,"nov.ru":true,"novosibirsk.ru":true,"nsk.ru":true,"omsk.ru":true,"orenburg.ru":true,"oryol.ru":true,"palana.ru":true,"penza.ru":true,"perm.ru":true,"pskov.ru":true,"ptz.ru":true,"rnd.ru":true,"ryazan.ru":true,"sakhalin.ru":true,"samara.ru":true,"saratov.ru":true,"simbirsk.ru":true,"smolensk.ru":true,"spb.ru":true,"stavropol.ru":true,"stv.ru":true,"surgut.ru":true,"tambov.ru":true,"tatarstan.ru":true,"tom.ru":true,"tomsk.ru":true,"tsaritsyn.ru":true,"tsk.ru":true,"tula.ru":true,"tuva.ru":true,"tver.ru":true,"tyumen.ru":true,"udm.ru":true,"udmurtia.ru":true,"ulan-ude.ru":true,"vladikavkaz.ru":true,"vladimir.ru":true,"vladivostok.ru":true,"volgograd.ru":true,"vologda.ru":true,"voronezh.ru":true,"vrn.ru":true,"vyatka.ru":true,"yakutia.ru":true,"yamal.ru":true,"yaroslavl.ru":true,"yekaterinburg.ru":true,"yuzhno-sakhalinsk.ru":true,"amursk.ru":true,"baikal.ru":true,"cmw.ru":true,"fareast.ru":true,"jamal.ru":true,"kms.ru":true,"k-uralsk.ru":true,"kustanai.ru":true,"kuzbass.ru":true,"magnitka.ru":true,"mytis.ru":true,"nakhodka.ru":true,"nkz.ru":true,"norilsk.ru":true,"oskol.ru":true,"pyatigorsk.ru":true,"rubtsovsk.ru":true,"snz.ru":true,"syzran.ru":true,"vdonsk.ru":true,"zgrad.ru":true,"gov.ru":true,"mil.ru":true,"test.ru":true,"rw":true,"gov.rw":true,"net.rw":true,"edu.rw":true,"ac.rw":true,"com.rw":true,"co.rw":true,"int.rw":true,"mil.rw":true,"gouv.rw":true,"sa":true,"com.sa":true,"net.sa":true,"org.sa":true,"gov.sa":true,"med.sa":true,"pub.sa":true,"edu.sa":true,"sch.sa":true,"sb":true,"com.sb":true,"edu.sb":true,"gov.sb":true,"net.sb":true,"org.sb":true,"sc":true,"com.sc":true,"gov.sc":true,"net.sc":true,"org.sc":true,"edu.sc":true,"sd":true,"com.sd":true,"net.sd":true,"org.sd":true,"edu.sd":true,"med.sd":true,"gov.sd":true,"info.sd":true,"se":true,"a.se":true,"ac.se":true,"b.se":true,"bd.se":true,"brand.se":true,"c.se":true,"d.se":true,"e.se":true,"f.se":true,"fh.se":true,"fhsk.se":true,"fhv.se":true,"g.se":true,"h.se":true,"i.se":true,"k.se":true,"komforb.se":true,"kommunalforbund.se":true,"komvux.se":true,"l.se":true,"lanbib.se":true,"m.se":true,"n.se":true,"naturbruksgymn.se":true,"o.se":true,"org.se":true,"p.se":true,"parti.se":true,"pp.se":true,"press.se":true,"r.se":true,"s.se":true,"sshn.se":true,"t.se":true,"tm.se":true,"u.se":true,"w.se":true,"x.se":true,"y.se":true,"z.se":true,"sg":true,"com.sg":true,"net.sg":true,"org.sg":true,"gov.sg":true,"edu.sg":true,"per.sg":true,"sh":true,"si":true,"sk":true,"sl":true,"com.sl":true,"net.sl":true,"edu.sl":true,"gov.sl":true,"org.sl":true,"sm":true,"sn":true,"art.sn":true,"com.sn":true,"edu.sn":true,"gouv.sn":true,"org.sn":true,"perso.sn":true,"univ.sn":true,"so":true,"com.so":true,"net.so":true,"org.so":true,"sr":true,"st":true,"co.st":true,"com.st":true,"consulado.st":true,"edu.st":true,"embaixada.st":true,"gov.st":true,"mil.st":true,"net.st":true,"org.st":true,"principe.st":true,"saotome.st":true,"store.st":true,"su":true,"*.sv":true,"sy":true,"edu.sy":true,"gov.sy":true,"net.sy":true,"mil.sy":true,"com.sy":true,"org.sy":true,"sz":true,"co.sz":true,"ac.sz":true,"org.sz":true,"tc":true,"td":true,"tel":true,"tf":true,"tg":true,"th":true,"ac.th":true,"co.th":true,"go.th":true,"in.th":true,"mi.th":true,"net.th":true,"or.th":true,"tj":true,"ac.tj":true,"biz.tj":true,"co.tj":true,"com.tj":true,"edu.tj":true,"go.tj":true,"gov.tj":true,"int.tj":true,"mil.tj":true,"name.tj":true,"net.tj":true,"nic.tj":true,"org.tj":true,"test.tj":true,"web.tj":true,"tk":true,"tl":true,"gov.tl":true,"tm":true,"tn":true,"com.tn":true,"ens.tn":true,"fin.tn":true,"gov.tn":true,"ind.tn":true,"intl.tn":true,"nat.tn":true,"net.tn":true,"org.tn":true,"info.tn":true,"perso.tn":true,"tourism.tn":true,"edunet.tn":true,"rnrt.tn":true,"rns.tn":true,"rnu.tn":true,"mincom.tn":true,"agrinet.tn":true,"defense.tn":true,"turen.tn":true,"to":true,"com.to":true,"gov.to":true,"net.to":true,"org.to":true,"edu.to":true,"mil.to":true,"*.tr":true,"nic.tr":false,"gov.nc.tr":true,"travel":true,"tt":true,"co.tt":true,"com.tt":true,"org.tt":true,"net.tt":true,"biz.tt":true,"info.tt":true,"pro.tt":true,"int.tt":true,"coop.tt":true,"jobs.tt":true,"mobi.tt":true,"travel.tt":true,"museum.tt":true,"aero.tt":true,"name.tt":true,"gov.tt":true,"edu.tt":true,"tv":true,"tw":true,"edu.tw":true,"gov.tw":true,"mil.tw":true,"com.tw":true,"net.tw":true,"org.tw":true,"idv.tw":true,"game.tw":true,"ebiz.tw":true,"club.tw":true,"xn--zf0ao64a.tw":true,"xn--uc0atv.tw":true,"xn--czrw28b.tw":true,"ac.tz":true,"co.tz":true,"go.tz":true,"mil.tz":true,"ne.tz":true,"or.tz":true,"sc.tz":true,"ua":true,"com.ua":true,"edu.ua":true,"gov.ua":true,"in.ua":true,"net.ua":true,"org.ua":true,"cherkassy.ua":true,"chernigov.ua":true,"chernovtsy.ua":true,"ck.ua":true,"cn.ua":true,"crimea.ua":true,"cv.ua":true,"dn.ua":true,"dnepropetrovsk.ua":true,"donetsk.ua":true,"dp.ua":true,"if.ua":true,"ivano-frankivsk.ua":true,"kh.ua":true,"kharkov.ua":true,"kherson.ua":true,"khmelnitskiy.ua":true,"kiev.ua":true,"kirovograd.ua":true,"km.ua":true,"kr.ua":true,"ks.ua":true,"kv.ua":true,"lg.ua":true,"lugansk.ua":true,"lutsk.ua":true,"lviv.ua":true,"mk.ua":true,"nikolaev.ua":true,"od.ua":true,"odessa.ua":true,"pl.ua":true,"poltava.ua":true,"rovno.ua":true,"rv.ua":true,"sebastopol.ua":true,"sumy.ua":true,"te.ua":true,"ternopil.ua":true,"uzhgorod.ua":true,"vinnica.ua":true,"vn.ua":true,"zaporizhzhe.ua":true,"zp.ua":true,"zhitomir.ua":true,"zt.ua":true,"co.ua":true,"pp.ua":true,"ug":true,"co.ug":true,"ac.ug":true,"sc.ug":true,"go.ug":true,"ne.ug":true,"or.ug":true,"*.uk":true,"*.sch.uk":true,"bl.uk":false,"british-library.uk":false,"icnet.uk":false,"jet.uk":false,"mod.uk":false,"nel.uk":false,"nhs.uk":false,"nic.uk":false,"nls.uk":false,"national-library-scotland.uk":false,"parliament.uk":false,"police.uk":false,"us":true,"dni.us":true,"fed.us":true,"isa.us":true,"kids.us":true,"nsn.us":true,"ak.us":true,"al.us":true,"ar.us":true,"as.us":true,"az.us":true,"ca.us":true,"co.us":true,"ct.us":true,"dc.us":true,"de.us":true,"fl.us":true,"ga.us":true,"gu.us":true,"hi.us":true,"ia.us":true,"id.us":true,"il.us":true,"in.us":true,"ks.us":true,"ky.us":true,"la.us":true,"ma.us":true,"md.us":true,"me.us":true,"mi.us":true,"mn.us":true,"mo.us":true,"ms.us":true,"mt.us":true,"nc.us":true,"nd.us":true,"ne.us":true,"nh.us":true,"nj.us":true,"nm.us":true,"nv.us":true,"ny.us":true,"oh.us":true,"ok.us":true,"or.us":true,"pa.us":true,"pr.us":true,"ri.us":true,"sc.us":true,"sd.us":true,"tn.us":true,"tx.us":true,"ut.us":true,"vi.us":true,"vt.us":true,"va.us":true,"wa.us":true,"wi.us":true,"wv.us":true,"wy.us":true,"k12.ak.us":true,"k12.al.us":true,"k12.ar.us":true,"k12.as.us":true,"k12.az.us":true,"k12.ca.us":true,"k12.co.us":true,"k12.ct.us":true,"k12.dc.us":true,"k12.de.us":true,"k12.fl.us":true,"k12.ga.us":true,"k12.gu.us":true,"k12.ia.us":true,"k12.id.us":true,"k12.il.us":true,"k12.in.us":true,"k12.ks.us":true,"k12.ky.us":true,"k12.la.us":true,"k12.ma.us":true,"k12.md.us":true,"k12.me.us":true,"k12.mi.us":true,"k12.mn.us":true,"k12.mo.us":true,"k12.ms.us":true,"k12.mt.us":true,"k12.nc.us":true,"k12.nd.us":true,"k12.ne.us":true,"k12.nh.us":true,"k12.nj.us":true,"k12.nm.us":true,"k12.nv.us":true,"k12.ny.us":true,"k12.oh.us":true,"k12.ok.us":true,"k12.or.us":true,"k12.pa.us":true,"k12.pr.us":true,"k12.ri.us":true,"k12.sc.us":true,"k12.sd.us":true,"k12.tn.us":true,"k12.tx.us":true,"k12.ut.us":true,"k12.vi.us":true,"k12.vt.us":true,"k12.va.us":true,"k12.wa.us":true,"k12.wi.us":true,"k12.wv.us":true,"k12.wy.us":true,"cc.ak.us":true,"cc.al.us":true,"cc.ar.us":true,"cc.as.us":true,"cc.az.us":true,"cc.ca.us":true,"cc.co.us":true,"cc.ct.us":true,"cc.dc.us":true,"cc.de.us":true,"cc.fl.us":true,"cc.ga.us":true,"cc.gu.us":true,"cc.hi.us":true,"cc.ia.us":true,"cc.id.us":true,"cc.il.us":true,"cc.in.us":true,"cc.ks.us":true,"cc.ky.us":true,"cc.la.us":true,"cc.ma.us":true,"cc.md.us":true,"cc.me.us":true,"cc.mi.us":true,"cc.mn.us":true,"cc.mo.us":true,"cc.ms.us":true,"cc.mt.us":true,"cc.nc.us":true,"cc.nd.us":true,"cc.ne.us":true,"cc.nh.us":true,"cc.nj.us":true,"cc.nm.us":true,"cc.nv.us":true,"cc.ny.us":true,"cc.oh.us":true,"cc.ok.us":true,"cc.or.us":true,"cc.pa.us":true,"cc.pr.us":true,"cc.ri.us":true,"cc.sc.us":true,"cc.sd.us":true,"cc.tn.us":true,"cc.tx.us":true,"cc.ut.us":true,"cc.vi.us":true,"cc.vt.us":true,"cc.va.us":true,"cc.wa.us":true,"cc.wi.us":true,"cc.wv.us":true,"cc.wy.us":true,"lib.ak.us":true,"lib.al.us":true,"lib.ar.us":true,"lib.as.us":true,"lib.az.us":true,"lib.ca.us":true,"lib.co.us":true,"lib.ct.us":true,"lib.dc.us":true,"lib.de.us":true,"lib.fl.us":true,"lib.ga.us":true,"lib.gu.us":true,"lib.hi.us":true,"lib.ia.us":true,"lib.id.us":true,"lib.il.us":true,"lib.in.us":true,"lib.ks.us":true,"lib.ky.us":true,"lib.la.us":true,"lib.ma.us":true,"lib.md.us":true,"lib.me.us":true,"lib.mi.us":true,"lib.mn.us":true,"lib.mo.us":true,"lib.ms.us":true,"lib.mt.us":true,"lib.nc.us":true,"lib.nd.us":true,"lib.ne.us":true,"lib.nh.us":true,"lib.nj.us":true,"lib.nm.us":true,"lib.nv.us":true,"lib.ny.us":true,"lib.oh.us":true,"lib.ok.us":true,"lib.or.us":true,"lib.pa.us":true,"lib.pr.us":true,"lib.ri.us":true,"lib.sc.us":true,"lib.sd.us":true,"lib.tn.us":true,"lib.tx.us":true,"lib.ut.us":true,"lib.vi.us":true,"lib.vt.us":true,"lib.va.us":true,"lib.wa.us":true,"lib.wi.us":true,"lib.wv.us":true,"lib.wy.us":true,"pvt.k12.ma.us":true,"chtr.k12.ma.us":true,"paroch.k12.ma.us":true,"*.uy":true,"uz":true,"com.uz":true,"co.uz":true,"va":true,"vc":true,"com.vc":true,"net.vc":true,"org.vc":true,"gov.vc":true,"mil.vc":true,"edu.vc":true,"*.ve":true,"vg":true,"vi":true,"co.vi":true,"com.vi":true,"k12.vi":true,"net.vi":true,"org.vi":true,"vn":true,"com.vn":true,"net.vn":true,"org.vn":true,"edu.vn":true,"gov.vn":true,"int.vn":true,"ac.vn":true,"biz.vn":true,"info.vn":true,"name.vn":true,"pro.vn":true,"health.vn":true,"vu":true,"wf":true,"ws":true,"com.ws":true,"net.ws":true,"org.ws":true,"gov.ws":true,"edu.ws":true,"yt":true,"xn--mgbaam7a8h":true,"xn--54b7fta0cc":true,"xn--fiqs8s":true,"xn--fiqz9s":true,"xn--lgbbat1ad8j":true,"xn--wgbh1c":true,"xn--node":true,"xn--j6w193g":true,"xn--h2brj9c":true,"xn--mgbbh1a71e":true,"xn--fpcrj9c3d":true,"xn--gecrj9c":true,"xn--s9brj9c":true,"xn--45brj9c":true,"xn--xkc2dl3a5ee0h":true,"xn--mgba3a4f16a":true,"xn--mgba3a4fra":true,"xn--mgbayh7gpa":true,"xn--3e0b707e":true,"xn--fzc2c9e2c":true,"xn--xkc2al3hye2a":true,"xn--mgbc0a9azcg":true,"xn--mgb9awbf":true,"xn--ygbi2ammx":true,"xn--90a3ac":true,"xn--p1ai":true,"xn--wgbl6a":true,"xn--mgberp4a5d4ar":true,"xn--mgberp4a5d4a87g":true,"xn--mgbqly7c0a67fbc":true,"xn--mgbqly7cvafr":true,"xn--ogbpf8fl":true,"xn--mgbtf8fl":true,"xn--yfro4i67o":true,"xn--clchc0ea0b2g2a9gcd":true,"xn--o3cw4h":true,"xn--pgbs0dh":true,"xn--kpry57d":true,"xn--kprw13d":true,"xn--nnx388a":true,"xn--j1amh":true,"xn--mgb2ddes":true,"xxx":true,"*.ye":true,"*.za":true,"*.zm":true,"*.zw":true,"biz.at":true,"info.at":true,"priv.at":true,"co.ca":true,"ar.com":true,"br.com":true,"cn.com":true,"de.com":true,"eu.com":true,"gb.com":true,"gr.com":true,"hu.com":true,"jpn.com":true,"kr.com":true,"no.com":true,"qc.com":true,"ru.com":true,"sa.com":true,"se.com":true,"uk.com":true,"us.com":true,"uy.com":true,"za.com":true,"gb.net":true,"jp.net":true,"se.net":true,"uk.net":true,"ae.org":true,"us.org":true,"com.de":true,"operaunite.com":true,"appspot.com":true,"iki.fi":true,"c.la":true,"za.net":true,"za.org":true,"co.nl":true,"co.no":true,"co.pl":true,"dyndns-at-home.com":true,"dyndns-at-work.com":true,"dyndns-blog.com":true,"dyndns-free.com":true,"dyndns-home.com":true,"dyndns-ip.com":true,"dyndns-mail.com":true,"dyndns-office.com":true,"dyndns-pics.com":true,"dyndns-remote.com":true,"dyndns-server.com":true,"dyndns-web.com":true,"dyndns-wiki.com":true,"dyndns-work.com":true,"dyndns.biz":true,"dyndns.info":true,"dyndns.org":true,"dyndns.tv":true,"at-band-camp.net":true,"ath.cx":true,"barrel-of-knowledge.info":true,"barrell-of-knowledge.info":true,"better-than.tv":true,"blogdns.com":true,"blogdns.net":true,"blogdns.org":true,"blogsite.org":true,"boldlygoingnowhere.org":true,"broke-it.net":true,"buyshouses.net":true,"cechire.com":true,"dnsalias.com":true,"dnsalias.net":true,"dnsalias.org":true,"dnsdojo.com":true,"dnsdojo.net":true,"dnsdojo.org":true,"does-it.net":true,"doesntexist.com":true,"doesntexist.org":true,"dontexist.com":true,"dontexist.net":true,"dontexist.org":true,"doomdns.com":true,"doomdns.org":true,"dvrdns.org":true,"dyn-o-saur.com":true,"dynalias.com":true,"dynalias.net":true,"dynalias.org":true,"dynathome.net":true,"dyndns.ws":true,"endofinternet.net":true,"endofinternet.org":true,"endoftheinternet.org":true,"est-a-la-maison.com":true,"est-a-la-masion.com":true,"est-le-patron.com":true,"est-mon-blogueur.com":true,"for-better.biz":true,"for-more.biz":true,"for-our.info":true,"for-some.biz":true,"for-the.biz":true,"forgot.her.name":true,"forgot.his.name":true,"from-ak.com":true,"from-al.com":true,"from-ar.com":true,"from-az.net":true,"from-ca.com":true,"from-co.net":true,"from-ct.com":true,"from-dc.com":true,"from-de.com":true,"from-fl.com":true,"from-ga.com":true,"from-hi.com":true,"from-ia.com":true,"from-id.com":true,"from-il.com":true,"from-in.com":true,"from-ks.com":true,"from-ky.com":true,"from-la.net":true,"from-ma.com":true,"from-md.com":true,"from-me.org":true,"from-mi.com":true,"from-mn.com":true,"from-mo.com":true,"from-ms.com":true,"from-mt.com":true,"from-nc.com":true,"from-nd.com":true,"from-ne.com":true,"from-nh.com":true,"from-nj.com":true,"from-nm.com":true,"from-nv.com":true,"from-ny.net":true,"from-oh.com":true,"from-ok.com":true,"from-or.com":true,"from-pa.com":true,"from-pr.com":true,"from-ri.com":true,"from-sc.com":true,"from-sd.com":true,"from-tn.com":true,"from-tx.com":true,"from-ut.com":true,"from-va.com":true,"from-vt.com":true,"from-wa.com":true,"from-wi.com":true,"from-wv.com":true,"from-wy.com":true,"ftpaccess.cc":true,"fuettertdasnetz.de":true,"game-host.org":true,"game-server.cc":true,"getmyip.com":true,"gets-it.net":true,"go.dyndns.org":true,"gotdns.com":true,"gotdns.org":true,"groks-the.info":true,"groks-this.info":true,"ham-radio-op.net":true,"here-for-more.info":true,"hobby-site.com":true,"hobby-site.org":true,"home.dyndns.org":true,"homedns.org":true,"homeftp.net":true,"homeftp.org":true,"homeip.net":true,"homelinux.com":true,"homelinux.net":true,"homelinux.org":true,"homeunix.com":true,"homeunix.net":true,"homeunix.org":true,"iamallama.com":true,"in-the-band.net":true,"is-a-anarchist.com":true,"is-a-blogger.com":true,"is-a-bookkeeper.com":true,"is-a-bruinsfan.org":true,"is-a-bulls-fan.com":true,"is-a-candidate.org":true,"is-a-caterer.com":true,"is-a-celticsfan.org":true,"is-a-chef.com":true,"is-a-chef.net":true,"is-a-chef.org":true,"is-a-conservative.com":true,"is-a-cpa.com":true,"is-a-cubicle-slave.com":true,"is-a-democrat.com":true,"is-a-designer.com":true,"is-a-doctor.com":true,"is-a-financialadvisor.com":true,"is-a-geek.com":true,"is-a-geek.net":true,"is-a-geek.org":true,"is-a-green.com":true,"is-a-guru.com":true,"is-a-hard-worker.com":true,"is-a-hunter.com":true,"is-a-knight.org":true,"is-a-landscaper.com":true,"is-a-lawyer.com":true,"is-a-liberal.com":true,"is-a-libertarian.com":true,"is-a-linux-user.org":true,"is-a-llama.com":true,"is-a-musician.com":true,"is-a-nascarfan.com":true,"is-a-nurse.com":true,"is-a-painter.com":true,"is-a-patsfan.org":true,"is-a-personaltrainer.com":true,"is-a-photographer.com":true,"is-a-player.com":true,"is-a-republican.com":true,"is-a-rockstar.com":true,"is-a-socialist.com":true,"is-a-soxfan.org":true,"is-a-student.com":true,"is-a-teacher.com":true,"is-a-techie.com":true,"is-a-therapist.com":true,"is-an-accountant.com":true,"is-an-actor.com":true,"is-an-actress.com":true,"is-an-anarchist.com":true,"is-an-artist.com":true,"is-an-engineer.com":true,"is-an-entertainer.com":true,"is-by.us":true,"is-certified.com":true,"is-found.org":true,"is-gone.com":true,"is-into-anime.com":true,"is-into-cars.com":true,"is-into-cartoons.com":true,"is-into-games.com":true,"is-leet.com":true,"is-lost.org":true,"is-not-certified.com":true,"is-saved.org":true,"is-slick.com":true,"is-uberleet.com":true,"is-very-bad.org":true,"is-very-evil.org":true,"is-very-good.org":true,"is-very-nice.org":true,"is-very-sweet.org":true,"is-with-theband.com":true,"isa-geek.com":true,"isa-geek.net":true,"isa-geek.org":true,"isa-hockeynut.com":true,"issmarterthanyou.com":true,"isteingeek.de":true,"istmein.de":true,"kicks-ass.net":true,"kicks-ass.org":true,"knowsitall.info":true,"land-4-sale.us":true,"lebtimnetz.de":true,"leitungsen.de":true,"likes-pie.com":true,"likescandy.com":true,"merseine.nu":true,"mine.nu":true,"misconfused.org":true,"mypets.ws":true,"myphotos.cc":true,"neat-url.com":true,"office-on-the.net":true,"on-the-web.tv":true,"podzone.net":true,"podzone.org":true,"readmyblog.org":true,"saves-the-whales.com":true,"scrapper-site.net":true,"scrapping.cc":true,"selfip.biz":true,"selfip.com":true,"selfip.info":true,"selfip.net":true,"selfip.org":true,"sells-for-less.com":true,"sells-for-u.com":true,"sells-it.net":true,"sellsyourhome.org":true,"servebbs.com":true,"servebbs.net":true,"servebbs.org":true,"serveftp.net":true,"serveftp.org":true,"servegame.org":true,"shacknet.nu":true,"simple-url.com":true,"space-to-rent.com":true,"stuff-4-sale.org":true,"stuff-4-sale.us":true,"teaches-yoga.com":true,"thruhere.net":true,"traeumtgerade.de":true,"webhop.biz":true,"webhop.info":true,"webhop.net":true,"webhop.org":true,"worse-than.tv":true,"writesthisblog.com":true});
    
    // END of automatically generated file
    
  provide("tough-cookie/lib/pubsuffix", module.exports);
}(global));

// pakmanager:tough-cookie/lib/store
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  'use strict';
    /*jshint unused:false */
    
    function Store() {
    }
    exports.Store = Store;
    
    // Stores may be synchronous, but are still required to use a
    // Continuation-Passing Style API.  The CookieJar itself will expose a "*Sync"
    // API that converts from synchronous-callbacks to imperative style.
    Store.prototype.synchronous = false;
    
    Store.prototype.findCookie = function(domain, path, key, cb) {
      throw new Error('findCookie is not implemented');
    };
    
    Store.prototype.findCookies = function(domain, path, cb) {
      throw new Error('findCookies is not implemented');
    };
    
    Store.prototype.putCookie = function(cookie, cb) {
      throw new Error('putCookie is not implemented');
    };
    
    Store.prototype.updateCookie = function(oldCookie, newCookie, cb) {
      // recommended default implementation:
      // return this.putCookie(newCookie, cb);
      throw new Error('updateCookie is not implemented');
    };
    
    Store.prototype.removeCookie = function(domain, path, key, cb) {
      throw new Error('removeCookie is not implemented');
    };
    
    Store.prototype.removeCookies = function removeCookies(domain, path, cb) {
      throw new Error('removeCookies is not implemented');
    };
    
  provide("tough-cookie/lib/store", module.exports);
}(global));

// pakmanager:tough-cookie/lib/cookie
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  /*
     * Copyright GoInstant, Inc. and other contributors. All rights reserved.
     * Permission is hereby granted, free of charge, to any person obtaining a copy
     * of this software and associated documentation files (the "Software"), to
     * deal in the Software without restriction, including without limitation the
     * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
     * sell copies of the Software, and to permit persons to whom the Software is
     * furnished to do so, subject to the following conditions:
     *
     * The above copyright notice and this permission notice shall be included in
     * all copies or substantial portions of the Software.
     *
     * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
     * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
     * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
     * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
     * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
     * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
     * IN THE SOFTWARE.
     */
    
    'use strict';
    var net = require('net');
    var urlParse = require('url').parse;
    var pubsuffix =  require('tough-cookie/lib/pubsuffix');
    var Store =  require('tough-cookie/lib/store').Store;
    
    var punycode;
    try {
      punycode = require('punycode');
    } catch(e) {
      console.warn("cookie: can't load punycode; won't use punycode for domain normalization");
    }
    
    var DATE_DELIM = /[\x09\x20-\x2F\x3B-\x40\x5B-\x60\x7B-\x7E]/;
    
    // From RFC2616 S2.2:
    var TOKEN = /[\x21\x23-\x26\x2A\x2B\x2D\x2E\x30-\x39\x41-\x5A\x5E-\x7A\x7C\x7E]/;
    
    // From RFC6265 S4.1.1
    // note that it excludes \x3B ";"
    var COOKIE_OCTET  = /[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]/;
    var COOKIE_OCTETS = new RegExp('^'+COOKIE_OCTET.source+'$');
    
    // The name/key cannot be empty but the value can (S5.2):
    var COOKIE_PAIR_STRICT = new RegExp('^('+TOKEN.source+'+)=("?)('+COOKIE_OCTET.source+'*)\\2$');
    var COOKIE_PAIR = /^([^=\s]+)\s*=\s*("?)\s*(.*)\s*\2\s*$/;
    
    // RFC6265 S4.1.1 defines extension-av as 'any CHAR except CTLs or ";"'
    // Note ';' is \x3B
    var NON_CTL_SEMICOLON = /[\x20-\x3A\x3C-\x7E]+/;
    var EXTENSION_AV = NON_CTL_SEMICOLON;
    var PATH_VALUE = NON_CTL_SEMICOLON;
    
    // Used for checking whether or not there is a trailing semi-colon
    var TRAILING_SEMICOLON = /;+$/;
    
    /* RFC6265 S5.1.1.5:
     * [fail if] the day-of-month-value is less than 1 or greater than 31
     */
    var DAY_OF_MONTH = /^(0?[1-9]|[12][0-9]|3[01])$/;
    
    /* RFC6265 S5.1.1.5:
     * [fail if]
     * *  the hour-value is greater than 23,
     * *  the minute-value is greater than 59, or
     * *  the second-value is greater than 59.
     */
    var TIME = /(0?[0-9]|1[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])/;
    var STRICT_TIME = /^(0?[0-9]|1[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/;
    
    var MONTH = /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$/i;
    var MONTH_TO_NUM = {
      jan:0, feb:1, mar:2, apr:3, may:4, jun:5,
      jul:6, aug:7, sep:8, oct:9, nov:10, dec:11
    };
    var NUM_TO_MONTH = [
      'Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'
    ];
    var NUM_TO_DAY = [
      'Sun','Mon','Tue','Wed','Thu','Fri','Sat'
    ];
    
    var YEAR = /^([1-9][0-9]{1,3})$/; // 2 to 4 digits
    
    var MAX_TIME = 2147483647000; // 31-bit max
    var MIN_TIME = 0; // 31-bit min
    
    
    // RFC6265 S5.1.1 date parser:
    function parseDate(str,strict) {
      if (!str) {
        return;
      }
      var found_time, found_dom, found_month, found_year;
    
      /* RFC6265 S5.1.1:
       * 2. Process each date-token sequentially in the order the date-tokens
       * appear in the cookie-date
       */
      var tokens = str.split(DATE_DELIM);
      if (!tokens) {
        return;
      }
    
      var date = new Date();
      date.setMilliseconds(0);
    
      for (var i=0; i<tokens.length; i++) {
        var token = tokens[i].trim();
        if (!token.length) {
          continue;
        }
    
        var result;
    
        /* 2.1. If the found-time flag is not set and the token matches the time
         * production, set the found-time flag and set the hour- value,
         * minute-value, and second-value to the numbers denoted by the digits in
         * the date-token, respectively.  Skip the remaining sub-steps and continue
         * to the next date-token.
         */
        if (!found_time) {
          result = (strict ? STRICT_TIME : TIME).exec(token);
          if (result) {
            found_time = true;
            date.setUTCHours(result[1]);
            date.setUTCMinutes(result[2]);
            date.setUTCSeconds(result[3]);
            continue;
          }
        }
    
        /* 2.2. If the found-day-of-month flag is not set and the date-token matches
         * the day-of-month production, set the found-day-of- month flag and set
         * the day-of-month-value to the number denoted by the date-token.  Skip
         * the remaining sub-steps and continue to the next date-token.
         */
        if (!found_dom) {
          result = DAY_OF_MONTH.exec(token);
          if (result) {
            found_dom = true;
            date.setUTCDate(result[1]);
            continue;
          }
        }
    
        /* 2.3. If the found-month flag is not set and the date-token matches the
         * month production, set the found-month flag and set the month-value to
         * the month denoted by the date-token.  Skip the remaining sub-steps and
         * continue to the next date-token.
         */
        if (!found_month) {
          result = MONTH.exec(token);
          if (result) {
            found_month = true;
            date.setUTCMonth(MONTH_TO_NUM[result[1].toLowerCase()]);
            continue;
          }
        }
    
        /* 2.4. If the found-year flag is not set and the date-token matches the year
         * production, set the found-year flag and set the year-value to the number
         * denoted by the date-token.  Skip the remaining sub-steps and continue to
         * the next date-token.
         */
        if (!found_year) {
          result = YEAR.exec(token);
          if (result) {
            var year = result[0];
            /* From S5.1.1:
             * 3.  If the year-value is greater than or equal to 70 and less
             * than or equal to 99, increment the year-value by 1900.
             * 4.  If the year-value is greater than or equal to 0 and less
             * than or equal to 69, increment the year-value by 2000.
             */
            if (70 <= year && year <= 99) {
              year += 1900;
            } else if (0 <= year && year <= 69) {
              year += 2000;
            }
    
            if (year < 1601) {
              return; // 5. ... the year-value is less than 1601
            }
    
            found_year = true;
            date.setUTCFullYear(year);
            continue;
          }
        }
      }
    
      if (!(found_time && found_dom && found_month && found_year)) {
        return; // 5. ... at least one of the found-day-of-month, found-month, found-
                // year, or found-time flags is not set,
      }
    
      return date;
    }
    
    function formatDate(date) {
      var d = date.getUTCDate(); d = d >= 10 ? d : '0'+d;
      var h = date.getUTCHours(); h = h >= 10 ? h : '0'+h;
      var m = date.getUTCMinutes(); m = m >= 10 ? m : '0'+m;
      var s = date.getUTCSeconds(); s = s >= 10 ? s : '0'+s;
      return NUM_TO_DAY[date.getUTCDay()] + ', ' +
        d+' '+ NUM_TO_MONTH[date.getUTCMonth()] +' '+ date.getUTCFullYear() +' '+
        h+':'+m+':'+s+' GMT';
    }
    
    // S5.1.2 Canonicalized Host Names
    function canonicalDomain(str) {
      if (str == null) {
        return null;
      }
      str = str.trim().replace(/^\./,''); // S4.1.2.3 & S5.2.3: ignore leading .
    
      // convert to IDN if any non-ASCII characters
      if (punycode && /[^\u0001-\u007f]/.test(str)) {
        str = punycode.toASCII(str);
      }
    
      return str.toLowerCase();
    }
    
    // S5.1.3 Domain Matching
    function domainMatch(str, domStr, canonicalize) {
      if (str == null || domStr == null) {
        return null;
      }
      if (canonicalize !== false) {
        str = canonicalDomain(str);
        domStr = canonicalDomain(domStr);
      }
    
      /*
       * "The domain string and the string are identical. (Note that both the
       * domain string and the string will have been canonicalized to lower case at
       * this point)"
       */
      if (str == domStr) {
        return true;
      }
    
      /* "All of the following [three] conditions hold:" (order adjusted from the RFC) */
    
      /* "* The string is a host name (i.e., not an IP address)." */
      if (net.isIP(str)) {
        return false;
      }
    
      /* "* The domain string is a suffix of the string" */
      var idx = str.indexOf(domStr);
      if (idx <= 0) {
        return false; // it's a non-match (-1) or prefix (0)
      }
    
      // e.g "a.b.c".indexOf("b.c") === 2
      // 5 === 3+2
      if (str.length !== domStr.length + idx) { // it's not a suffix
        return false;
      }
    
      /* "* The last character of the string that is not included in the domain
      * string is a %x2E (".") character." */
      if (str.substr(idx-1,1) !== '.') {
        return false;
      }
    
      return true;
    }
    
    
    // RFC6265 S5.1.4 Paths and Path-Match
    
    /*
     * "The user agent MUST use an algorithm equivalent to the following algorithm
     * to compute the default-path of a cookie:"
     *
     * Assumption: the path (and not query part or absolute uri) is passed in.
     */
    function defaultPath(path) {
      // "2. If the uri-path is empty or if the first character of the uri-path is not
      // a %x2F ("/") character, output %x2F ("/") and skip the remaining steps.
      if (!path || path.substr(0,1) !== "/") {
        return "/";
      }
    
      // "3. If the uri-path contains no more than one %x2F ("/") character, output
      // %x2F ("/") and skip the remaining step."
      if (path === "/") {
        return path;
      }
    
      var rightSlash = path.lastIndexOf("/");
      if (rightSlash === 0) {
        return "/";
      }
    
      // "4. Output the characters of the uri-path from the first character up to,
      // but not including, the right-most %x2F ("/")."
      return path.slice(0, rightSlash);
    }
    
    /*
     * "A request-path path-matches a given cookie-path if at least one of the
     * following conditions holds:"
     */
    function pathMatch(reqPath,cookiePath) {
      // "o  The cookie-path and the request-path are identical."
      if (cookiePath === reqPath) {
        return true;
      }
    
      var idx = reqPath.indexOf(cookiePath);
      if (idx === 0) {
        // "o  The cookie-path is a prefix of the request-path, and the last
        // character of the cookie-path is %x2F ("/")."
        if (cookiePath.substr(-1) === "/") {
          return true;
        }
    
        // " o  The cookie-path is a prefix of the request-path, and the first
        // character of the request-path that is not included in the cookie- path
        // is a %x2F ("/") character."
        if (reqPath.substr(cookiePath.length,1) === "/") {
          return true;
        }
      }
    
      return false;
    }
    
    function parse(str, strict) {
      str = str.trim();
    
      // S4.1.1 Trailing semi-colons are not part of the specification.
      // If we are not in strict mode we remove the trailing semi-colons.
      var semiColonCheck = TRAILING_SEMICOLON.exec(str);
      if (semiColonCheck) {
        if (strict) {
          return;
        }
        str = str.slice(0, semiColonCheck.index);
      }
    
      // We use a regex to parse the "name-value-pair" part of S5.2
      var firstSemi = str.indexOf(';'); // S5.2 step 1
      var pairRx = strict ? COOKIE_PAIR_STRICT : COOKIE_PAIR;
      var result = pairRx.exec(firstSemi === -1 ? str : str.substr(0,firstSemi));
    
      // Rx satisfies the "the name string is empty" and "lacks a %x3D ("=")"
      // constraints as well as trimming any whitespace.
      if (!result) {
        return;
      }
    
      var c = new Cookie();
      c.key = result[1]; // the regexp should trim() already
      c.value = result[3]; // [2] is quotes or empty-string
    
      if (firstSemi === -1) {
        return c;
      }
    
      // S5.2.3 "unparsed-attributes consist of the remainder of the set-cookie-string
      // (including the %x3B (";") in question)." plus later on in the same section
      // "discard the first ";" and trim".
      var unparsed = str.slice(firstSemi).replace(/^\s*;\s*/,'').trim();
    
      // "If the unparsed-attributes string is empty, skip the rest of these
      // steps."
      if (unparsed.length === 0) {
        return c;
      }
    
      /*
       * S5.2 says that when looping over the items "[p]rocess the attribute-name
       * and attribute-value according to the requirements in the following
       * subsections" for every item.  Plus, for many of the individual attributes
       * in S5.3 it says to use the "attribute-value of the last attribute in the
       * cookie-attribute-list".  Therefore, in this implementation, we overwrite
       * the previous value.
       */
      var cookie_avs = unparsed.split(/\s*;\s*/);
      while (cookie_avs.length) {
        var av = cookie_avs.shift();
    
        if (strict && !EXTENSION_AV.test(av)) {
          return;
        }
    
        var av_sep = av.indexOf('=');
        var av_key, av_value;
        if (av_sep === -1) {
          av_key = av;
          av_value = null;
        } else {
          av_key = av.substr(0,av_sep);
          av_value = av.substr(av_sep+1);
        }
    
        av_key = av_key.trim().toLowerCase();
        if (av_value) {
          av_value = av_value.trim();
        }
    
        switch(av_key) {
        case 'expires': // S5.2.1
          if (!av_value) {if(strict){return;}else{break;} }
          var exp = parseDate(av_value,strict);
          // "If the attribute-value failed to parse as a cookie date, ignore the
          // cookie-av."
          if (exp == null) { if(strict){return;}else{break;} }
          c.expires = exp;
          // over and underflow not realistically a concern: V8's getTime() seems to
          // store something larger than a 32-bit time_t (even with 32-bit node)
          break;
    
        case 'max-age': // S5.2.2
          if (!av_value) { if(strict){return;}else{break;} }
          // "If the first character of the attribute-value is not a DIGIT or a "-"
          // character ...[or]... If the remainder of attribute-value contains a
          // non-DIGIT character, ignore the cookie-av."
          if (!/^-?[0-9]+$/.test(av_value)) { if(strict){return;}else{break;} }
          var delta = parseInt(av_value,10);
          if (strict && delta <= 0) {
            return; // S4.1.1
          }
          // "If delta-seconds is less than or equal to zero (0), let expiry-time
          // be the earliest representable date and time."
          c.setMaxAge(delta);
          break;
    
        case 'domain': // S5.2.3
          // "If the attribute-value is empty, the behavior is undefined.  However,
          // the user agent SHOULD ignore the cookie-av entirely."
          if (!av_value) { if(strict){return;}else{break;} }
          // S5.2.3 "Let cookie-domain be the attribute-value without the leading %x2E
          // (".") character."
          var domain = av_value.trim().replace(/^\./,'');
          if (!domain) { if(strict){return;}else{break;} } // see "is empty" above
          // "Convert the cookie-domain to lower case."
          c.domain = domain.toLowerCase();
          break;
    
        case 'path': // S5.2.4
          /*
           * "If the attribute-value is empty or if the first character of the
           * attribute-value is not %x2F ("/"):
           *   Let cookie-path be the default-path.
           * Otherwise:
           *   Let cookie-path be the attribute-value."
           *
           * We'll represent the default-path as null since it depends on the
           * context of the parsing.
           */
          if (!av_value || av_value.substr(0,1) != "/") {
            if(strict){return;}else{break;}
          }
          c.path = av_value;
          break;
    
        case 'secure': // S5.2.5
          /*
           * "If the attribute-name case-insensitively matches the string "Secure",
           * the user agent MUST append an attribute to the cookie-attribute-list
           * with an attribute-name of Secure and an empty attribute-value."
           */
          if (av_value != null) { if(strict){return;} }
          c.secure = true;
          break;
    
        case 'httponly': // S5.2.6 -- effectively the same as 'secure'
          if (av_value != null) { if(strict){return;} }
          c.httpOnly = true;
          break;
    
        default:
          c.extensions = c.extensions || [];
          c.extensions.push(av);
          break;
        }
      }
    
      // ensure a default date for sorting:
      c.creation = new Date();
      return c;
    }
    
    function fromJSON(str) {
      if (!str) {
        return null;
      }
    
      var obj;
      try {
        obj = JSON.parse(str);
      } catch (e) {
        return null;
      }
    
      var c = new Cookie();
      for (var i=0; i<numCookieProperties; i++) {
        var prop = cookieProperties[i];
        if (obj[prop] == null) {
          continue;
        }
        if (prop === 'expires' ||
            prop === 'creation' ||
            prop === 'lastAccessed')
        {
          c[prop] = obj[prop] == "Infinity" ? "Infinity" : new Date(obj[prop]);
        } else {
          c[prop] = obj[prop];
        }
      }
    
    
      // ensure a default date for sorting:
      c.creation = c.creation || new Date();
    
      return c;
    }
    
    /* Section 5.4 part 2:
     * "*  Cookies with longer paths are listed before cookies with
     *     shorter paths.
     *
     *  *  Among cookies that have equal-length path fields, cookies with
     *     earlier creation-times are listed before cookies with later
     *     creation-times."
     */
    
    function cookieCompare(a,b) {
      // descending for length: b CMP a
      var deltaLen = (b.path ? b.path.length : 0) - (a.path ? a.path.length : 0);
      if (deltaLen !== 0) {
        return deltaLen;
      }
      // ascending for time: a CMP b
      return (a.creation ? a.creation.getTime() : MAX_TIME) -
             (b.creation ? b.creation.getTime() : MAX_TIME);
    }
    
    // Gives the permutation of all possible domainMatch()es of a given domain. The
    // array is in shortest-to-longest order.  Handy for indexing.
    function permuteDomain(domain) {
      var pubSuf = pubsuffix.getPublicSuffix(domain);
      if (!pubSuf) {
        return null;
      }
      if (pubSuf == domain) {
        return [domain];
      }
    
      var prefix = domain.slice(0,-(pubSuf.length+1)); // ".example.com"
      var parts = prefix.split('.').reverse();
      var cur = pubSuf;
      var permutations = [cur];
      while (parts.length) {
        cur = parts.shift()+'.'+cur;
        permutations.push(cur);
      }
      return permutations;
    }
    
    // Gives the permutation of all possible pathMatch()es of a given path. The
    // array is in longest-to-shortest order.  Handy for indexing.
    function permutePath(path) {
      if (path === '/') {
        return ['/'];
      }
      if (path.lastIndexOf('/') === path.length-1) {
        path = path.substr(0,path.length-1);
      }
      var permutations = [path];
      while (path.length > 1) {
        var lindex = path.lastIndexOf('/');
        if (lindex === 0) {
          break;
        }
        path = path.substr(0,lindex);
        permutations.push(path);
      }
      permutations.push('/');
      return permutations;
    }
    
    
    function Cookie (opts) {
      if (typeof opts !== "object") {
        return;
      }
      Object.keys(opts).forEach(function (key) {
        if (Cookie.prototype.hasOwnProperty(key)) {
          this[key] = opts[key] || Cookie.prototype[key];
        }
      }.bind(this));
    }
    
    Cookie.parse = parse;
    Cookie.fromJSON = fromJSON;
    
    Cookie.prototype.key = "";
    Cookie.prototype.value = "";
    
    // the order in which the RFC has them:
    Cookie.prototype.expires = "Infinity"; // coerces to literal Infinity
    Cookie.prototype.maxAge = null; // takes precedence over expires for TTL
    Cookie.prototype.domain = null;
    Cookie.prototype.path = null;
    Cookie.prototype.secure = false;
    Cookie.prototype.httpOnly = false;
    Cookie.prototype.extensions = null;
    
    // set by the CookieJar:
    Cookie.prototype.hostOnly = null; // boolean when set
    Cookie.prototype.pathIsDefault = null; // boolean when set
    Cookie.prototype.creation = null; // Date when set; defaulted by Cookie.parse
    Cookie.prototype.lastAccessed = null; // Date when set
    
    var cookieProperties = Object.freeze(Object.keys(Cookie.prototype).map(function(p) {
      if (p instanceof Function) {
        return;
      }
      return p;
    }));
    var numCookieProperties = cookieProperties.length;
    
    Cookie.prototype.inspect = function inspect() {
      var now = Date.now();
      return 'Cookie="'+this.toString() +
        '; hostOnly='+(this.hostOnly != null ? this.hostOnly : '?') +
        '; aAge='+(this.lastAccessed ? (now-this.lastAccessed.getTime())+'ms' : '?') +
        '; cAge='+(this.creation ? (now-this.creation.getTime())+'ms' : '?') +
        '"';
    };
    
    Cookie.prototype.validate = function validate() {
      if (!COOKIE_OCTETS.test(this.value)) {
        return false;
      }
      if (this.expires != Infinity && !(this.expires instanceof Date) && !parseDate(this.expires,true)) {
        return false;
      }
      if (this.maxAge != null && this.maxAge <= 0) {
        return false; // "Max-Age=" non-zero-digit *DIGIT
      }
      if (this.path != null && !PATH_VALUE.test(this.path)) {
        return false;
      }
    
      var cdomain = this.cdomain();
      if (cdomain) {
        if (cdomain.match(/\.$/)) {
          return false; // S4.1.2.3 suggests that this is bad. domainMatch() tests confirm this
        }
        var suffix = pubsuffix.getPublicSuffix(cdomain);
        if (suffix == null) { // it's a public suffix
          return false;
        }
      }
      return true;
    };
    
    Cookie.prototype.setExpires = function setExpires(exp) {
      if (exp instanceof Date) {
        this.expires = exp;
      } else {
        this.expires = parseDate(exp) || "Infinity";
      }
    };
    
    Cookie.prototype.setMaxAge = function setMaxAge(age) {
      if (age === Infinity || age === -Infinity) {
        this.maxAge = age.toString(); // so JSON.stringify() works
      } else {
        this.maxAge = age;
      }
    };
    
    // gives Cookie header format
    Cookie.prototype.cookieString = function cookieString() {
      var val = this.value;
      if (val == null) {
        val = '';
      }
      return this.key+'='+val;
    };
    
    // gives Set-Cookie header format
    Cookie.prototype.toString = function toString() {
      var str = this.cookieString();
    
      if (this.expires != Infinity) {
        if (this.expires instanceof Date) {
          str += '; Expires='+formatDate(this.expires);
        } else {
          str += '; Expires='+this.expires;
        }
      }
    
      if (this.maxAge != null && this.maxAge != Infinity) {
        str += '; Max-Age='+this.maxAge;
      }
    
      if (this.domain && !this.hostOnly) {
        str += '; Domain='+this.domain;
      }
      if (this.path) {
        str += '; Path='+this.path;
      }
    
      if (this.secure) {
        str += '; Secure';
      }
      if (this.httpOnly) {
        str += '; HttpOnly';
      }
      if (this.extensions) {
        this.extensions.forEach(function(ext) {
          str += '; '+ext;
        });
      }
    
      return str;
    };
    
    // TTL() partially replaces the "expiry-time" parts of S5.3 step 3 (setCookie()
    // elsewhere)
    // S5.3 says to give the "latest representable date" for which we use Infinity
    // For "expired" we use 0
    Cookie.prototype.TTL = function TTL(now) {
      /* RFC6265 S4.1.2.2 If a cookie has both the Max-Age and the Expires
       * attribute, the Max-Age attribute has precedence and controls the
       * expiration date of the cookie.
       * (Concurs with S5.3 step 3)
       */
      if (this.maxAge != null) {
        return this.maxAge<=0 ? 0 : this.maxAge*1000;
      }
    
      var expires = this.expires;
      if (expires != Infinity) {
        if (!(expires instanceof Date)) {
          expires = parseDate(expires) || Infinity;
        }
    
        if (expires == Infinity) {
          return Infinity;
        }
    
        return expires.getTime() - (now || Date.now());
      }
    
      return Infinity;
    };
    
    // expiryTime() replaces the "expiry-time" parts of S5.3 step 3 (setCookie()
    // elsewhere)
    Cookie.prototype.expiryTime = function expiryTime(now) {
      if (this.maxAge != null) {
        var relativeTo = this.creation || now || new Date();
        var age = (this.maxAge <= 0) ? -Infinity : this.maxAge*1000;
        return relativeTo.getTime() + age;
      }
    
      if (this.expires == Infinity) {
        return Infinity;
      }
      return this.expires.getTime();
    };
    
    // expiryDate() replaces the "expiry-time" parts of S5.3 step 3 (setCookie()
    // elsewhere), except it returns a Date
    Cookie.prototype.expiryDate = function expiryDate(now) {
      var millisec = this.expiryTime(now);
      if (millisec == Infinity) {
        return new Date(MAX_TIME);
      } else if (millisec == -Infinity) {
        return new Date(MIN_TIME);
      } else {
        return new Date(millisec);
      }
    };
    
    // This replaces the "persistent-flag" parts of S5.3 step 3
    Cookie.prototype.isPersistent = function isPersistent() {
      return (this.maxAge != null || this.expires != Infinity);
    };
    
    // Mostly S5.1.2 and S5.2.3:
    Cookie.prototype.cdomain =
    Cookie.prototype.canonicalizedDomain = function canonicalizedDomain() {
      if (this.domain == null) {
        return null;
      }
      return canonicalDomain(this.domain);
    };
    
    
    var memstore;
    function CookieJar(store, rejectPublicSuffixes) {
      if (rejectPublicSuffixes != null) {
        this.rejectPublicSuffixes = rejectPublicSuffixes;
      }
    
      if (!store) {
        memstore = memstore ||  require('tough-cookie/lib/memstore');
        store = new memstore.MemoryCookieStore();
      }
      this.store = store;
    }
    CookieJar.prototype.store = null;
    CookieJar.prototype.rejectPublicSuffixes = true;
    var CAN_BE_SYNC = [];
    
    CAN_BE_SYNC.push('setCookie');
    CookieJar.prototype.setCookie = function(cookie, url, options, cb) {
      var err;
      var context = (url instanceof Object) ? url : urlParse(url);
      if (options instanceof Function) {
        cb = options;
        options = {};
      }
    
      var host = canonicalDomain(context.hostname);
    
      // S5.3 step 1
      if (!(cookie instanceof Cookie)) {
        cookie = Cookie.parse(cookie, options.strict === true);
      }
      if (!cookie) {
        err = new Error("Cookie failed to parse");
        return cb(options.ignoreError ? null : err);
      }
    
      // S5.3 step 2
      var now = options.now || new Date(); // will assign later to save effort in the face of errors
    
      // S5.3 step 3: NOOP; persistent-flag and expiry-time is handled by getCookie()
    
      // S5.3 step 4: NOOP; domain is null by default
    
      // S5.3 step 5: public suffixes
      if (this.rejectPublicSuffixes && cookie.domain) {
        var suffix = pubsuffix.getPublicSuffix(cookie.cdomain());
        if (suffix == null) { // e.g. "com"
          err = new Error("Cookie has domain set to a public suffix");
          return cb(options.ignoreError ? null : err);
        }
      }
    
      // S5.3 step 6:
      if (cookie.domain) {
        if (!domainMatch(host, cookie.cdomain(), false)) {
          err = new Error("Cookie not in this host's domain. Cookie:"+cookie.cdomain()+" Request:"+host);
          return cb(options.ignoreError ? null : err);
        }
    
        if (cookie.hostOnly == null) { // don't reset if already set
          cookie.hostOnly = false;
        }
    
      } else {
        cookie.hostOnly = true;
        cookie.domain = host;
      }
    
      // S5.3 step 7: "Otherwise, set the cookie's path to the default-path of the
      // request-uri"
      if (!cookie.path) {
        cookie.path = defaultPath(context.pathname);
        cookie.pathIsDefault = true;
      } else {
        if (cookie.path.length > 1 && cookie.path.substr(-1) == '/') {
          cookie.path = cookie.path.slice(0,-1);
        }
      }
    
      // S5.3 step 8: NOOP; secure attribute
      // S5.3 step 9: NOOP; httpOnly attribute
    
      // S5.3 step 10
      if (options.http === false && cookie.httpOnly) {
        err = new Error("Cookie is HttpOnly and this isn't an HTTP API");
        return cb(options.ignoreError ? null : err);
      }
    
      var store = this.store;
    
      if (!store.updateCookie) {
        store.updateCookie = function(oldCookie, newCookie, cb) {
          this.putCookie(newCookie, cb);
        };
      }
    
      function withCookie(err, oldCookie) {
        if (err) {
          return cb(err);
        }
    
        var next = function(err) {
          if (err) {
            return cb(err);
          } else {
            cb(null, cookie);
          }
        };
    
        if (oldCookie) {
          // S5.3 step 11 - "If the cookie store contains a cookie with the same name,
          // domain, and path as the newly created cookie:"
          if (options.http === false && oldCookie.httpOnly) { // step 11.2
            err = new Error("old Cookie is HttpOnly and this isn't an HTTP API");
            return cb(options.ignoreError ? null : err);
          }
          cookie.creation = oldCookie.creation; // step 11.3
          cookie.lastAccessed = now;
          // Step 11.4 (delete cookie) is implied by just setting the new one:
          store.updateCookie(oldCookie, cookie, next); // step 12
    
        } else {
          cookie.creation = cookie.lastAccessed = now;
          store.putCookie(cookie, next); // step 12
        }
      }
    
      store.findCookie(cookie.domain, cookie.path, cookie.key, withCookie);
    };
    
    // RFC6365 S5.4
    CAN_BE_SYNC.push('getCookies');
    CookieJar.prototype.getCookies = function(url, options, cb) {
      var context = (url instanceof Object) ? url : urlParse(url);
      if (options instanceof Function) {
        cb = options;
        options = {};
      }
    
      var host = canonicalDomain(context.hostname);
      var path = context.pathname || '/';
    
      var secure = options.secure;
      if (secure == null && context.protocol &&
          (context.protocol == 'https:' || context.protocol == 'wss:'))
      {
        secure = true;
      }
    
      var http = options.http;
      if (http == null) {
        http = true;
      }
    
      var now = options.now || Date.now();
      var expireCheck = options.expire !== false;
      var allPaths = !!options.allPaths;
      var store = this.store;
    
      function matchingCookie(c) {
        // "Either:
        //   The cookie's host-only-flag is true and the canonicalized
        //   request-host is identical to the cookie's domain.
        // Or:
        //   The cookie's host-only-flag is false and the canonicalized
        //   request-host domain-matches the cookie's domain."
        if (c.hostOnly) {
          if (c.domain != host) {
            return false;
          }
        } else {
          if (!domainMatch(host, c.domain, false)) {
            return false;
          }
        }
    
        // "The request-uri's path path-matches the cookie's path."
        if (!allPaths && !pathMatch(path, c.path)) {
          return false;
        }
    
        // "If the cookie's secure-only-flag is true, then the request-uri's
        // scheme must denote a "secure" protocol"
        if (c.secure && !secure) {
          return false;
        }
    
        // "If the cookie's http-only-flag is true, then exclude the cookie if the
        // cookie-string is being generated for a "non-HTTP" API"
        if (c.httpOnly && !http) {
          return false;
        }
    
        // deferred from S5.3
        // non-RFC: allow retention of expired cookies by choice
        if (expireCheck && c.expiryTime() <= now) {
          store.removeCookie(c.domain, c.path, c.key, function(){}); // result ignored
          return false;
        }
    
        return true;
      }
    
      store.findCookies(host, allPaths ? null : path, function(err,cookies) {
        if (err) {
          return cb(err);
        }
    
        cookies = cookies.filter(matchingCookie);
    
        // sorting of S5.4 part 2
        if (options.sort !== false) {
          cookies = cookies.sort(cookieCompare);
        }
    
        // S5.4 part 3
        var now = new Date();
        cookies.forEach(function(c) {
          c.lastAccessed = now;
        });
        // TODO persist lastAccessed
    
        cb(null,cookies);
      });
    };
    
    CAN_BE_SYNC.push('getCookieString');
    CookieJar.prototype.getCookieString = function(/*..., cb*/) {
      var args = Array.prototype.slice.call(arguments,0);
      var cb = args.pop();
      var next = function(err,cookies) {
        if (err) {
          cb(err);
        } else {
          cb(null, cookies.map(function(c){
            return c.cookieString();
          }).join('; '));
        }
      };
      args.push(next);
      this.getCookies.apply(this,args);
    };
    
    CAN_BE_SYNC.push('getSetCookieStrings');
    CookieJar.prototype.getSetCookieStrings = function(/*..., cb*/) {
      var args = Array.prototype.slice.call(arguments,0);
      var cb = args.pop();
      var next = function(err,cookies) {
        if (err) {
          cb(err);
        } else {
          cb(null, cookies.map(function(c){
            return c.toString();
          }));
        }
      };
      args.push(next);
      this.getCookies.apply(this,args);
    };
    
    // Use a closure to provide a true imperative API for synchronous stores.
    function syncWrap(method) {
      return function() {
        if (!this.store.synchronous) {
          throw new Error('CookieJar store is not synchronous; use async API instead.');
        }
    
        var args = Array.prototype.slice.call(arguments);
        var syncErr, syncResult;
        args.push(function syncCb(err, result) {
          syncErr = err;
          syncResult = result;
        });
        this[method].apply(this, args);
    
        if (syncErr) {
          throw syncErr;
        }
        return syncResult;
      };
    }
    
    // wrap all declared CAN_BE_SYNC methods in the sync wrapper
    CAN_BE_SYNC.forEach(function(method) {
      CookieJar.prototype[method+'Sync'] = syncWrap(method);
    });
    
    module.exports = {
      CookieJar: CookieJar,
      Cookie: Cookie,
      Store: Store,
      parseDate: parseDate,
      formatDate: formatDate,
      parse: parse,
      fromJSON: fromJSON,
      domainMatch: domainMatch,
      defaultPath: defaultPath,
      pathMatch: pathMatch,
      getPublicSuffix: pubsuffix.getPublicSuffix,
      cookieCompare: cookieCompare,
      permuteDomain: permuteDomain,
      permutePath: permutePath,
      canonicalDomain: canonicalDomain,
    };
    
  provide("tough-cookie/lib/cookie", module.exports);
}(global));

// pakmanager:tough-cookie/lib/memstore
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  'use strict';
    var tough =  require('tough-cookie/lib/cookie');
    var Store =  require('tough-cookie/lib/store').Store;
    var permuteDomain = tough.permuteDomain;
    var permutePath = tough.permutePath;
    var util = require('util');
    
    function MemoryCookieStore() {
      Store.call(this);
      this.idx = {};
    }
    util.inherits(MemoryCookieStore, Store);
    exports.MemoryCookieStore = MemoryCookieStore;
    MemoryCookieStore.prototype.idx = null;
    MemoryCookieStore.prototype.synchronous = true;
    
    // force a default depth:
    MemoryCookieStore.prototype.inspect = function() {
      return "{ idx: "+util.inspect(this.idx, false, 2)+' }';
    };
    
    MemoryCookieStore.prototype.findCookie = function(domain, path, key, cb) {
      if (!this.idx[domain]) {
        return cb(null,undefined);
      }
      if (!this.idx[domain][path]) {
        return cb(null,undefined);
      }
      return cb(null,this.idx[domain][path][key]||null);
    };
    
    MemoryCookieStore.prototype.findCookies = function(domain, path, cb) {
      var results = [];
      if (!domain) {
        return cb(null,[]);
      }
    
      var pathMatcher;
      if (!path) {
        // null or '/' means "all paths"
        pathMatcher = function matchAll(domainIndex) {
          for (var curPath in domainIndex) {
            var pathIndex = domainIndex[curPath];
            for (var key in pathIndex) {
              results.push(pathIndex[key]);
            }
          }
        };
    
      } else if (path === '/') {
        pathMatcher = function matchSlash(domainIndex) {
          var pathIndex = domainIndex['/'];
          if (!pathIndex) {
            return;
          }
          for (var key in pathIndex) {
            results.push(pathIndex[key]);
          }
        };
    
      } else {
        var paths = permutePath(path) || [path];
        pathMatcher = function matchRFC(domainIndex) {
          paths.forEach(function(curPath) {
            var pathIndex = domainIndex[curPath];
            if (!pathIndex) {
              return;
            }
            for (var key in pathIndex) {
              results.push(pathIndex[key]);
            }
          });
        };
      }
    
      var domains = permuteDomain(domain) || [domain];
      var idx = this.idx;
      domains.forEach(function(curDomain) {
        var domainIndex = idx[curDomain];
        if (!domainIndex) {
          return;
        }
        pathMatcher(domainIndex);
      });
    
      cb(null,results);
    };
    
    MemoryCookieStore.prototype.putCookie = function(cookie, cb) {
      if (!this.idx[cookie.domain]) {
        this.idx[cookie.domain] = {};
      }
      if (!this.idx[cookie.domain][cookie.path]) {
        this.idx[cookie.domain][cookie.path] = {};
      }
      this.idx[cookie.domain][cookie.path][cookie.key] = cookie;
      cb(null);
    };
    
    MemoryCookieStore.prototype.updateCookie = function updateCookie(oldCookie, newCookie, cb) {
      // updateCookie() may avoid updating cookies that are identical.  For example,
      // lastAccessed may not be important to some stores and an equality
      // comparison could exclude that field.
      this.putCookie(newCookie,cb);
    };
    
    MemoryCookieStore.prototype.removeCookie = function removeCookie(domain, path, key, cb) {
      if (this.idx[domain] && this.idx[domain][path] && this.idx[domain][path][key]) {
        delete this.idx[domain][path][key];
      }
      cb(null);
    };
    
    MemoryCookieStore.prototype.removeCookies = function removeCookies(domain, path, cb) {
      if (this.idx[domain]) {
        if (path) {
          delete this.idx[domain][path];
        } else {
          delete this.idx[domain];
        }
      }
      return cb(null);
    };
    
  provide("tough-cookie/lib/memstore", module.exports);
}(global));

// pakmanager:tough-cookie
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  /*
     * Copyright GoInstant, Inc. and other contributors. All rights reserved.
     * Permission is hereby granted, free of charge, to any person obtaining a copy
     * of this software and associated documentation files (the "Software"), to
     * deal in the Software without restriction, including without limitation the
     * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
     * sell copies of the Software, and to permit persons to whom the Software is
     * furnished to do so, subject to the following conditions:
     *
     * The above copyright notice and this permission notice shall be included in
     * all copies or substantial portions of the Software.
     *
     * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
     * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
     * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
     * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
     * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
     * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
     * IN THE SOFTWARE.
     */
    
    'use strict';
    var net = require('net');
    var urlParse = require('url').parse;
    var pubsuffix =  require('tough-cookie/lib/pubsuffix');
    var Store =  require('tough-cookie/lib/store').Store;
    
    var punycode;
    try {
      punycode = require('punycode');
    } catch(e) {
      console.warn("cookie: can't load punycode; won't use punycode for domain normalization");
    }
    
    var DATE_DELIM = /[\x09\x20-\x2F\x3B-\x40\x5B-\x60\x7B-\x7E]/;
    
    // From RFC2616 S2.2:
    var TOKEN = /[\x21\x23-\x26\x2A\x2B\x2D\x2E\x30-\x39\x41-\x5A\x5E-\x7A\x7C\x7E]/;
    
    // From RFC6265 S4.1.1
    // note that it excludes \x3B ";"
    var COOKIE_OCTET  = /[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]/;
    var COOKIE_OCTETS = new RegExp('^'+COOKIE_OCTET.source+'$');
    
    // The name/key cannot be empty but the value can (S5.2):
    var COOKIE_PAIR_STRICT = new RegExp('^('+TOKEN.source+'+)=("?)('+COOKIE_OCTET.source+'*)\\2$');
    var COOKIE_PAIR = /^([^=\s]+)\s*=\s*("?)\s*(.*)\s*\2\s*$/;
    
    // RFC6265 S4.1.1 defines extension-av as 'any CHAR except CTLs or ";"'
    // Note ';' is \x3B
    var NON_CTL_SEMICOLON = /[\x20-\x3A\x3C-\x7E]+/;
    var EXTENSION_AV = NON_CTL_SEMICOLON;
    var PATH_VALUE = NON_CTL_SEMICOLON;
    
    // Used for checking whether or not there is a trailing semi-colon
    var TRAILING_SEMICOLON = /;+$/;
    
    /* RFC6265 S5.1.1.5:
     * [fail if] the day-of-month-value is less than 1 or greater than 31
     */
    var DAY_OF_MONTH = /^(0?[1-9]|[12][0-9]|3[01])$/;
    
    /* RFC6265 S5.1.1.5:
     * [fail if]
     * *  the hour-value is greater than 23,
     * *  the minute-value is greater than 59, or
     * *  the second-value is greater than 59.
     */
    var TIME = /(0?[0-9]|1[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])/;
    var STRICT_TIME = /^(0?[0-9]|1[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/;
    
    var MONTH = /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$/i;
    var MONTH_TO_NUM = {
      jan:0, feb:1, mar:2, apr:3, may:4, jun:5,
      jul:6, aug:7, sep:8, oct:9, nov:10, dec:11
    };
    var NUM_TO_MONTH = [
      'Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'
    ];
    var NUM_TO_DAY = [
      'Sun','Mon','Tue','Wed','Thu','Fri','Sat'
    ];
    
    var YEAR = /^([1-9][0-9]{1,3})$/; // 2 to 4 digits
    
    var MAX_TIME = 2147483647000; // 31-bit max
    var MIN_TIME = 0; // 31-bit min
    
    
    // RFC6265 S5.1.1 date parser:
    function parseDate(str,strict) {
      if (!str) {
        return;
      }
      var found_time, found_dom, found_month, found_year;
    
      /* RFC6265 S5.1.1:
       * 2. Process each date-token sequentially in the order the date-tokens
       * appear in the cookie-date
       */
      var tokens = str.split(DATE_DELIM);
      if (!tokens) {
        return;
      }
    
      var date = new Date();
      date.setMilliseconds(0);
    
      for (var i=0; i<tokens.length; i++) {
        var token = tokens[i].trim();
        if (!token.length) {
          continue;
        }
    
        var result;
    
        /* 2.1. If the found-time flag is not set and the token matches the time
         * production, set the found-time flag and set the hour- value,
         * minute-value, and second-value to the numbers denoted by the digits in
         * the date-token, respectively.  Skip the remaining sub-steps and continue
         * to the next date-token.
         */
        if (!found_time) {
          result = (strict ? STRICT_TIME : TIME).exec(token);
          if (result) {
            found_time = true;
            date.setUTCHours(result[1]);
            date.setUTCMinutes(result[2]);
            date.setUTCSeconds(result[3]);
            continue;
          }
        }
    
        /* 2.2. If the found-day-of-month flag is not set and the date-token matches
         * the day-of-month production, set the found-day-of- month flag and set
         * the day-of-month-value to the number denoted by the date-token.  Skip
         * the remaining sub-steps and continue to the next date-token.
         */
        if (!found_dom) {
          result = DAY_OF_MONTH.exec(token);
          if (result) {
            found_dom = true;
            date.setUTCDate(result[1]);
            continue;
          }
        }
    
        /* 2.3. If the found-month flag is not set and the date-token matches the
         * month production, set the found-month flag and set the month-value to
         * the month denoted by the date-token.  Skip the remaining sub-steps and
         * continue to the next date-token.
         */
        if (!found_month) {
          result = MONTH.exec(token);
          if (result) {
            found_month = true;
            date.setUTCMonth(MONTH_TO_NUM[result[1].toLowerCase()]);
            continue;
          }
        }
    
        /* 2.4. If the found-year flag is not set and the date-token matches the year
         * production, set the found-year flag and set the year-value to the number
         * denoted by the date-token.  Skip the remaining sub-steps and continue to
         * the next date-token.
         */
        if (!found_year) {
          result = YEAR.exec(token);
          if (result) {
            var year = result[0];
            /* From S5.1.1:
             * 3.  If the year-value is greater than or equal to 70 and less
             * than or equal to 99, increment the year-value by 1900.
             * 4.  If the year-value is greater than or equal to 0 and less
             * than or equal to 69, increment the year-value by 2000.
             */
            if (70 <= year && year <= 99) {
              year += 1900;
            } else if (0 <= year && year <= 69) {
              year += 2000;
            }
    
            if (year < 1601) {
              return; // 5. ... the year-value is less than 1601
            }
    
            found_year = true;
            date.setUTCFullYear(year);
            continue;
          }
        }
      }
    
      if (!(found_time && found_dom && found_month && found_year)) {
        return; // 5. ... at least one of the found-day-of-month, found-month, found-
                // year, or found-time flags is not set,
      }
    
      return date;
    }
    
    function formatDate(date) {
      var d = date.getUTCDate(); d = d >= 10 ? d : '0'+d;
      var h = date.getUTCHours(); h = h >= 10 ? h : '0'+h;
      var m = date.getUTCMinutes(); m = m >= 10 ? m : '0'+m;
      var s = date.getUTCSeconds(); s = s >= 10 ? s : '0'+s;
      return NUM_TO_DAY[date.getUTCDay()] + ', ' +
        d+' '+ NUM_TO_MONTH[date.getUTCMonth()] +' '+ date.getUTCFullYear() +' '+
        h+':'+m+':'+s+' GMT';
    }
    
    // S5.1.2 Canonicalized Host Names
    function canonicalDomain(str) {
      if (str == null) {
        return null;
      }
      str = str.trim().replace(/^\./,''); // S4.1.2.3 & S5.2.3: ignore leading .
    
      // convert to IDN if any non-ASCII characters
      if (punycode && /[^\u0001-\u007f]/.test(str)) {
        str = punycode.toASCII(str);
      }
    
      return str.toLowerCase();
    }
    
    // S5.1.3 Domain Matching
    function domainMatch(str, domStr, canonicalize) {
      if (str == null || domStr == null) {
        return null;
      }
      if (canonicalize !== false) {
        str = canonicalDomain(str);
        domStr = canonicalDomain(domStr);
      }
    
      /*
       * "The domain string and the string are identical. (Note that both the
       * domain string and the string will have been canonicalized to lower case at
       * this point)"
       */
      if (str == domStr) {
        return true;
      }
    
      /* "All of the following [three] conditions hold:" (order adjusted from the RFC) */
    
      /* "* The string is a host name (i.e., not an IP address)." */
      if (net.isIP(str)) {
        return false;
      }
    
      /* "* The domain string is a suffix of the string" */
      var idx = str.indexOf(domStr);
      if (idx <= 0) {
        return false; // it's a non-match (-1) or prefix (0)
      }
    
      // e.g "a.b.c".indexOf("b.c") === 2
      // 5 === 3+2
      if (str.length !== domStr.length + idx) { // it's not a suffix
        return false;
      }
    
      /* "* The last character of the string that is not included in the domain
      * string is a %x2E (".") character." */
      if (str.substr(idx-1,1) !== '.') {
        return false;
      }
    
      return true;
    }
    
    
    // RFC6265 S5.1.4 Paths and Path-Match
    
    /*
     * "The user agent MUST use an algorithm equivalent to the following algorithm
     * to compute the default-path of a cookie:"
     *
     * Assumption: the path (and not query part or absolute uri) is passed in.
     */
    function defaultPath(path) {
      // "2. If the uri-path is empty or if the first character of the uri-path is not
      // a %x2F ("/") character, output %x2F ("/") and skip the remaining steps.
      if (!path || path.substr(0,1) !== "/") {
        return "/";
      }
    
      // "3. If the uri-path contains no more than one %x2F ("/") character, output
      // %x2F ("/") and skip the remaining step."
      if (path === "/") {
        return path;
      }
    
      var rightSlash = path.lastIndexOf("/");
      if (rightSlash === 0) {
        return "/";
      }
    
      // "4. Output the characters of the uri-path from the first character up to,
      // but not including, the right-most %x2F ("/")."
      return path.slice(0, rightSlash);
    }
    
    /*
     * "A request-path path-matches a given cookie-path if at least one of the
     * following conditions holds:"
     */
    function pathMatch(reqPath,cookiePath) {
      // "o  The cookie-path and the request-path are identical."
      if (cookiePath === reqPath) {
        return true;
      }
    
      var idx = reqPath.indexOf(cookiePath);
      if (idx === 0) {
        // "o  The cookie-path is a prefix of the request-path, and the last
        // character of the cookie-path is %x2F ("/")."
        if (cookiePath.substr(-1) === "/") {
          return true;
        }
    
        // " o  The cookie-path is a prefix of the request-path, and the first
        // character of the request-path that is not included in the cookie- path
        // is a %x2F ("/") character."
        if (reqPath.substr(cookiePath.length,1) === "/") {
          return true;
        }
      }
    
      return false;
    }
    
    function parse(str, strict) {
      str = str.trim();
    
      // S4.1.1 Trailing semi-colons are not part of the specification.
      // If we are not in strict mode we remove the trailing semi-colons.
      var semiColonCheck = TRAILING_SEMICOLON.exec(str);
      if (semiColonCheck) {
        if (strict) {
          return;
        }
        str = str.slice(0, semiColonCheck.index);
      }
    
      // We use a regex to parse the "name-value-pair" part of S5.2
      var firstSemi = str.indexOf(';'); // S5.2 step 1
      var pairRx = strict ? COOKIE_PAIR_STRICT : COOKIE_PAIR;
      var result = pairRx.exec(firstSemi === -1 ? str : str.substr(0,firstSemi));
    
      // Rx satisfies the "the name string is empty" and "lacks a %x3D ("=")"
      // constraints as well as trimming any whitespace.
      if (!result) {
        return;
      }
    
      var c = new Cookie();
      c.key = result[1]; // the regexp should trim() already
      c.value = result[3]; // [2] is quotes or empty-string
    
      if (firstSemi === -1) {
        return c;
      }
    
      // S5.2.3 "unparsed-attributes consist of the remainder of the set-cookie-string
      // (including the %x3B (";") in question)." plus later on in the same section
      // "discard the first ";" and trim".
      var unparsed = str.slice(firstSemi).replace(/^\s*;\s*/,'').trim();
    
      // "If the unparsed-attributes string is empty, skip the rest of these
      // steps."
      if (unparsed.length === 0) {
        return c;
      }
    
      /*
       * S5.2 says that when looping over the items "[p]rocess the attribute-name
       * and attribute-value according to the requirements in the following
       * subsections" for every item.  Plus, for many of the individual attributes
       * in S5.3 it says to use the "attribute-value of the last attribute in the
       * cookie-attribute-list".  Therefore, in this implementation, we overwrite
       * the previous value.
       */
      var cookie_avs = unparsed.split(/\s*;\s*/);
      while (cookie_avs.length) {
        var av = cookie_avs.shift();
    
        if (strict && !EXTENSION_AV.test(av)) {
          return;
        }
    
        var av_sep = av.indexOf('=');
        var av_key, av_value;
        if (av_sep === -1) {
          av_key = av;
          av_value = null;
        } else {
          av_key = av.substr(0,av_sep);
          av_value = av.substr(av_sep+1);
        }
    
        av_key = av_key.trim().toLowerCase();
        if (av_value) {
          av_value = av_value.trim();
        }
    
        switch(av_key) {
        case 'expires': // S5.2.1
          if (!av_value) {if(strict){return;}else{break;} }
          var exp = parseDate(av_value,strict);
          // "If the attribute-value failed to parse as a cookie date, ignore the
          // cookie-av."
          if (exp == null) { if(strict){return;}else{break;} }
          c.expires = exp;
          // over and underflow not realistically a concern: V8's getTime() seems to
          // store something larger than a 32-bit time_t (even with 32-bit node)
          break;
    
        case 'max-age': // S5.2.2
          if (!av_value) { if(strict){return;}else{break;} }
          // "If the first character of the attribute-value is not a DIGIT or a "-"
          // character ...[or]... If the remainder of attribute-value contains a
          // non-DIGIT character, ignore the cookie-av."
          if (!/^-?[0-9]+$/.test(av_value)) { if(strict){return;}else{break;} }
          var delta = parseInt(av_value,10);
          if (strict && delta <= 0) {
            return; // S4.1.1
          }
          // "If delta-seconds is less than or equal to zero (0), let expiry-time
          // be the earliest representable date and time."
          c.setMaxAge(delta);
          break;
    
        case 'domain': // S5.2.3
          // "If the attribute-value is empty, the behavior is undefined.  However,
          // the user agent SHOULD ignore the cookie-av entirely."
          if (!av_value) { if(strict){return;}else{break;} }
          // S5.2.3 "Let cookie-domain be the attribute-value without the leading %x2E
          // (".") character."
          var domain = av_value.trim().replace(/^\./,'');
          if (!domain) { if(strict){return;}else{break;} } // see "is empty" above
          // "Convert the cookie-domain to lower case."
          c.domain = domain.toLowerCase();
          break;
    
        case 'path': // S5.2.4
          /*
           * "If the attribute-value is empty or if the first character of the
           * attribute-value is not %x2F ("/"):
           *   Let cookie-path be the default-path.
           * Otherwise:
           *   Let cookie-path be the attribute-value."
           *
           * We'll represent the default-path as null since it depends on the
           * context of the parsing.
           */
          if (!av_value || av_value.substr(0,1) != "/") {
            if(strict){return;}else{break;}
          }
          c.path = av_value;
          break;
    
        case 'secure': // S5.2.5
          /*
           * "If the attribute-name case-insensitively matches the string "Secure",
           * the user agent MUST append an attribute to the cookie-attribute-list
           * with an attribute-name of Secure and an empty attribute-value."
           */
          if (av_value != null) { if(strict){return;} }
          c.secure = true;
          break;
    
        case 'httponly': // S5.2.6 -- effectively the same as 'secure'
          if (av_value != null) { if(strict){return;} }
          c.httpOnly = true;
          break;
    
        default:
          c.extensions = c.extensions || [];
          c.extensions.push(av);
          break;
        }
      }
    
      // ensure a default date for sorting:
      c.creation = new Date();
      return c;
    }
    
    function fromJSON(str) {
      if (!str) {
        return null;
      }
    
      var obj;
      try {
        obj = JSON.parse(str);
      } catch (e) {
        return null;
      }
    
      var c = new Cookie();
      for (var i=0; i<numCookieProperties; i++) {
        var prop = cookieProperties[i];
        if (obj[prop] == null) {
          continue;
        }
        if (prop === 'expires' ||
            prop === 'creation' ||
            prop === 'lastAccessed')
        {
          c[prop] = obj[prop] == "Infinity" ? "Infinity" : new Date(obj[prop]);
        } else {
          c[prop] = obj[prop];
        }
      }
    
    
      // ensure a default date for sorting:
      c.creation = c.creation || new Date();
    
      return c;
    }
    
    /* Section 5.4 part 2:
     * "*  Cookies with longer paths are listed before cookies with
     *     shorter paths.
     *
     *  *  Among cookies that have equal-length path fields, cookies with
     *     earlier creation-times are listed before cookies with later
     *     creation-times."
     */
    
    function cookieCompare(a,b) {
      // descending for length: b CMP a
      var deltaLen = (b.path ? b.path.length : 0) - (a.path ? a.path.length : 0);
      if (deltaLen !== 0) {
        return deltaLen;
      }
      // ascending for time: a CMP b
      return (a.creation ? a.creation.getTime() : MAX_TIME) -
             (b.creation ? b.creation.getTime() : MAX_TIME);
    }
    
    // Gives the permutation of all possible domainMatch()es of a given domain. The
    // array is in shortest-to-longest order.  Handy for indexing.
    function permuteDomain(domain) {
      var pubSuf = pubsuffix.getPublicSuffix(domain);
      if (!pubSuf) {
        return null;
      }
      if (pubSuf == domain) {
        return [domain];
      }
    
      var prefix = domain.slice(0,-(pubSuf.length+1)); // ".example.com"
      var parts = prefix.split('.').reverse();
      var cur = pubSuf;
      var permutations = [cur];
      while (parts.length) {
        cur = parts.shift()+'.'+cur;
        permutations.push(cur);
      }
      return permutations;
    }
    
    // Gives the permutation of all possible pathMatch()es of a given path. The
    // array is in longest-to-shortest order.  Handy for indexing.
    function permutePath(path) {
      if (path === '/') {
        return ['/'];
      }
      if (path.lastIndexOf('/') === path.length-1) {
        path = path.substr(0,path.length-1);
      }
      var permutations = [path];
      while (path.length > 1) {
        var lindex = path.lastIndexOf('/');
        if (lindex === 0) {
          break;
        }
        path = path.substr(0,lindex);
        permutations.push(path);
      }
      permutations.push('/');
      return permutations;
    }
    
    
    function Cookie (opts) {
      if (typeof opts !== "object") {
        return;
      }
      Object.keys(opts).forEach(function (key) {
        if (Cookie.prototype.hasOwnProperty(key)) {
          this[key] = opts[key] || Cookie.prototype[key];
        }
      }.bind(this));
    }
    
    Cookie.parse = parse;
    Cookie.fromJSON = fromJSON;
    
    Cookie.prototype.key = "";
    Cookie.prototype.value = "";
    
    // the order in which the RFC has them:
    Cookie.prototype.expires = "Infinity"; // coerces to literal Infinity
    Cookie.prototype.maxAge = null; // takes precedence over expires for TTL
    Cookie.prototype.domain = null;
    Cookie.prototype.path = null;
    Cookie.prototype.secure = false;
    Cookie.prototype.httpOnly = false;
    Cookie.prototype.extensions = null;
    
    // set by the CookieJar:
    Cookie.prototype.hostOnly = null; // boolean when set
    Cookie.prototype.pathIsDefault = null; // boolean when set
    Cookie.prototype.creation = null; // Date when set; defaulted by Cookie.parse
    Cookie.prototype.lastAccessed = null; // Date when set
    
    var cookieProperties = Object.freeze(Object.keys(Cookie.prototype).map(function(p) {
      if (p instanceof Function) {
        return;
      }
      return p;
    }));
    var numCookieProperties = cookieProperties.length;
    
    Cookie.prototype.inspect = function inspect() {
      var now = Date.now();
      return 'Cookie="'+this.toString() +
        '; hostOnly='+(this.hostOnly != null ? this.hostOnly : '?') +
        '; aAge='+(this.lastAccessed ? (now-this.lastAccessed.getTime())+'ms' : '?') +
        '; cAge='+(this.creation ? (now-this.creation.getTime())+'ms' : '?') +
        '"';
    };
    
    Cookie.prototype.validate = function validate() {
      if (!COOKIE_OCTETS.test(this.value)) {
        return false;
      }
      if (this.expires != Infinity && !(this.expires instanceof Date) && !parseDate(this.expires,true)) {
        return false;
      }
      if (this.maxAge != null && this.maxAge <= 0) {
        return false; // "Max-Age=" non-zero-digit *DIGIT
      }
      if (this.path != null && !PATH_VALUE.test(this.path)) {
        return false;
      }
    
      var cdomain = this.cdomain();
      if (cdomain) {
        if (cdomain.match(/\.$/)) {
          return false; // S4.1.2.3 suggests that this is bad. domainMatch() tests confirm this
        }
        var suffix = pubsuffix.getPublicSuffix(cdomain);
        if (suffix == null) { // it's a public suffix
          return false;
        }
      }
      return true;
    };
    
    Cookie.prototype.setExpires = function setExpires(exp) {
      if (exp instanceof Date) {
        this.expires = exp;
      } else {
        this.expires = parseDate(exp) || "Infinity";
      }
    };
    
    Cookie.prototype.setMaxAge = function setMaxAge(age) {
      if (age === Infinity || age === -Infinity) {
        this.maxAge = age.toString(); // so JSON.stringify() works
      } else {
        this.maxAge = age;
      }
    };
    
    // gives Cookie header format
    Cookie.prototype.cookieString = function cookieString() {
      var val = this.value;
      if (val == null) {
        val = '';
      }
      return this.key+'='+val;
    };
    
    // gives Set-Cookie header format
    Cookie.prototype.toString = function toString() {
      var str = this.cookieString();
    
      if (this.expires != Infinity) {
        if (this.expires instanceof Date) {
          str += '; Expires='+formatDate(this.expires);
        } else {
          str += '; Expires='+this.expires;
        }
      }
    
      if (this.maxAge != null && this.maxAge != Infinity) {
        str += '; Max-Age='+this.maxAge;
      }
    
      if (this.domain && !this.hostOnly) {
        str += '; Domain='+this.domain;
      }
      if (this.path) {
        str += '; Path='+this.path;
      }
    
      if (this.secure) {
        str += '; Secure';
      }
      if (this.httpOnly) {
        str += '; HttpOnly';
      }
      if (this.extensions) {
        this.extensions.forEach(function(ext) {
          str += '; '+ext;
        });
      }
    
      return str;
    };
    
    // TTL() partially replaces the "expiry-time" parts of S5.3 step 3 (setCookie()
    // elsewhere)
    // S5.3 says to give the "latest representable date" for which we use Infinity
    // For "expired" we use 0
    Cookie.prototype.TTL = function TTL(now) {
      /* RFC6265 S4.1.2.2 If a cookie has both the Max-Age and the Expires
       * attribute, the Max-Age attribute has precedence and controls the
       * expiration date of the cookie.
       * (Concurs with S5.3 step 3)
       */
      if (this.maxAge != null) {
        return this.maxAge<=0 ? 0 : this.maxAge*1000;
      }
    
      var expires = this.expires;
      if (expires != Infinity) {
        if (!(expires instanceof Date)) {
          expires = parseDate(expires) || Infinity;
        }
    
        if (expires == Infinity) {
          return Infinity;
        }
    
        return expires.getTime() - (now || Date.now());
      }
    
      return Infinity;
    };
    
    // expiryTime() replaces the "expiry-time" parts of S5.3 step 3 (setCookie()
    // elsewhere)
    Cookie.prototype.expiryTime = function expiryTime(now) {
      if (this.maxAge != null) {
        var relativeTo = this.creation || now || new Date();
        var age = (this.maxAge <= 0) ? -Infinity : this.maxAge*1000;
        return relativeTo.getTime() + age;
      }
    
      if (this.expires == Infinity) {
        return Infinity;
      }
      return this.expires.getTime();
    };
    
    // expiryDate() replaces the "expiry-time" parts of S5.3 step 3 (setCookie()
    // elsewhere), except it returns a Date
    Cookie.prototype.expiryDate = function expiryDate(now) {
      var millisec = this.expiryTime(now);
      if (millisec == Infinity) {
        return new Date(MAX_TIME);
      } else if (millisec == -Infinity) {
        return new Date(MIN_TIME);
      } else {
        return new Date(millisec);
      }
    };
    
    // This replaces the "persistent-flag" parts of S5.3 step 3
    Cookie.prototype.isPersistent = function isPersistent() {
      return (this.maxAge != null || this.expires != Infinity);
    };
    
    // Mostly S5.1.2 and S5.2.3:
    Cookie.prototype.cdomain =
    Cookie.prototype.canonicalizedDomain = function canonicalizedDomain() {
      if (this.domain == null) {
        return null;
      }
      return canonicalDomain(this.domain);
    };
    
    
    var memstore;
    function CookieJar(store, rejectPublicSuffixes) {
      if (rejectPublicSuffixes != null) {
        this.rejectPublicSuffixes = rejectPublicSuffixes;
      }
    
      if (!store) {
        memstore = memstore ||  require('tough-cookie/lib/memstore');
        store = new memstore.MemoryCookieStore();
      }
      this.store = store;
    }
    CookieJar.prototype.store = null;
    CookieJar.prototype.rejectPublicSuffixes = true;
    var CAN_BE_SYNC = [];
    
    CAN_BE_SYNC.push('setCookie');
    CookieJar.prototype.setCookie = function(cookie, url, options, cb) {
      var err;
      var context = (url instanceof Object) ? url : urlParse(url);
      if (options instanceof Function) {
        cb = options;
        options = {};
      }
    
      var host = canonicalDomain(context.hostname);
    
      // S5.3 step 1
      if (!(cookie instanceof Cookie)) {
        cookie = Cookie.parse(cookie, options.strict === true);
      }
      if (!cookie) {
        err = new Error("Cookie failed to parse");
        return cb(options.ignoreError ? null : err);
      }
    
      // S5.3 step 2
      var now = options.now || new Date(); // will assign later to save effort in the face of errors
    
      // S5.3 step 3: NOOP; persistent-flag and expiry-time is handled by getCookie()
    
      // S5.3 step 4: NOOP; domain is null by default
    
      // S5.3 step 5: public suffixes
      if (this.rejectPublicSuffixes && cookie.domain) {
        var suffix = pubsuffix.getPublicSuffix(cookie.cdomain());
        if (suffix == null) { // e.g. "com"
          err = new Error("Cookie has domain set to a public suffix");
          return cb(options.ignoreError ? null : err);
        }
      }
    
      // S5.3 step 6:
      if (cookie.domain) {
        if (!domainMatch(host, cookie.cdomain(), false)) {
          err = new Error("Cookie not in this host's domain. Cookie:"+cookie.cdomain()+" Request:"+host);
          return cb(options.ignoreError ? null : err);
        }
    
        if (cookie.hostOnly == null) { // don't reset if already set
          cookie.hostOnly = false;
        }
    
      } else {
        cookie.hostOnly = true;
        cookie.domain = host;
      }
    
      // S5.3 step 7: "Otherwise, set the cookie's path to the default-path of the
      // request-uri"
      if (!cookie.path) {
        cookie.path = defaultPath(context.pathname);
        cookie.pathIsDefault = true;
      } else {
        if (cookie.path.length > 1 && cookie.path.substr(-1) == '/') {
          cookie.path = cookie.path.slice(0,-1);
        }
      }
    
      // S5.3 step 8: NOOP; secure attribute
      // S5.3 step 9: NOOP; httpOnly attribute
    
      // S5.3 step 10
      if (options.http === false && cookie.httpOnly) {
        err = new Error("Cookie is HttpOnly and this isn't an HTTP API");
        return cb(options.ignoreError ? null : err);
      }
    
      var store = this.store;
    
      if (!store.updateCookie) {
        store.updateCookie = function(oldCookie, newCookie, cb) {
          this.putCookie(newCookie, cb);
        };
      }
    
      function withCookie(err, oldCookie) {
        if (err) {
          return cb(err);
        }
    
        var next = function(err) {
          if (err) {
            return cb(err);
          } else {
            cb(null, cookie);
          }
        };
    
        if (oldCookie) {
          // S5.3 step 11 - "If the cookie store contains a cookie with the same name,
          // domain, and path as the newly created cookie:"
          if (options.http === false && oldCookie.httpOnly) { // step 11.2
            err = new Error("old Cookie is HttpOnly and this isn't an HTTP API");
            return cb(options.ignoreError ? null : err);
          }
          cookie.creation = oldCookie.creation; // step 11.3
          cookie.lastAccessed = now;
          // Step 11.4 (delete cookie) is implied by just setting the new one:
          store.updateCookie(oldCookie, cookie, next); // step 12
    
        } else {
          cookie.creation = cookie.lastAccessed = now;
          store.putCookie(cookie, next); // step 12
        }
      }
    
      store.findCookie(cookie.domain, cookie.path, cookie.key, withCookie);
    };
    
    // RFC6365 S5.4
    CAN_BE_SYNC.push('getCookies');
    CookieJar.prototype.getCookies = function(url, options, cb) {
      var context = (url instanceof Object) ? url : urlParse(url);
      if (options instanceof Function) {
        cb = options;
        options = {};
      }
    
      var host = canonicalDomain(context.hostname);
      var path = context.pathname || '/';
    
      var secure = options.secure;
      if (secure == null && context.protocol &&
          (context.protocol == 'https:' || context.protocol == 'wss:'))
      {
        secure = true;
      }
    
      var http = options.http;
      if (http == null) {
        http = true;
      }
    
      var now = options.now || Date.now();
      var expireCheck = options.expire !== false;
      var allPaths = !!options.allPaths;
      var store = this.store;
    
      function matchingCookie(c) {
        // "Either:
        //   The cookie's host-only-flag is true and the canonicalized
        //   request-host is identical to the cookie's domain.
        // Or:
        //   The cookie's host-only-flag is false and the canonicalized
        //   request-host domain-matches the cookie's domain."
        if (c.hostOnly) {
          if (c.domain != host) {
            return false;
          }
        } else {
          if (!domainMatch(host, c.domain, false)) {
            return false;
          }
        }
    
        // "The request-uri's path path-matches the cookie's path."
        if (!allPaths && !pathMatch(path, c.path)) {
          return false;
        }
    
        // "If the cookie's secure-only-flag is true, then the request-uri's
        // scheme must denote a "secure" protocol"
        if (c.secure && !secure) {
          return false;
        }
    
        // "If the cookie's http-only-flag is true, then exclude the cookie if the
        // cookie-string is being generated for a "non-HTTP" API"
        if (c.httpOnly && !http) {
          return false;
        }
    
        // deferred from S5.3
        // non-RFC: allow retention of expired cookies by choice
        if (expireCheck && c.expiryTime() <= now) {
          store.removeCookie(c.domain, c.path, c.key, function(){}); // result ignored
          return false;
        }
    
        return true;
      }
    
      store.findCookies(host, allPaths ? null : path, function(err,cookies) {
        if (err) {
          return cb(err);
        }
    
        cookies = cookies.filter(matchingCookie);
    
        // sorting of S5.4 part 2
        if (options.sort !== false) {
          cookies = cookies.sort(cookieCompare);
        }
    
        // S5.4 part 3
        var now = new Date();
        cookies.forEach(function(c) {
          c.lastAccessed = now;
        });
        // TODO persist lastAccessed
    
        cb(null,cookies);
      });
    };
    
    CAN_BE_SYNC.push('getCookieString');
    CookieJar.prototype.getCookieString = function(/*..., cb*/) {
      var args = Array.prototype.slice.call(arguments,0);
      var cb = args.pop();
      var next = function(err,cookies) {
        if (err) {
          cb(err);
        } else {
          cb(null, cookies.map(function(c){
            return c.cookieString();
          }).join('; '));
        }
      };
      args.push(next);
      this.getCookies.apply(this,args);
    };
    
    CAN_BE_SYNC.push('getSetCookieStrings');
    CookieJar.prototype.getSetCookieStrings = function(/*..., cb*/) {
      var args = Array.prototype.slice.call(arguments,0);
      var cb = args.pop();
      var next = function(err,cookies) {
        if (err) {
          cb(err);
        } else {
          cb(null, cookies.map(function(c){
            return c.toString();
          }));
        }
      };
      args.push(next);
      this.getCookies.apply(this,args);
    };
    
    // Use a closure to provide a true imperative API for synchronous stores.
    function syncWrap(method) {
      return function() {
        if (!this.store.synchronous) {
          throw new Error('CookieJar store is not synchronous; use async API instead.');
        }
    
        var args = Array.prototype.slice.call(arguments);
        var syncErr, syncResult;
        args.push(function syncCb(err, result) {
          syncErr = err;
          syncResult = result;
        });
        this[method].apply(this, args);
    
        if (syncErr) {
          throw syncErr;
        }
        return syncResult;
      };
    }
    
    // wrap all declared CAN_BE_SYNC methods in the sync wrapper
    CAN_BE_SYNC.forEach(function(method) {
      CookieJar.prototype[method+'Sync'] = syncWrap(method);
    });
    
    module.exports = {
      CookieJar: CookieJar,
      Cookie: Cookie,
      Store: Store,
      parseDate: parseDate,
      formatDate: formatDate,
      parse: parse,
      fromJSON: fromJSON,
      domainMatch: domainMatch,
      defaultPath: defaultPath,
      pathMatch: pathMatch,
      getPublicSuffix: pubsuffix.getPublicSuffix,
      cookieCompare: cookieCompare,
      permuteDomain: permuteDomain,
      permutePath: permutePath,
      canonicalDomain: canonicalDomain,
    };
    
  provide("tough-cookie", module.exports);
}(global));

// pakmanager:http-signature/lib/parser
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright 2012 Joyent, Inc.  All rights reserved.
    
    var assert = require('assert-plus');
    var util = require('util');
    
    
    
    ///--- Globals
    
    var Algorithms = {
      'rsa-sha1': true,
      'rsa-sha256': true,
      'rsa-sha512': true,
      'dsa-sha1': true,
      'hmac-sha1': true,
      'hmac-sha256': true,
      'hmac-sha512': true
    };
    
    var State = {
      New: 0,
      Params: 1
    };
    
    var ParamsState = {
      Name: 0,
      Quote: 1,
      Value: 2,
      Comma: 3
    };
    
    
    
    ///--- Specific Errors
    
    function HttpSignatureError(message, caller) {
      if (Error.captureStackTrace)
        Error.captureStackTrace(this, caller || HttpSignatureError);
    
      this.message = message;
      this.name = caller.name;
    }
    util.inherits(HttpSignatureError, Error);
    
    function ExpiredRequestError(message) {
      HttpSignatureError.call(this, message, ExpiredRequestError);
    }
    util.inherits(ExpiredRequestError, HttpSignatureError);
    
    
    function InvalidHeaderError(message) {
      HttpSignatureError.call(this, message, InvalidHeaderError);
    }
    util.inherits(InvalidHeaderError, HttpSignatureError);
    
    
    function InvalidParamsError(message) {
      HttpSignatureError.call(this, message, InvalidParamsError);
    }
    util.inherits(InvalidParamsError, HttpSignatureError);
    
    
    function MissingHeaderError(message) {
      HttpSignatureError.call(this, message, MissingHeaderError);
    }
    util.inherits(MissingHeaderError, HttpSignatureError);
    
    
    
    ///--- Exported API
    
    module.exports = {
    
      /**
       * Parses the 'Authorization' header out of an http.ServerRequest object.
       *
       * Note that this API will fully validate the Authorization header, and throw
       * on any error.  It will not however check the signature, or the keyId format
       * as those are specific to your environment.  You can use the options object
       * to pass in extra constraints.
       *
       * As a response object you can expect this:
       *
       *     {
       *       "scheme": "Signature",
       *       "params": {
       *         "keyId": "foo",
       *         "algorithm": "rsa-sha256",
       *         "headers": [
       *           "date" or "x-date",
       *           "content-md5"
       *         ],
       *         "signature": "base64"
       *       },
       *       "signingString": "ready to be passed to crypto.verify()"
       *     }
       *
       * @param {Object} request an http.ServerRequest.
       * @param {Object} options an optional options object with:
       *                   - clockSkew: allowed clock skew in seconds (default 300).
       *                   - headers: required header names (def: date or x-date)
       *                   - algorithms: algorithms to support (default: all).
       * @return {Object} parsed out object (see above).
       * @throws {TypeError} on invalid input.
       * @throws {InvalidHeaderError} on an invalid Authorization header error.
       * @throws {InvalidParamsError} if the params in the scheme are invalid.
       * @throws {MissingHeaderError} if the params indicate a header not present,
       *                              either in the request headers from the params,
       *                              or not in the params from a required header
       *                              in options.
       * @throws {ExpiredRequestError} if the value of date or x-date exceeds skew.
       */
      parseRequest: function parseRequest(request, options) {
        assert.object(request, 'request');
        assert.object(request.headers, 'request.headers');
        if (options === undefined) {
          options = {};
        }
        if (options.headers === undefined) {
          options.headers = [request.headers['x-date'] ? 'x-date' : 'date'];
        }
        assert.object(options, 'options');
        assert.arrayOfString(options.headers, 'options.headers');
        assert.optionalNumber(options.clockSkew, 'options.clockSkew');
    
        if (!request.headers.authorization)
          throw new MissingHeaderError('no authorization header present in ' +
                                       'the request');
    
        options.clockSkew = options.clockSkew || 300;
    
    
        var i = 0;
        var state = State.New;
        var substate = ParamsState.Name;
        var tmpName = '';
        var tmpValue = '';
    
        var parsed = {
          scheme: '',
          params: {},
          signingString: '',
    
          get algorithm() {
            return this.params.algorithm.toUpperCase();
          },
    
          get keyId() {
            return this.params.keyId;
          }
    
        };
    
        var authz = request.headers.authorization;
        for (i = 0; i < authz.length; i++) {
          var c = authz.charAt(i);
    
          switch (Number(state)) {
    
          case State.New:
            if (c !== ' ') parsed.scheme += c;
            else state = State.Params;
            break;
    
          case State.Params:
            switch (Number(substate)) {
    
            case ParamsState.Name:
              var code = c.charCodeAt(0);
              // restricted name of A-Z / a-z
              if ((code >= 0x41 && code <= 0x5a) || // A-Z
                  (code >= 0x61 && code <= 0x7a)) { // a-z
                tmpName += c;
              } else if (c === '=') {
                if (tmpName.length === 0)
                  throw new InvalidHeaderError('bad param format');
                substate = ParamsState.Quote;
              } else {
                throw new InvalidHeaderError('bad param format');
              }
              break;
    
            case ParamsState.Quote:
              if (c === '"') {
                tmpValue = '';
                substate = ParamsState.Value;
              } else {
                throw new InvalidHeaderError('bad param format');
              }
              break;
    
            case ParamsState.Value:
              if (c === '"') {
                parsed.params[tmpName] = tmpValue;
                substate = ParamsState.Comma;
              } else {
                tmpValue += c;
              }
              break;
    
            case ParamsState.Comma:
              if (c === ',') {
                tmpName = '';
                substate = ParamsState.Name;
              } else {
                throw new InvalidHeaderError('bad param format');
              }
              break;
    
            default:
              throw new Error('Invalid substate');
            }
            break;
    
          default:
            throw new Error('Invalid substate');
          }
    
        }
    
        if (!parsed.params.headers || parsed.params.headers === '') {
          if (request.headers['x-date']) {
            parsed.params.headers = ['x-date'];
          } else {
            parsed.params.headers = ['date'];
          }
        } else {
          parsed.params.headers = parsed.params.headers.split(' ');
        }
    
        // Minimally validate the parsed object
        if (!parsed.scheme || parsed.scheme !== 'Signature')
          throw new InvalidHeaderError('scheme was not "Signature"');
    
        if (!parsed.params.keyId)
          throw new InvalidHeaderError('keyId was not specified');
    
        if (!parsed.params.algorithm)
          throw new InvalidHeaderError('algorithm was not specified');
    
        if (!parsed.params.signature)
          throw new InvalidHeaderError('signature was not specified');
    
        // Check the algorithm against the official list
        parsed.params.algorithm = parsed.params.algorithm.toLowerCase();
        if (!Algorithms[parsed.params.algorithm])
          throw new InvalidParamsError(parsed.params.algorithm +
                                       ' is not supported');
    
        // Build the signingString
        for (i = 0; i < parsed.params.headers.length; i++) {
          var h = parsed.params.headers[i].toLowerCase();
          parsed.params.headers[i] = h;
    
          if (h !== 'request-line') {
            var value = request.headers[h];
            if (!value)
              throw new MissingHeaderError(h + ' was not in the request');
            parsed.signingString += h + ': ' + value;
          } else {
            parsed.signingString +=
              request.method + ' ' + request.url + ' HTTP/' + request.httpVersion;
          }
    
          if ((i + 1) < parsed.params.headers.length)
            parsed.signingString += '\n';
        }
    
        // Check against the constraints
        var date;
        if (request.headers.date || request.headers['x-date']) {
            if (request.headers['x-date']) {
              date = new Date(request.headers['x-date']);
            } else {
              date = new Date(request.headers.date);
            }
          var now = new Date();
          var skew = Math.abs(now.getTime() - date.getTime());
    
          if (skew > options.clockSkew * 1000) {
            throw new ExpiredRequestError('clock skew of ' +
                                          (skew / 1000) +
                                          's was greater than ' +
                                          options.clockSkew + 's');
          }
        }
    
        options.headers.forEach(function (hdr) {
          // Remember that we already checked any headers in the params
          // were in the request, so if this passes we're good.
          if (parsed.params.headers.indexOf(hdr) < 0)
            throw new MissingHeaderError(hdr + ' was not a signed header');
        });
    
        if (options.algorithms) {
          if (options.algorithms.indexOf(parsed.params.algorithm) === -1)
            throw new InvalidParamsError(parsed.params.algorithm +
                                         ' is not a supported algorithm');
        }
    
        return parsed;
      }
    
    };
    
  provide("http-signature/lib/parser", module.exports);
}(global));

// pakmanager:http-signature/lib/signer
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright 2012 Joyent, Inc.  All rights reserved.
    
    var assert = require('assert-plus');
    var crypto = require('crypto');
    var http = require('http');
    
    var sprintf = require('util').format;
    
    
    
    ///--- Globals
    
    var Algorithms = {
      'rsa-sha1': true,
      'rsa-sha256': true,
      'rsa-sha512': true,
      'dsa-sha1': true,
      'hmac-sha1': true,
      'hmac-sha256': true,
      'hmac-sha512': true
    };
    
    var Authorization =
      'Signature keyId="%s",algorithm="%s",headers="%s",signature="%s"';
    
    
    
    ///--- Specific Errors
    
    function MissingHeaderError(message) {
        this.name = 'MissingHeaderError';
        this.message = message;
        this.stack = (new Error()).stack;
    }
    MissingHeaderError.prototype = new Error();
    
    
    function InvalidAlgorithmError(message) {
        this.name = 'InvalidAlgorithmError';
        this.message = message;
        this.stack = (new Error()).stack;
    }
    InvalidAlgorithmError.prototype = new Error();
    
    
    
    ///--- Internal Functions
    
    function _pad(val) {
      if (parseInt(val, 10) < 10) {
        val = '0' + val;
      }
      return val;
    }
    
    
    function _rfc1123() {
      var date = new Date();
    
      var months = ['Jan',
                    'Feb',
                    'Mar',
                    'Apr',
                    'May',
                    'Jun',
                    'Jul',
                    'Aug',
                    'Sep',
                    'Oct',
                    'Nov',
                    'Dec'];
      var days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
      return days[date.getUTCDay()] + ', ' +
        _pad(date.getUTCDate()) + ' ' +
        months[date.getUTCMonth()] + ' ' +
        date.getUTCFullYear() + ' ' +
        _pad(date.getUTCHours()) + ':' +
        _pad(date.getUTCMinutes()) + ':' +
        _pad(date.getUTCSeconds()) +
        ' GMT';
    }
    
    
    
    ///--- Exported API
    
    module.exports = {
    
      /**
       * Adds an 'Authorization' header to an http.ClientRequest object.
       *
       * Note that this API will add a Date header if it's not already set. Any
       * other headers in the options.headers array MUST be present, or this
       * will throw.
       *
       * You shouldn't need to check the return type; it's just there if you want
       * to be pedantic.
       *
       * @param {Object} request an instance of http.ClientRequest.
       * @param {Object} options signing parameters object:
       *                   - {String} keyId required.
       *                   - {String} key required (either a PEM or HMAC key).
       *                   - {Array} headers optional; defaults to ['date'].
       *                   - {String} algorithm optional; defaults to 'rsa-sha256'.
       *                   - {String} httpVersion optional; defaults to '1.1'.
       * @return {Boolean} true if Authorization (and optionally Date) were added.
       * @throws {TypeError} on bad parameter types (input).
       * @throws {InvalidAlgorithmError} if algorithm was bad.
       * @throws {MissingHeaderError} if a header to be signed was specified but
       *                              was not present.
       */
      signRequest: function signRequest(request, options) {
        assert.object(request, 'request');
        assert.object(options, 'options');
        assert.optionalString(options.algorithm, 'options.algorithm');
        assert.string(options.keyId, 'options.keyId');
        assert.optionalArrayOfString(options.headers, 'options.headers');
        assert.optionalString(options.httpVersion, 'options.httpVersion');
    
        if (!request.getHeader('Date'))
          request.setHeader('Date', _rfc1123());
        if (!options.headers)
          options.headers = ['date'];
        if (!options.algorithm)
          options.algorithm = 'rsa-sha256';
        if (!options.httpVersion)
          options.httpVersion = '1.1';
    
        options.algorithm = options.algorithm.toLowerCase();
    
        if (!Algorithms[options.algorithm])
          throw new InvalidAlgorithmError(options.algorithm + ' is not supported');
    
        var i;
        var stringToSign = '';
        for (i = 0; i < options.headers.length; i++) {
          if (typeof (options.headers[i]) !== 'string')
            throw new TypeError('options.headers must be an array of Strings');
    
          var h = options.headers[i].toLowerCase();
    
          if (h !== 'request-line') {
            var value = request.getHeader(h);
            if (!value) {
              throw new MissingHeaderError(h + ' was not in the request');
            }
            stringToSign += h + ': ' + value;
          } else {
            value =
            stringToSign +=
              request.method + ' ' + request.path + ' HTTP/' + options.httpVersion;
          }
    
          if ((i + 1) < options.headers.length)
            stringToSign += '\n';
        }
    
        var alg = options.algorithm.match(/(hmac|rsa)-(\w+)/);
        var signature;
        if (alg[1] === 'hmac') {
          var hmac = crypto.createHmac(alg[2].toUpperCase(), options.key);
          hmac.update(stringToSign);
          signature = hmac.digest('base64');
        } else {
          var signer = crypto.createSign(options.algorithm.toUpperCase());
          signer.update(stringToSign);
          signature = signer.sign(options.key, 'base64');
        }
    
        request.setHeader('Authorization', sprintf(Authorization,
                                                   options.keyId,
                                                   options.algorithm,
                                                   options.headers.join(' '),
                                                   signature));
    
        return true;
      }
    
    };
    
  provide("http-signature/lib/signer", module.exports);
}(global));

// pakmanager:http-signature/lib/verify
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright 2011 Joyent, Inc.  All rights reserved.
    
    var assert = require('assert-plus');
    var crypto = require('crypto');
    
    
    
    ///--- Exported API
    
    module.exports = {
    
      /**
       * Simply wraps up the node crypto operations for you, and returns
       * true or false.  You are expected to pass in an object that was
       * returned from `parse()`.
       *
       * @param {Object} parsedSignature the object you got from `parse`.
       * @param {String} key either an RSA private key PEM or HMAC secret.
       * @return {Boolean} true if valid, false otherwise.
       * @throws {TypeError} if you pass in bad arguments.
       */
      verifySignature: function verifySignature(parsedSignature, key) {
        assert.object(parsedSignature, 'parsedSignature');
        assert.string(key, 'key');
    
        var alg = parsedSignature.algorithm.match(/(HMAC|RSA|DSA)-(\w+)/);
        if (!alg || alg.length !== 3)
          throw new TypeError('parsedSignature: unsupported algorithm ' +
                              parsedSignature.algorithm);
    
        if (alg[1] === 'HMAC') {
          var hmac = crypto.createHmac(alg[2].toUpperCase(), key);
          hmac.update(parsedSignature.signingString);
          return (hmac.digest('base64') === parsedSignature.params.signature);
        } else {
          var verify = crypto.createVerify(alg[0]);
          verify.update(parsedSignature.signingString);
          return verify.verify(key, parsedSignature.params.signature, 'base64');
        }
      }
    
    };
    
  provide("http-signature/lib/verify", module.exports);
}(global));

// pakmanager:http-signature/lib/util
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright 2012 Joyent, Inc.  All rights reserved.
    
    var assert = require('assert-plus');
    var crypto = require('crypto');
    
    var asn1 = require('asn1');
    var ctype = require('ctype');
    
    
    
    ///--- Helpers
    
    function readNext(buffer, offset) {
      var len = ctype.ruint32(buffer, 'big', offset);
      offset += 4;
    
      var newOffset = offset + len;
    
      return {
        data: buffer.slice(offset, newOffset),
        offset: newOffset
      };
    }
    
    
    function writeInt(writer, buffer) {
      writer.writeByte(0x02); // ASN1.Integer
      writer.writeLength(buffer.length);
    
      for (var i = 0; i < buffer.length; i++)
        writer.writeByte(buffer[i]);
    
      return writer;
    }
    
    
    function rsaToPEM(key) {
      var buffer;
      var der;
      var exponent;
      var i;
      var modulus;
      var newKey = '';
      var offset = 0;
      var type;
      var tmp;
    
      try {
        buffer = new Buffer(key.split(' ')[1], 'base64');
    
        tmp = readNext(buffer, offset);
        type = tmp.data.toString();
        offset = tmp.offset;
    
        if (type !== 'ssh-rsa')
          throw new Error('Invalid ssh key type: ' + type);
    
        tmp = readNext(buffer, offset);
        exponent = tmp.data;
        offset = tmp.offset;
    
        tmp = readNext(buffer, offset);
        modulus = tmp.data;
      } catch (e) {
        throw new Error('Invalid ssh key: ' + key);
      }
    
      // DER is a subset of BER
      der = new asn1.BerWriter();
    
      der.startSequence();
    
      der.startSequence();
      der.writeOID('1.2.840.113549.1.1.1');
      der.writeNull();
      der.endSequence();
    
      der.startSequence(0x03); // bit string
      der.writeByte(0x00);
    
      // Actual key
      der.startSequence();
      writeInt(der, modulus);
      writeInt(der, exponent);
      der.endSequence();
    
      // bit string
      der.endSequence();
    
      der.endSequence();
    
      tmp = der.buffer.toString('base64');
      for (i = 0; i < tmp.length; i++) {
        if ((i % 64) === 0)
          newKey += '\n';
        newKey += tmp.charAt(i);
      }
    
      if (!/\\n$/.test(newKey))
        newKey += '\n';
    
      return '-----BEGIN PUBLIC KEY-----' + newKey + '-----END PUBLIC KEY-----\n';
    }
    
    
    function dsaToPEM(key) {
      var buffer;
      var offset = 0;
      var tmp;
      var der;
      var newKey = '';
    
      var type;
      var p;
      var q;
      var g;
      var y;
    
      try {
        buffer = new Buffer(key.split(' ')[1], 'base64');
    
        tmp = readNext(buffer, offset);
        type = tmp.data.toString();
        offset = tmp.offset;
    
        /* JSSTYLED */
        if (!/^ssh-ds[as].*/.test(type))
          throw new Error('Invalid ssh key type: ' + type);
    
        tmp = readNext(buffer, offset);
        p = tmp.data;
        offset = tmp.offset;
    
        tmp = readNext(buffer, offset);
        q = tmp.data;
        offset = tmp.offset;
    
        tmp = readNext(buffer, offset);
        g = tmp.data;
        offset = tmp.offset;
    
        tmp = readNext(buffer, offset);
        y = tmp.data;
      } catch (e) {
        console.log(e.stack);
        throw new Error('Invalid ssh key: ' + key);
      }
    
      // DER is a subset of BER
      der = new asn1.BerWriter();
    
      der.startSequence();
    
      der.startSequence();
      der.writeOID('1.2.840.10040.4.1');
    
      der.startSequence();
      writeInt(der, p);
      writeInt(der, q);
      writeInt(der, g);
      der.endSequence();
    
      der.endSequence();
    
      der.startSequence(0x03); // bit string
      der.writeByte(0x00);
      writeInt(der, y);
      der.endSequence();
    
      der.endSequence();
    
      tmp = der.buffer.toString('base64');
      for (var i = 0; i < tmp.length; i++) {
        if ((i % 64) === 0)
          newKey += '\n';
        newKey += tmp.charAt(i);
      }
    
      if (!/\\n$/.test(newKey))
        newKey += '\n';
    
      return '-----BEGIN PUBLIC KEY-----' + newKey + '-----END PUBLIC KEY-----\n';
    }
    
    
    ///--- API
    
    module.exports = {
    
      /**
       * Converts an OpenSSH public key (rsa only) to a PKCS#8 PEM file.
       *
       * The intent of this module is to interoperate with OpenSSL only,
       * specifically the node crypto module's `verify` method.
       *
       * @param {String} key an OpenSSH public key.
       * @return {String} PEM encoded form of the RSA public key.
       * @throws {TypeError} on bad input.
       * @throws {Error} on invalid ssh key formatted data.
       */
      sshKeyToPEM: function sshKeyToPEM(key) {
        assert.string(key, 'ssh_key');
    
        /* JSSTYLED */
        if (/^ssh-rsa.*/.test(key))
          return rsaToPEM(key);
    
        /* JSSTYLED */
        if (/^ssh-ds[as].*/.test(key))
          return dsaToPEM(key);
    
        throw new Error('Only RSA and DSA public keys are allowed');
      },
    
    
      /**
       * Generates an OpenSSH fingerprint from an ssh public key.
       *
       * @param {String} key an OpenSSH public key.
       * @return {String} key fingerprint.
       * @throws {TypeError} on bad input.
       * @throws {Error} if what you passed doesn't look like an ssh public key.
       */
      fingerprint: function fingerprint(key) {
        assert.string(key, 'ssh_key');
    
        var pieces = key.split(' ');
        if (!pieces || !pieces.length || pieces.length < 2)
          throw new Error('invalid ssh key');
    
        var data = new Buffer(pieces[1], 'base64');
    
        var hash = crypto.createHash('md5');
        hash.update(data);
        var digest = hash.digest('hex');
    
        var fp = '';
        for (var i = 0; i < digest.length; i++) {
          if (i && i % 2 === 0)
            fp += ':';
    
          fp += digest[i];
        }
    
        return fp;
      }
    
    
    };
    
  provide("http-signature/lib/util", module.exports);
}(global));

// pakmanager:http-signature
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright 2011 Joyent, Inc.  All rights reserved.
    
    var parser =  require('http-signature/lib/parser');
    var signer =  require('http-signature/lib/signer');
    var verify =  require('http-signature/lib/verify');
    var util =  require('http-signature/lib/util');
    
    
    
    ///--- API
    
    module.exports = {
    
      parse: parser.parseRequest,
      parseRequest: parser.parseRequest,
    
      sign: signer.signRequest,
      signRequest: signer.signRequest,
    
      sshKeyToPEM: util.sshKeyToPEM,
      sshKeyFingerprint: util.fingerprint,
    
      verify: verify.verifySignature,
      verifySignature: verify.verifySignature
    };
    
  provide("http-signature", module.exports);
}(global));

// pakmanager:oauth-sign
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  var crypto = require('crypto')
      , qs = require('querystring')
      ;
    
    function sha1 (key, body) {
      return crypto.createHmac('sha1', key).update(body).digest('base64')
    }
    
    function rsa (key, body) {
      return crypto.createSign("RSA-SHA1").update(body).sign(key, 'base64');
    }
    
    function rfc3986 (str) {
      return encodeURIComponent(str)
        .replace(/!/g,'%21')
        .replace(/\*/g,'%2A')
        .replace(/\(/g,'%28')
        .replace(/\)/g,'%29')
        .replace(/'/g,'%27')
        ;
    }
    
    // Maps object to bi-dimensional array
    // Converts { foo: 'A', bar: [ 'b', 'B' ]} to
    // [ ['foo', 'A'], ['bar', 'b'], ['bar', 'B'] ]
    function map (obj) {
      var key, val, arr = []
      for (key in obj) {
        val = obj[key]
        if (Array.isArray(val))
          for (var i = 0; i < val.length; i++)
            arr.push([key, val[i]])
        else
          arr.push([key, val])
      }
      return arr
    }
    
    // Compare function for sort
    function compare (a, b) {
      return a > b ? 1 : a < b ? -1 : 0
    }
    
    function generateBase (httpMethod, base_uri, params) {
      // adapted from https://dev.twitter.com/docs/auth/oauth and 
      // https://dev.twitter.com/docs/auth/creating-signature
    
      // Parameter normalization
      // http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
      var normalized = map(params)
      // 1.  First, the name and value of each parameter are encoded
      .map(function (p) {
        return [ rfc3986(p[0]), rfc3986(p[1] || '') ]
      })
      // 2.  The parameters are sorted by name, using ascending byte value
      //     ordering.  If two or more parameters share the same name, they
      //     are sorted by their value.
      .sort(function (a, b) {
        return compare(a[0], b[0]) || compare(a[1], b[1])
      })
      // 3.  The name of each parameter is concatenated to its corresponding
      //     value using an "=" character (ASCII code 61) as a separator, even
      //     if the value is empty.
      .map(function (p) { return p.join('=') })
       // 4.  The sorted name/value pairs are concatenated together into a
       //     single string by using an "&" character (ASCII code 38) as
       //     separator.
      .join('&')
    
      var base = [
        rfc3986(httpMethod ? httpMethod.toUpperCase() : 'GET'),
        rfc3986(base_uri),
        rfc3986(normalized)
      ].join('&')
    
      return base
    }
    
    function hmacsign (httpMethod, base_uri, params, consumer_secret, token_secret) {
      var base = generateBase(httpMethod, base_uri, params)
      var key = [
        consumer_secret || '',
        token_secret || ''
      ].map(rfc3986).join('&')
    
      return sha1(key, base)
    }
    
    function rsasign (httpMethod, base_uri, params, private_key, token_secret) {
      var base = generateBase(httpMethod, base_uri, params)
      var key = private_key || ''
    
      return rsa(key, base)
    }
    
    function sign (signMethod, httpMethod, base_uri, params, consumer_secret, token_secret) {
      var method
    
      switch (signMethod) {
        case 'RSA-SHA1':
          method = rsasign
          break
        case 'HMAC-SHA1':
          method = hmacsign
          break
        default:
         throw new Error("Signature method not supported: " + signMethod)
      }
    
      return method.apply(null, [].slice.call(arguments, 1))
    }
    
    exports.hmacsign = hmacsign
    exports.rsasign = rsasign
    exports.sign = sign
    exports.rfc3986 = rfc3986
    
  provide("oauth-sign", module.exports);
}(global));

// pakmanager:hawk/lib/utils
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Load modules
    
    var Sntp = require('sntp');
    var Boom = require('boom');
    
    
    // Declare internals
    
    var internals = {};
    
    
    exports.version = function () {
    
        return require('../package.json').version;
    };
    
    
    // Extract host and port from request
    
    //                                            $1                            $2
    internals.hostHeaderRegex = /^(?:(?:\r\n)?\s)*((?:[^:]+)|(?:\[[^\]]+\]))(?::(\d+))?(?:(?:\r\n)?\s)*$/;              // (IPv4, hostname)|(IPv6)
    
    
    exports.parseHost = function (req, hostHeaderName) {
    
        hostHeaderName = (hostHeaderName ? hostHeaderName.toLowerCase() : 'host');
        var hostHeader = req.headers[hostHeaderName];
        if (!hostHeader) {
            return null;
        }
    
        var hostParts = hostHeader.match(internals.hostHeaderRegex);
        if (!hostParts) {
            return null;
        }
    
        return {
            name: hostParts[1],
            port: (hostParts[2] ? hostParts[2] : (req.connection && req.connection.encrypted ? 443 : 80))
        };
    };
    
    
    // Parse Content-Type header content
    
    exports.parseContentType = function (header) {
    
        if (!header) {
            return '';
        }
    
        return header.split(';')[0].trim().toLowerCase();
    };
    
    
    // Convert node's  to request configuration object
    
    exports.parseRequest = function (req, options) {
    
        if (!req.headers) {
            return req;
        }
        
        // Obtain host and port information
    
        if (!options.host || !options.port) {
            var host = exports.parseHost(req, options.hostHeaderName);
            if (!host) {
                return new Error('Invalid Host header');
            }
        }
    
        var request = {
            method: req.method,
            url: req.url,
            host: options.host || host.name,
            port: options.port || host.port,
            authorization: req.headers.authorization,
            contentType: req.headers['content-type'] || ''
        };
    
        return request;
    };
    
    
    exports.now = function (localtimeOffsetMsec) {
    
        return Sntp.now() + (localtimeOffsetMsec || 0);
    };
    
    
    exports.nowSecs = function (localtimeOffsetMsec) {
    
        return Math.floor(exports.now(localtimeOffsetMsec) / 1000);
    };
    
    
    // Parse Hawk HTTP Authorization header
    
    exports.parseAuthorizationHeader = function (header, keys) {
    
        keys = keys || ['id', 'ts', 'nonce', 'hash', 'ext', 'mac', 'app', 'dlg'];
    
        if (!header) {
            return Boom.unauthorized(null, 'Hawk');
        }
    
        var headerParts = header.match(/^(\w+)(?:\s+(.*))?$/);       // Header: scheme[ something]
        if (!headerParts) {
            return Boom.badRequest('Invalid header syntax');
        }
    
        var scheme = headerParts[1];
        if (scheme.toLowerCase() !== 'hawk') {
            return Boom.unauthorized(null, 'Hawk');
        }
    
        var attributesString = headerParts[2];
        if (!attributesString) {
            return Boom.badRequest('Invalid header syntax');
        }
    
        var attributes = {};
        var errorMessage = '';
        var verify = attributesString.replace(/(\w+)="([^"\\]*)"\s*(?:,\s*|$)/g, function ($0, $1, $2) {
    
            // Check valid attribute names
    
            if (keys.indexOf($1) === -1) {
                errorMessage = 'Unknown attribute: ' + $1;
                return;
            }
    
            // Allowed attribute value characters: !#$%&'()*+,-./:;<=>?@[]^_`{|}~ and space, a-z, A-Z, 0-9
    
            if ($2.match(/^[ \w\!#\$%&'\(\)\*\+,\-\.\/\:;<\=>\?@\[\]\^`\{\|\}~]+$/) === null) {
                errorMessage = 'Bad attribute value: ' + $1;
                return;
            }
    
            // Check for duplicates
    
            if (attributes.hasOwnProperty($1)) {
                errorMessage = 'Duplicate attribute: ' + $1;
                return;
            }
    
            attributes[$1] = $2;
            return '';
        });
    
        if (verify !== '') {
            return Boom.badRequest(errorMessage || 'Bad header format');
        }
    
        return attributes;
    };
    
    
    exports.unauthorized = function (message) {
    
        return Boom.unauthorized(message, 'Hawk');
    };
    
    
  provide("hawk/lib/utils", module.exports);
}(global));

// pakmanager:hawk/lib/crypto
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Load modules
    
    var Crypto = require('crypto');
    var Url = require('url');
    var Utils =  require('hawk/lib/utils');
    
    
    // Declare internals
    
    var internals = {};
    
    
    // MAC normalization format version
    
    exports.headerVersion = '1';                        // Prevent comparison of mac values generated with different normalized string formats
    
    
    // Supported HMAC algorithms
    
    exports.algorithms = ['sha1', 'sha256'];
    
    
    // Calculate the request MAC
    
    /*
        type: 'header',                                 // 'header', 'bewit', 'response'
        credentials: {
            key: 'aoijedoaijsdlaksjdl',
            algorithm: 'sha256'                         // 'sha1', 'sha256'
        },
        options: {
            method: 'GET',
            resource: '/resource?a=1&b=2',
            host: 'example.com',
            port: 8080,
            ts: 1357718381034,
            nonce: 'd3d345f',
            hash: 'U4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=',
            ext: 'app-specific-data',
            app: 'hf48hd83qwkj',                        // Application id (Oz)
            dlg: 'd8djwekds9cj'                         // Delegated by application id (Oz), requires options.app
        }
    */
    
    exports.calculateMac = function (type, credentials, options) {
    
        var normalized = exports.generateNormalizedString(type, options);
    
        var hmac = Crypto.createHmac(credentials.algorithm, credentials.key).update(normalized);
        var digest = hmac.digest('base64');
        return digest;
    };
    
    
    exports.generateNormalizedString = function (type, options) {
    
        var resource = options.resource || '';
        if (resource &&
            resource[0] !== '/') {
    
            var url = Url.parse(resource, false);
            resource = url.path;                        // Includes query
        }
    
        var normalized = 'hawk.' + exports.headerVersion + '.' + type + '\n' +
                         options.ts + '\n' +
                         options.nonce + '\n' +
                         (options.method || '').toUpperCase() + '\n' +
                         resource + '\n' +
                         options.host.toLowerCase() + '\n' +
                         options.port + '\n' +
                         (options.hash || '') + '\n';
    
        if (options.ext) {
            normalized += options.ext.replace('\\', '\\\\').replace('\n', '\\n');
        }
    
        normalized += '\n';
    
        if (options.app) {
            normalized += options.app + '\n' +
                          (options.dlg || '') + '\n';
        }
    
        return normalized;
    };
    
    
    exports.calculatePayloadHash = function (payload, algorithm, contentType) {
    
        var hash = exports.initializePayloadHash(algorithm, contentType);
        hash.update(payload || '');
        return exports.finalizePayloadHash(hash);
    };
    
    
    exports.initializePayloadHash = function (algorithm, contentType) {
    
        var hash = Crypto.createHash(algorithm);
        hash.update('hawk.' + exports.headerVersion + '.payload\n');
        hash.update(Utils.parseContentType(contentType) + '\n');
        return hash;
    };
    
    
    exports.finalizePayloadHash = function (hash) {
    
        hash.update('\n');
        return hash.digest('base64');
    };
    
    
    exports.calculateTsMac = function (ts, credentials) {
    
        var hmac = Crypto.createHmac(credentials.algorithm, credentials.key);
        hmac.update('hawk.' + exports.headerVersion + '.ts\n' + ts + '\n');
        return hmac.digest('base64');
    };
    
    
    exports.timestampMessage = function (credentials, localtimeOffsetMsec) {
    
        var now = Utils.nowSecs(localtimeOffsetMsec);
        var tsm = exports.calculateTsMac(now, credentials);
        return { ts: now, tsm: tsm };
    };
    
  provide("hawk/lib/crypto", module.exports);
}(global));

// pakmanager:hawk/lib/server
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Load modules
    
    var Boom = require('boom');
    var Hoek = require('hoek');
    var Cryptiles = require('cryptiles');
    var Crypto =  require('hawk/lib/crypto');
    var Utils =  require('hawk/lib/utils');
    
    
    // Declare internals
    
    var internals = {};
    
    
    // Hawk authentication
    
    /*
       req:                 node's HTTP request object or an object as follows:
      
                            var request = {
                                method: 'GET',
                                url: '/resource/4?a=1&b=2',
                                host: 'example.com',
                                port: 8080,
                                authorization: 'Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="'
                            };
      
       credentialsFunc:     required function to lookup the set of Hawk credentials based on the provided credentials id.
                            The credentials include the MAC key, MAC algorithm, and other attributes (such as username)
                            needed by the application. This function is the equivalent of verifying the username and
                            password in Basic authentication.
      
                            var credentialsFunc = function (id, callback) {
        
                                // Lookup credentials in database
                                db.lookup(id, function (err, item) {
        
                                    if (err || !item) {
                                        return callback(err);
                                    }
        
                                    var credentials = {
                                        // Required
                                        key: item.key,
                                        algorithm: item.algorithm,
                                        // Application specific
                                        user: item.user
                                    };
        
                                    return callback(null, credentials);
                                });
                            };
      
       options: {
    
            hostHeaderName:        optional header field name, used to override the default 'Host' header when used
                                   behind a cache of a proxy. Apache2 changes the value of the 'Host' header while preserving
                                   the original (which is what the module must verify) in the 'x-forwarded-host' header field.
                                   Only used when passed a node Http.ServerRequest object.
      
            nonceFunc:             optional nonce validation function. The function signature is function(nonce, ts, callback)
                                   where 'callback' must be called using the signature function(err).
      
            timestampSkewSec:      optional number of seconds of permitted clock skew for incoming timestamps. Defaults to 60 seconds.
                                   Provides a +/- skew which means actual allowed window is double the number of seconds.
      
            localtimeOffsetMsec:   optional local clock time offset express in a number of milliseconds (positive or negative).
                                   Defaults to 0.
      
            payload:               optional payload for validation. The client calculates the hash value and includes it via the 'hash'
                                   header attribute. The server always ensures the value provided has been included in the request
                                   MAC. When this option is provided, it validates the hash value itself. Validation is done by calculating
                                   a hash value over the entire payload (assuming it has already be normalized to the same format and
                                   encoding used by the client to calculate the hash on request). If the payload is not available at the time
                                   of authentication, the authenticatePayload() method can be used by passing it the credentials and
                                   attributes.hash returned in the authenticate callback.
    
            host:                  optional host name override. Only used when passed a node request object.
            port:                  optional port override. Only used when passed a node request object.
        }
    
        callback: function (err, credentials, artifacts) { }
     */
    
    exports.authenticate = function (req, credentialsFunc, options, callback) {
    
        callback = Hoek.nextTick(callback);
        
        // Default options
    
        options.nonceFunc = options.nonceFunc || function (nonce, ts, nonceCallback) { return nonceCallback(); };   // No validation
        options.timestampSkewSec = options.timestampSkewSec || 60;                                                  // 60 seconds
    
        // Application time
    
        var now = Utils.now(options.localtimeOffsetMsec);                           // Measure now before any other processing
    
        // Convert node Http request object to a request configuration object
    
        var request = Utils.parseRequest(req, options);
        if (request instanceof Error) {
            return callback(Boom.badRequest(request.message));
        }
    
        // Parse HTTP Authorization header
    
        var attributes = Utils.parseAuthorizationHeader(request.authorization);
        if (attributes instanceof Error) {
            return callback(attributes);
        }
    
        // Construct artifacts container
    
        var artifacts = {
            method: request.method,
            host: request.host,
            port: request.port,
            resource: request.url,
            ts: attributes.ts,
            nonce: attributes.nonce,
            hash: attributes.hash,
            ext: attributes.ext,
            app: attributes.app,
            dlg: attributes.dlg,
            mac: attributes.mac,
            id: attributes.id
        };
    
        // Verify required header attributes
    
        if (!attributes.id ||
            !attributes.ts ||
            !attributes.nonce ||
            !attributes.mac) {
    
            return callback(Boom.badRequest('Missing attributes'), null, artifacts);
        }
    
        // Fetch Hawk credentials
    
        credentialsFunc(attributes.id, function (err, credentials) {
    
            if (err) {
                return callback(err, credentials || null, artifacts);
            }
    
            if (!credentials) {
                return callback(Boom.unauthorized('Unknown credentials', 'Hawk'), null, artifacts);
            }
    
            if (!credentials.key ||
                !credentials.algorithm) {
    
                return callback(Boom.internal('Invalid credentials'), credentials, artifacts);
            }
    
            if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
                return callback(Boom.internal('Unknown algorithm'), credentials, artifacts);
            }
    
            // Calculate MAC
    
            var mac = Crypto.calculateMac('header', credentials, artifacts);
            if (!Cryptiles.fixedTimeComparison(mac, attributes.mac)) {
                return callback(Boom.unauthorized('Bad mac', 'Hawk'), credentials, artifacts);
            }
    
            // Check payload hash
    
            if (options.payload ||
                options.payload === '') {
    
                if (!attributes.hash) {
                    return callback(Boom.unauthorized('Missing required payload hash', 'Hawk'), credentials, artifacts);
                }
    
                var hash = Crypto.calculatePayloadHash(options.payload, credentials.algorithm, request.contentType);
                if (!Cryptiles.fixedTimeComparison(hash, attributes.hash)) {
                    return callback(Boom.unauthorized('Bad payload hash', 'Hawk'), credentials, artifacts);
                }
            }
    
            // Check nonce
    
            options.nonceFunc(attributes.nonce, attributes.ts, function (err) {
    
                if (err) {
                    return callback(Boom.unauthorized('Invalid nonce', 'Hawk'), credentials, artifacts);
                }
    
                // Check timestamp staleness
    
                if (Math.abs((attributes.ts * 1000) - now) > (options.timestampSkewSec * 1000)) {
                    var tsm = Crypto.timestampMessage(credentials, options.localtimeOffsetMsec);
                    return callback(Boom.unauthorized('Stale timestamp', 'Hawk', tsm), credentials, artifacts);
                }
    
                // Successful authentication
    
                return callback(null, credentials, artifacts);
            });
        });
    };
    
    
    // Authenticate payload hash - used when payload cannot be provided during authenticate()
    
    /*
        payload:        raw request payload
        credentials:    from authenticate callback
        artifacts:      from authenticate callback
        contentType:    req.headers['content-type']
    */
    
    exports.authenticatePayload = function (payload, credentials, artifacts, contentType) {
    
        var calculatedHash = Crypto.calculatePayloadHash(payload, credentials.algorithm, contentType);
        return Cryptiles.fixedTimeComparison(calculatedHash, artifacts.hash);
    };
    
    
    // Authenticate payload hash - used when payload cannot be provided during authenticate()
    
    /*
        calculatedHash: the payload hash calculated using Crypto.calculatePayloadHash()
        artifacts:      from authenticate callback
    */
    
    exports.authenticatePayloadHash = function (calculatedHash, artifacts) {
    
        return Cryptiles.fixedTimeComparison(calculatedHash, artifacts.hash);
    };
    
    
    // Generate a Server-Authorization header for a given response
    
    /*
        credentials: {},                                        // Object received from authenticate()
        artifacts: {}                                           // Object received from authenticate(); 'mac', 'hash', and 'ext' - ignored
        options: {
            ext: 'application-specific',                        // Application specific data sent via the ext attribute
            payload: '{"some":"payload"}',                      // UTF-8 encoded string for body hash generation (ignored if hash provided)
            contentType: 'application/json',                    // Payload content-type (ignored if hash provided)
            hash: 'U4MKKSmiVxk37JCCrAVIjV='                     // Pre-calculated payload hash
        }
    */
    
    exports.header = function (credentials, artifacts, options) {
    
        // Prepare inputs
    
        options = options || {};
    
        if (!artifacts ||
            typeof artifacts !== 'object' ||
            typeof options !== 'object') {
    
            return '';
        }
    
        artifacts = Hoek.clone(artifacts);
        delete artifacts.mac;
        artifacts.hash = options.hash;
        artifacts.ext = options.ext;
    
        // Validate credentials
    
        if (!credentials ||
            !credentials.key ||
            !credentials.algorithm) {
    
            // Invalid credential object
            return '';
        }
    
        if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
            return '';
        }
    
        // Calculate payload hash
    
        if (!artifacts.hash &&
            (options.payload || options.payload === '')) {
    
            artifacts.hash = Crypto.calculatePayloadHash(options.payload, credentials.algorithm, options.contentType);
        }
    
        var mac = Crypto.calculateMac('response', credentials, artifacts);
    
        // Construct header
    
        var header = 'Hawk mac="' + mac + '"' +
                     (artifacts.hash ? ', hash="' + artifacts.hash + '"' : '');
    
        if (artifacts.ext !== null &&
            artifacts.ext !== undefined &&
            artifacts.ext !== '') {                       // Other falsey values allowed
    
            header += ', ext="' + Hoek.escapeHeaderAttribute(artifacts.ext) + '"';
        }
    
        return header;
    };
    
    
    /*
     * Arguments and options are the same as authenticate() with the exception that the only supported options are:
     * 'hostHeaderName', 'localtimeOffsetMsec', 'host', 'port'
     */
    
    exports.authenticateBewit = function (req, credentialsFunc, options, callback) {
    
        callback = Hoek.nextTick(callback);
    
        // Application time
    
        var now = Utils.now(options.localtimeOffsetMsec);
    
        // Convert node Http request object to a request configuration object
    
        var request = Utils.parseRequest(req, options);
        if (request instanceof Error) {
            return callback(Boom.badRequest(request.message));
        }
    
        // Extract bewit
    
        //                                 1     2             3           4     
        var resource = request.url.match(/^(\/.*)([\?&])bewit\=([^&$]*)(?:&(.+))?$/);
        if (!resource) {
            return callback(Boom.unauthorized(null, 'Hawk'));
        }
    
        // Bewit not empty
    
        if (!resource[3]) {
            return callback(Boom.unauthorized('Empty bewit', 'Hawk'));
        }
    
        // Verify method is GET
    
        if (request.method !== 'GET' &&
            request.method !== 'HEAD') {
    
            return callback(Boom.unauthorized('Invalid method', 'Hawk'));
        }
    
        // No other authentication
    
        if (request.authorization) {
            return callback(Boom.badRequest('Multiple authentications', 'Hawk'));
        }
    
        // Parse bewit
    
        var bewitString = Hoek.base64urlDecode(resource[3]);
        if (bewitString instanceof Error) {
            return callback(Boom.badRequest('Invalid bewit encoding'));
        }
    
        // Bewit format: id\exp\mac\ext ('\' is used because it is a reserved header attribute character)
    
        var bewitParts = bewitString.split('\\');
        if (bewitParts.length !== 4) {
            return callback(Boom.badRequest('Invalid bewit structure'));
        }
    
        var bewit = {
            id: bewitParts[0],
            exp: parseInt(bewitParts[1], 10),
            mac: bewitParts[2],
            ext: bewitParts[3] || ''
        };
    
        if (!bewit.id ||
            !bewit.exp ||
            !bewit.mac) {
    
            return callback(Boom.badRequest('Missing bewit attributes'));
        }
    
        // Construct URL without bewit
    
        var url = resource[1];
        if (resource[4]) {
            url += resource[2] + resource[4];
        }
    
        // Check expiration
    
        if (bewit.exp * 1000 <= now) {
            return callback(Boom.unauthorized('Access expired', 'Hawk'), null, bewit);
        }
    
        // Fetch Hawk credentials
    
        credentialsFunc(bewit.id, function (err, credentials) {
    
            if (err) {
                return callback(err, credentials || null, bewit.ext);
            }
    
            if (!credentials) {
                return callback(Boom.unauthorized('Unknown credentials', 'Hawk'), null, bewit);
            }
    
            if (!credentials.key ||
                !credentials.algorithm) {
    
                return callback(Boom.internal('Invalid credentials'), credentials, bewit);
            }
    
            if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
                return callback(Boom.internal('Unknown algorithm'), credentials, bewit);
            }
    
            // Calculate MAC
    
            var mac = Crypto.calculateMac('bewit', credentials, {
                ts: bewit.exp,
                nonce: '',
                method: 'GET',
                resource: url,
                host: request.host,
                port: request.port,
                ext: bewit.ext
            });
    
            if (!Cryptiles.fixedTimeComparison(mac, bewit.mac)) {
                return callback(Boom.unauthorized('Bad mac', 'Hawk'), credentials, bewit);
            }
    
            // Successful authentication
    
            return callback(null, credentials, bewit);
        });
    };
    
    
    /*
     *  options are the same as authenticate() with the exception that the only supported options are:
     * 'nonceFunc', 'timestampSkewSec', 'localtimeOffsetMsec'
     */
    
    exports.authenticateMessage = function (host, port, message, authorization, credentialsFunc, options, callback) {
    
        callback = Hoek.nextTick(callback);
        
        // Default options
    
        options.nonceFunc = options.nonceFunc || function (nonce, ts, nonceCallback) { return nonceCallback(); };   // No validation
        options.timestampSkewSec = options.timestampSkewSec || 60;                                                  // 60 seconds
    
        // Application time
    
        var now = Utils.now(options.localtimeOffsetMsec);                       // Measure now before any other processing
    
        // Validate authorization
        
        if (!authorization.id ||
            !authorization.ts ||
            !authorization.nonce ||
            !authorization.hash ||
            !authorization.mac) {
            
                return callback(Boom.badRequest('Invalid authorization'))
        }
    
        // Fetch Hawk credentials
    
        credentialsFunc(authorization.id, function (err, credentials) {
    
            if (err) {
                return callback(err, credentials || null);
            }
    
            if (!credentials) {
                return callback(Boom.unauthorized('Unknown credentials', 'Hawk'));
            }
    
            if (!credentials.key ||
                !credentials.algorithm) {
    
                return callback(Boom.internal('Invalid credentials'), credentials);
            }
    
            if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
                return callback(Boom.internal('Unknown algorithm'), credentials);
            }
    
            // Construct artifacts container
    
            var artifacts = {
                ts: authorization.ts,
                nonce: authorization.nonce,
                host: host,
                port: port,
                hash: authorization.hash
            };
    
            // Calculate MAC
    
            var mac = Crypto.calculateMac('message', credentials, artifacts);
            if (!Cryptiles.fixedTimeComparison(mac, authorization.mac)) {
                return callback(Boom.unauthorized('Bad mac', 'Hawk'), credentials);
            }
    
            // Check payload hash
    
            var hash = Crypto.calculatePayloadHash(message, credentials.algorithm);
            if (!Cryptiles.fixedTimeComparison(hash, authorization.hash)) {
                return callback(Boom.unauthorized('Bad message hash', 'Hawk'), credentials);
            }
    
            // Check nonce
    
            options.nonceFunc(authorization.nonce, authorization.ts, function (err) {
    
                if (err) {
                    return callback(Boom.unauthorized('Invalid nonce', 'Hawk'), credentials);
                }
    
                // Check timestamp staleness
    
                if (Math.abs((authorization.ts * 1000) - now) > (options.timestampSkewSec * 1000)) {
                    return callback(Boom.unauthorized('Stale timestamp'), credentials);
                }
    
                // Successful authentication
    
                return callback(null, credentials);
            });
        });
    };
    
  provide("hawk/lib/server", module.exports);
}(global));

// pakmanager:hawk/lib/client
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Load modules
    
    var Url = require('url');
    var Hoek = require('hoek');
    var Cryptiles = require('cryptiles');
    var Crypto =  require('hawk/lib/crypto');
    var Utils =  require('hawk/lib/utils');
    
    
    // Declare internals
    
    var internals = {};
    
    
    // Generate an Authorization header for a given request
    
    /*
        uri: 'http://example.com/resource?a=b' or object from Url.parse()
        method: HTTP verb (e.g. 'GET', 'POST')
        options: {
    
            // Required
    
            credentials: {
                id: 'dh37fgj492je',
                key: 'aoijedoaijsdlaksjdl',
                algorithm: 'sha256'                                 // 'sha1', 'sha256'
            },
    
            // Optional
    
            ext: 'application-specific',                        // Application specific data sent via the ext attribute
            timestamp: Date.now(),                              // A pre-calculated timestamp
            nonce: '2334f34f',                                  // A pre-generated nonce
            localtimeOffsetMsec: 400,                           // Time offset to sync with server time (ignored if timestamp provided)
            payload: '{"some":"payload"}',                      // UTF-8 encoded string for body hash generation (ignored if hash provided)
            contentType: 'application/json',                    // Payload content-type (ignored if hash provided)
            hash: 'U4MKKSmiVxk37JCCrAVIjV=',                    // Pre-calculated payload hash
            app: '24s23423f34dx',                               // Oz application id
            dlg: '234sz34tww3sd'                                // Oz delegated-by application id
        }
    */
    
    exports.header = function (uri, method, options) {
    
        var result = {
            field: '',
            artifacts: {}
        };
    
        // Validate inputs
    
        if (!uri || (typeof uri !== 'string' && typeof uri !== 'object') ||
            !method || typeof method !== 'string' ||
            !options || typeof options !== 'object') {
    
            result.err = 'Invalid argument type';
            return result;
        }
    
        // Application time
    
        var timestamp = options.timestamp || Utils.nowSecs(options.localtimeOffsetMsec);
    
        // Validate credentials
    
        var credentials = options.credentials;
        if (!credentials ||
            !credentials.id ||
            !credentials.key ||
            !credentials.algorithm) {
    
            result.err = 'Invalid credential object';
            return result;
        }
    
        if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
            result.err = 'Unknown algorithm';
            return result;
        }
    
        // Parse URI
    
        if (typeof uri === 'string') {
            uri = Url.parse(uri);
        }
    
        // Calculate signature
    
        var artifacts = {
            ts: timestamp,
            nonce: options.nonce || Cryptiles.randomString(6),
            method: method,
            resource: uri.pathname + (uri.search || ''),                            // Maintain trailing '?'
            host: uri.hostname,
            port: uri.port || (uri.protocol === 'http:' ? 80 : 443),
            hash: options.hash,
            ext: options.ext,
            app: options.app,
            dlg: options.dlg
        };
    
        result.artifacts = artifacts;
    
        // Calculate payload hash
    
        if (!artifacts.hash &&
            (options.payload || options.payload === '')) {
    
            artifacts.hash = Crypto.calculatePayloadHash(options.payload, credentials.algorithm, options.contentType);
        }
    
        var mac = Crypto.calculateMac('header', credentials, artifacts);
    
        // Construct header
    
        var hasExt = artifacts.ext !== null && artifacts.ext !== undefined && artifacts.ext !== '';       // Other falsey values allowed
        var header = 'Hawk id="' + credentials.id +
                     '", ts="' + artifacts.ts +
                     '", nonce="' + artifacts.nonce +
                     (artifacts.hash ? '", hash="' + artifacts.hash : '') +
                     (hasExt ? '", ext="' + Hoek.escapeHeaderAttribute(artifacts.ext) : '') +
                     '", mac="' + mac + '"';
    
        if (artifacts.app) {
            header += ', app="' + artifacts.app +
                      (artifacts.dlg ? '", dlg="' + artifacts.dlg : '') + '"';
        }
    
        result.field = header;
    
        return result;
    };
    
    
    // Validate server response
    
    /*
        res:        node's response object
        artifacts:  object received from header().artifacts
        options: {
            payload:    optional payload received
            required:   specifies if a Server-Authorization header is required. Defaults to 'false'
        }
    */
    
    exports.authenticate = function (res, credentials, artifacts, options) {
    
        artifacts = Hoek.clone(artifacts);
        options = options || {};
    
        if (res.headers['www-authenticate']) {
    
            // Parse HTTP WWW-Authenticate header
    
            var attributes = Utils.parseAuthorizationHeader(res.headers['www-authenticate'], ['ts', 'tsm', 'error']);
            if (attributes instanceof Error) {
                return false;
            }
    
            // Validate server timestamp (not used to update clock since it is done via the SNPT client)
    
            if (attributes.ts) {
                var tsm = Crypto.calculateTsMac(attributes.ts, credentials);
                if (tsm !== attributes.tsm) {
                    return false;
                }
            }
        }
    
        // Parse HTTP Server-Authorization header
    
        if (!res.headers['server-authorization'] &&
            !options.required) {
    
            return true;
        }
    
        var attributes = Utils.parseAuthorizationHeader(res.headers['server-authorization'], ['mac', 'ext', 'hash']);
        if (attributes instanceof Error) {
            return false;
        }
    
        artifacts.ext = attributes.ext;
        artifacts.hash = attributes.hash;
    
        var mac = Crypto.calculateMac('response', credentials, artifacts);
        if (mac !== attributes.mac) {
            return false;
        }
    
        if (!options.payload &&
            options.payload !== '') {
    
            return true;
        }
    
        if (!attributes.hash) {
            return false;
        }
    
        var calculatedHash = Crypto.calculatePayloadHash(options.payload, credentials.algorithm, res.headers['content-type']);
        return (calculatedHash === attributes.hash);
    };
    
    
    // Generate a bewit value for a given URI
    
    /*
        uri: 'http://example.com/resource?a=b' or object from Url.parse()
        options: {
    
            // Required
    
            credentials: {
                id: 'dh37fgj492je',
                key: 'aoijedoaijsdlaksjdl',
                algorithm: 'sha256'                             // 'sha1', 'sha256'
            },
            ttlSec: 60 * 60,                                    // TTL in seconds
    
            // Optional
    
            ext: 'application-specific',                        // Application specific data sent via the ext attribute
            localtimeOffsetMsec: 400                            // Time offset to sync with server time
        };
    */
    
    exports.getBewit = function (uri, options) {
    
        // Validate inputs
    
        if (!uri ||
            (typeof uri !== 'string' && typeof uri !== 'object') ||
            !options ||
            typeof options !== 'object' ||
            !options.ttlSec) {
    
            return '';
        }
    
        options.ext = (options.ext === null || options.ext === undefined ? '' : options.ext);       // Zero is valid value
    
        // Application time
    
        var now = Utils.now(options.localtimeOffsetMsec);
    
        // Validate credentials
    
        var credentials = options.credentials;
        if (!credentials ||
            !credentials.id ||
            !credentials.key ||
            !credentials.algorithm) {
    
            return '';
        }
    
        if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
            return '';
        }
    
        // Parse URI
    
        if (typeof uri === 'string') {
            uri = Url.parse(uri);
        }
    
        // Calculate signature
    
        var exp = Math.floor(now / 1000) + options.ttlSec;
        var mac = Crypto.calculateMac('bewit', credentials, {
            ts: exp,
            nonce: '',
            method: 'GET',
            resource: uri.pathname + (uri.search || ''),                            // Maintain trailing '?'
            host: uri.hostname,
            port: uri.port || (uri.protocol === 'http:' ? 80 : 443),
            ext: options.ext
        });
    
        // Construct bewit: id\exp\mac\ext
    
        var bewit = credentials.id + '\\' + exp + '\\' + mac + '\\' + options.ext;
        return Hoek.base64urlEncode(bewit);
    };
    
    
    // Generate an authorization string for a message
    
    /*
        host: 'example.com',
        port: 8000,
        message: '{"some":"payload"}',                          // UTF-8 encoded string for body hash generation
        options: {
    
            // Required
    
            credentials: {
                id: 'dh37fgj492je',
                key: 'aoijedoaijsdlaksjdl',
                algorithm: 'sha256'                             // 'sha1', 'sha256'
            },
    
            // Optional
    
            timestamp: Date.now(),                              // A pre-calculated timestamp
            nonce: '2334f34f',                                  // A pre-generated nonce
            localtimeOffsetMsec: 400,                           // Time offset to sync with server time (ignored if timestamp provided)
        }
    */
    
    exports.message = function (host, port, message, options) {
    
        // Validate inputs
    
        if (!host || typeof host !== 'string' ||
            !port || typeof port !== 'number' ||
            message === null || message === undefined || typeof message !== 'string' ||
            !options || typeof options !== 'object') {
    
            return null;
        }
    
        // Application time
    
        var timestamp = options.timestamp || Utils.nowSecs(options.localtimeOffsetMsec);
    
        // Validate credentials
    
        var credentials = options.credentials;
        if (!credentials ||
            !credentials.id ||
            !credentials.key ||
            !credentials.algorithm) {
    
            // Invalid credential object
            return null;
        }
    
        if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
            return null;
        }
    
        // Calculate signature
    
        var artifacts = {
            ts: timestamp,
            nonce: options.nonce || Cryptiles.randomString(6),
            host: host,
            port: port,
            hash: Crypto.calculatePayloadHash(message, credentials.algorithm)
        };
    
        // Construct authorization
    
        var result = {
            id: credentials.id,
            ts: artifacts.ts,
            nonce: artifacts.nonce,
            hash: artifacts.hash,
            mac: Crypto.calculateMac('message', credentials, artifacts)
        };
    
        return result;
    };
    
    
    
    
  provide("hawk/lib/client", module.exports);
}(global));

// pakmanager:hawk/lib
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Export sub-modules
    
    exports.error = exports.Error = require('boom');
    exports.sntp = require('sntp');
    
    exports.server =  require('hawk/lib/server');
    exports.client =  require('hawk/lib/client');
    exports.crypto =  require('hawk/lib/crypto');
    exports.utils =  require('hawk/lib/utils');
    
    exports.uri = {
        authenticate: exports.server.authenticateBewit,
        getBewit: exports.client.getBewit
    };
    
    
  provide("hawk/lib", module.exports);
}(global));

// pakmanager:hawk
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  module.exports =  require('hawk/lib');
  provide("hawk", module.exports);
}(global));

// pakmanager:aws-sign2
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  
    /*!
     * knox - auth
     * Copyright(c) 2010 LearnBoost <dev@learnboost.com>
     * MIT Licensed
     */
    
    /**
     * Module dependencies.
     */
    
    var crypto = require('crypto')
      , parse = require('url').parse
      ;
    
    /**
     * Valid keys.
     */
    
    var keys = 
      [ 'acl'
      , 'location'
      , 'logging'
      , 'notification'
      , 'partNumber'
      , 'policy'
      , 'requestPayment'
      , 'torrent'
      , 'uploadId'
      , 'uploads'
      , 'versionId'
      , 'versioning'
      , 'versions'
      , 'website'
      ]
    
    /**
     * Return an "Authorization" header value with the given `options`
     * in the form of "AWS <key>:<signature>"
     *
     * @param {Object} options
     * @return {String}
     * @api private
     */
    
    function authorization (options) {
      return 'AWS ' + options.key + ':' + sign(options)
    }
    
    module.exports = authorization
    module.exports.authorization = authorization
    
    /**
     * Simple HMAC-SHA1 Wrapper
     *
     * @param {Object} options
     * @return {String}
     * @api private
     */ 
    
    function hmacSha1 (options) {
      return crypto.createHmac('sha1', options.secret).update(options.message).digest('base64')
    }
    
    module.exports.hmacSha1 = hmacSha1
    
    /**
     * Create a base64 sha1 HMAC for `options`. 
     * 
     * @param {Object} options
     * @return {String}
     * @api private
     */
    
    function sign (options) {
      options.message = stringToSign(options)
      return hmacSha1(options)
    }
    module.exports.sign = sign
    
    /**
     * Create a base64 sha1 HMAC for `options`. 
     *
     * Specifically to be used with S3 presigned URLs
     * 
     * @param {Object} options
     * @return {String}
     * @api private
     */
    
    function signQuery (options) {
      options.message = queryStringToSign(options)
      return hmacSha1(options)
    }
    module.exports.signQuery= signQuery
    
    /**
     * Return a string for sign() with the given `options`.
     *
     * Spec:
     * 
     *    <verb>\n
     *    <md5>\n
     *    <content-type>\n
     *    <date>\n
     *    [headers\n]
     *    <resource>
     *
     * @param {Object} options
     * @return {String}
     * @api private
     */
    
    function stringToSign (options) {
      var headers = options.amazonHeaders || ''
      if (headers) headers += '\n'
      var r = 
        [ options.verb
        , options.md5
        , options.contentType
        , options.date ? options.date.toUTCString() : ''
        , headers + options.resource
        ]
      return r.join('\n')
    }
    module.exports.queryStringToSign = stringToSign
    
    /**
     * Return a string for sign() with the given `options`, but is meant exclusively
     * for S3 presigned URLs
     *
     * Spec:
     * 
     *    <date>\n
     *    <resource>
     *
     * @param {Object} options
     * @return {String}
     * @api private
     */
    
    function queryStringToSign (options){
      return 'GET\n\n\n' + options.date + '\n' + options.resource
    }
    module.exports.queryStringToSign = queryStringToSign
    
    /**
     * Perform the following:
     *
     *  - ignore non-amazon headers
     *  - lowercase fields
     *  - sort lexicographically
     *  - trim whitespace between ":"
     *  - join with newline
     *
     * @param {Object} headers
     * @return {String}
     * @api private
     */
    
    function canonicalizeHeaders (headers) {
      var buf = []
        , fields = Object.keys(headers)
        ;
      for (var i = 0, len = fields.length; i < len; ++i) {
        var field = fields[i]
          , val = headers[field]
          , field = field.toLowerCase()
          ;
        if (0 !== field.indexOf('x-amz')) continue
        buf.push(field + ':' + val)
      }
      return buf.sort().join('\n')
    }
    module.exports.canonicalizeHeaders = canonicalizeHeaders
    
    /**
     * Perform the following:
     *
     *  - ignore non sub-resources
     *  - sort lexicographically
     *
     * @param {String} resource
     * @return {String}
     * @api private
     */
    
    function canonicalizeResource (resource) {
      var url = parse(resource, true)
        , path = url.pathname
        , buf = []
        ;
    
      Object.keys(url.query).forEach(function(key){
        if (!~keys.indexOf(key)) return
        var val = '' == url.query[key] ? '' : '=' + encodeURIComponent(url.query[key])
        buf.push(key + val)
      })
    
      return path + (buf.length ? '?' + buf.sort().join('&') : '')
    }
    module.exports.canonicalizeResource = canonicalizeResource
    
  provide("aws-sign2", module.exports);
}(global));

// pakmanager:stringstream
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  var util = require('util')
    var Stream = require('stream')
    var StringDecoder = require('string_decoder').StringDecoder
    
    module.exports = StringStream
    module.exports.AlignedStringDecoder = AlignedStringDecoder
    
    function StringStream(from, to) {
      if (!(this instanceof StringStream)) return new StringStream(from, to)
    
      Stream.call(this)
    
      if (from == null) from = 'utf8'
    
      this.readable = this.writable = true
      this.paused = false
      this.toEncoding = (to == null ? from : to)
      this.fromEncoding = (to == null ? '' : from)
      this.decoder = new AlignedStringDecoder(this.toEncoding)
    }
    util.inherits(StringStream, Stream)
    
    StringStream.prototype.write = function(data) {
      if (!this.writable) {
        var err = new Error('stream not writable')
        err.code = 'EPIPE'
        this.emit('error', err)
        return false
      }
      if (this.fromEncoding) {
        if (Buffer.isBuffer(data)) data = data.toString()
        data = new Buffer(data, this.fromEncoding)
      }
      var string = this.decoder.write(data)
      if (string.length) this.emit('data', string)
      return !this.paused
    }
    
    StringStream.prototype.flush = function() {
      if (this.decoder.flush) {
        var string = this.decoder.flush()
        if (string.length) this.emit('data', string)
      }
    }
    
    StringStream.prototype.end = function() {
      if (!this.writable && !this.readable) return
      this.flush()
      this.emit('end')
      this.writable = this.readable = false
      this.destroy()
    }
    
    StringStream.prototype.destroy = function() {
      this.decoder = null
      this.writable = this.readable = false
      this.emit('close')
    }
    
    StringStream.prototype.pause = function() {
      this.paused = true
    }
    
    StringStream.prototype.resume = function () {
      if (this.paused) this.emit('drain')
      this.paused = false
    }
    
    function AlignedStringDecoder(encoding) {
      StringDecoder.call(this, encoding)
    
      switch (this.encoding) {
        case 'base64':
          this.write = alignedWrite
          this.alignedBuffer = new Buffer(3)
          this.alignedBytes = 0
          break
      }
    }
    util.inherits(AlignedStringDecoder, StringDecoder)
    
    AlignedStringDecoder.prototype.flush = function() {
      if (!this.alignedBuffer || !this.alignedBytes) return ''
      var leftover = this.alignedBuffer.toString(this.encoding, 0, this.alignedBytes)
      this.alignedBytes = 0
      return leftover
    }
    
    function alignedWrite(buffer) {
      var rem = (this.alignedBytes + buffer.length) % this.alignedBuffer.length
      if (!rem && !this.alignedBytes) return buffer.toString(this.encoding)
    
      var returnBuffer = new Buffer(this.alignedBytes + buffer.length - rem)
    
      this.alignedBuffer.copy(returnBuffer, 0, 0, this.alignedBytes)
      buffer.copy(returnBuffer, this.alignedBytes, 0, buffer.length - rem)
    
      buffer.copy(this.alignedBuffer, 0, buffer.length - rem, buffer.length)
      this.alignedBytes = rem
    
      return returnBuffer.toString(this.encoding)
    }
    
  provide("stringstream", module.exports);
}(global));

// pakmanager:request/lib/cookies
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  'use strict'
    
    var tough = require('tough-cookie')
    
    var Cookie = tough.Cookie
      , CookieJar = tough.CookieJar
    
    
    exports.parse = function(str) {
      if (str && str.uri) {
        str = str.uri
      }
      if (typeof str !== 'string') {
        throw new Error('The cookie function only accepts STRING as param')
      }
      return Cookie.parse(str)
    }
    
    // Adapt the sometimes-Async api of tough.CookieJar to our requirements
    function RequestJar(store) {
      var self = this
      self._jar = new CookieJar(store)
    }
    RequestJar.prototype.setCookie = function(cookieOrStr, uri, options) {
      var self = this
      return self._jar.setCookieSync(cookieOrStr, uri, options || {})
    }
    RequestJar.prototype.getCookieString = function(uri) {
      var self = this
      return self._jar.getCookieStringSync(uri)
    }
    RequestJar.prototype.getCookies = function(uri) {
      var self = this
      return self._jar.getCookiesSync(uri)
    }
    
    exports.jar = function(store) {
      return new RequestJar(store)
    }
    
  provide("request/lib/cookies", module.exports);
}(global));

// pakmanager:request/lib/helpers
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  'use strict'
    
    var extend = require('util')._extend
      , jsonSafeStringify = require('json-stringify-safe')
      , crypto = require('crypto')
    
    function deferMethod() {
      if(typeof setImmediate === 'undefined') {
        return process.nextTick
      }
      
      return setImmediate
    }
    
    function constructObject(initialObject) {
      initialObject = initialObject || {}
    
      return {
        extend: function (object) {
          return constructObject(extend(initialObject, object))
        },
        done: function () {
          return initialObject
        }
      }
    }
    
    function constructOptionsFrom(uri, options) {
      var params = constructObject()
      if (typeof options === 'object') {
        params.extend(options).extend({uri: uri})
      } else if (typeof uri === 'string') {
        params.extend({uri: uri})
      } else {
        params.extend(uri)
      }
      return params.done()
    }
    
    function isFunction(value) {
      return typeof value === 'function'
    }
    
    function filterForCallback(values) {
      var callbacks = values.filter(isFunction)
      return callbacks[0]
    }
    
    function paramsHaveRequestBody(params) {
      return (
        params.options.body ||
        params.options.requestBodyStream ||
        (params.options.json && typeof params.options.json !== 'boolean') ||
        params.options.multipart
      )
    }
    
    function safeStringify (obj) {
      var ret
      try {
        ret = JSON.stringify(obj)
      } catch (e) {
        ret = jsonSafeStringify(obj)
      }
      return ret
    }
    
    function md5 (str) {
      return crypto.createHash('md5').update(str).digest('hex')
    }
    
    function isReadStream (rs) {
      return rs.readable && rs.path && rs.mode
    }
    
    function toBase64 (str) {
      return (new Buffer(str || '', 'ascii')).toString('base64')
    }
    
    exports.isFunction            = isFunction
    exports.constructObject       = constructObject
    exports.constructOptionsFrom  = constructOptionsFrom
    exports.filterForCallback     = filterForCallback
    exports.paramsHaveRequestBody = paramsHaveRequestBody
    exports.safeStringify         = safeStringify
    exports.md5                   = md5
    exports.isReadStream          = isReadStream
    exports.toBase64              = toBase64
    exports.defer                 = deferMethod()
    
  provide("request/lib/helpers", module.exports);
}(global));

// pakmanager:request
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Copyright 2010-2012 Mikeal Rogers
    //
    //    Licensed under the Apache License, Version 2.0 (the "License");
    //    you may not use this file except in compliance with the License.
    //    You may obtain a copy of the License at
    //
    //        http://www.apache.org/licenses/LICENSE-2.0
    //
    //    Unless required by applicable law or agreed to in writing, software
    //    distributed under the License is distributed on an "AS IS" BASIS,
    //    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    //    See the License for the specific language governing permissions and
    //    limitations under the License.
    
    'use strict'
    
    var extend                = require('util')._extend
      , cookies               =  require('request/lib/cookies')
      , helpers               =  require('request/lib/helpers')
    
    var isFunction            = helpers.isFunction
      , constructObject       = helpers.constructObject
      , filterForCallback     = helpers.filterForCallback
      , constructOptionsFrom  = helpers.constructOptionsFrom
      , paramsHaveRequestBody = helpers.paramsHaveRequestBody
    
    
    // organize params for patch, post, put, head, del
    function initParams(uri, options, callback) {
      callback = filterForCallback([options, callback])
      options = constructOptionsFrom(uri, options)
    
      return constructObject()
        .extend({callback: callback})
        .extend({options: options})
        .extend({uri: options.uri})
        .done()
    }
    
    function request (uri, options, callback) {
      if (typeof uri === 'undefined') {
        throw new Error('undefined is not a valid uri or options object.')
      }
    
      var params = initParams(uri, options, callback)
      options = params.options
      options.callback = params.callback
      options.uri = params.uri
    
      return new request.Request(options)
    }
    
    function requester(params) {
      if(typeof params.options._requester === 'function') {
        return params.options._requester
      }
      return request
    }
    
    request.get = function (uri, options, callback) {
      var params = initParams(uri, options, callback)
      params.options.method = 'GET'
      return requester(params)(params.uri || null, params.options, params.callback)
    }
    
    request.head = function (uri, options, callback) {
      var params = initParams(uri, options, callback)
      params.options.method = 'HEAD'
    
      if (paramsHaveRequestBody(params)) {
        throw new Error('HTTP HEAD requests MUST NOT include a request body.')
      }
    
      return requester(params)(params.uri || null, params.options, params.callback)
    }
    
    request.post = function (uri, options, callback) {
      var params = initParams(uri, options, callback)
      params.options.method = 'POST'
      return requester(params)(params.uri || null, params.options, params.callback)
    }
    
    request.put = function (uri, options, callback) {
      var params = initParams(uri, options, callback)
      params.options.method = 'PUT'
      return requester(params)(params.uri || null, params.options, params.callback)
    }
    
    request.patch = function (uri, options, callback) {
      var params = initParams(uri, options, callback)
      params.options.method = 'PATCH'
      return requester(params)(params.uri || null, params.options, params.callback)
    }
    
    request.del = function (uri, options, callback) {
      var params = initParams(uri, options, callback)
      params.options.method = 'DELETE'
      return requester(params)(params.uri || null, params.options, params.callback)
    }
    
    request.jar = function (store) {
      return cookies.jar(store)
    }
    
    request.cookie = function (str) {
      return cookies.parse(str)
    }
    
    request.defaults = function (options, requester) {
      var self = this
      var wrap = function (method) {
        var headerlessOptions = function (options) {
          options = extend({}, options)
          delete options.headers
          return options
        }
    
        var getHeaders = function (params, options) {
          return constructObject()
            .extend(options.headers)
            .extend(params.options.headers)
            .done()
        }
    
        return function (uri, opts, callback) {
          var params = initParams(uri, opts, callback)
          params.options = extend(headerlessOptions(options), params.options)
    
          if (options.headers) {
            params.options.headers = getHeaders(params, options)
          }
    
          if (isFunction(requester)) {
            if (method === self) {
              method = requester
            } else {
              params.options._requester = requester
            }
          }
    
          return method(params.options, params.callback)
        }
      }
    
      var defaults      = wrap(self)
      defaults.get      = wrap(self.get)
      defaults.patch    = wrap(self.patch)
      defaults.post     = wrap(self.post)
      defaults.put      = wrap(self.put)
      defaults.head     = wrap(self.head)
      defaults.del      = wrap(self.del)
      defaults.cookie   = wrap(self.cookie)
      defaults.jar      = self.jar
      defaults.defaults = self.defaults
      return defaults
    }
    
    request.forever = function (agentOptions, optionsArg) {
      var options = constructObject()
      if (optionsArg) {
        options.extend(optionsArg)
      }
      if (agentOptions) {
        options.agentOptions = agentOptions
      }
    
      options.extend({forever: true})
      return request.defaults(options.done())
    }
    
    // Exports
    
    module.exports = request
    request.Request =   require('request')
    request.debug = process.env.NODE_DEBUG && /\brequest\b/.test(process.env.NODE_DEBUG)
    request.initParams = initParams
    
  provide("request", module.exports);
}(global));

// pakmanager:colors/lib/styles
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  /*
    The MIT License (MIT)
    
    Copyright (c) Sindre Sorhus <sindresorhus@gmail.com> (sindresorhus.com)
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
    
    */
    
    var styles = {};
    module['exports'] = styles;
    
    var codes = {
      reset: [0, 0],
    
      bold: [1, 22],
      dim: [2, 22],
      italic: [3, 23],
      underline: [4, 24],
      inverse: [7, 27],
      hidden: [8, 28],
      strikethrough: [9, 29],
    
      black: [30, 39],
      red: [31, 39],
      green: [32, 39],
      yellow: [33, 39],
      blue: [34, 39],
      magenta: [35, 39],
      cyan: [36, 39],
      white: [37, 39],
      gray: [90, 39],
      grey: [90, 39],
    
      bgBlack: [40, 49],
      bgRed: [41, 49],
      bgGreen: [42, 49],
      bgYellow: [43, 49],
      bgBlue: [44, 49],
      bgMagenta: [45, 49],
      bgCyan: [46, 49],
      bgWhite: [47, 49],
    
      // legacy styles for colors pre v1.0.0
      blackBG: [40, 49],
      redBG: [41, 49],
      greenBG: [42, 49],
      yellowBG: [43, 49],
      blueBG: [44, 49],
      magentaBG: [45, 49],
      cyanBG: [46, 49],
      whiteBG: [47, 49]
    
    };
    
    Object.keys(codes).forEach(function (key) {
      var val = codes[key];
      var style = styles[key] = [];
      style.open = '\u001b[' + val[0] + 'm';
      style.close = '\u001b[' + val[1] + 'm';
    });
  provide("colors/lib/styles", module.exports);
}(global));

// pakmanager:colors/lib/system/supports-colors
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  /*
    The MIT License (MIT)
    
    Copyright (c) Sindre Sorhus <sindresorhus@gmail.com> (sindresorhus.com)
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
    
    */
    
    var argv = process.argv;
    
    module.exports = (function () {
      if (argv.indexOf('--no-color') !== -1 ||
        argv.indexOf('--color=false') !== -1) {
        return false;
      }
    
      if (argv.indexOf('--color') !== -1 ||
        argv.indexOf('--color=true') !== -1 ||
        argv.indexOf('--color=always') !== -1) {
        return true;
      }
    
      if (process.stdout && !process.stdout.isTTY) {
        return false;
      }
    
      if (process.platform === 'win32') {
        return true;
      }
    
      if ('COLORTERM' in process.env) {
        return true;
      }
    
      if (process.env.TERM === 'dumb') {
        return false;
      }
    
      if (/^screen|^xterm|^vt100|color|ansi|cygwin|linux/i.test(process.env.TERM)) {
        return true;
      }
    
      return false;
    })();
  provide("colors/lib/system/supports-colors", module.exports);
}(global));

// pakmanager:colors/lib/custom/trap
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  module['exports'] = function runTheTrap (text, options) {
      var result = "";
      text = text || "Run the trap, drop the bass";
      text = text.split('');
      var trap = {
        a: ["\u0040", "\u0104", "\u023a", "\u0245", "\u0394", "\u039b", "\u0414"],
        b: ["\u00df", "\u0181", "\u0243", "\u026e", "\u03b2", "\u0e3f"],
        c: ["\u00a9", "\u023b", "\u03fe"],
        d: ["\u00d0", "\u018a", "\u0500" , "\u0501" ,"\u0502", "\u0503"],
        e: ["\u00cb", "\u0115", "\u018e", "\u0258", "\u03a3", "\u03be", "\u04bc", "\u0a6c"],
        f: ["\u04fa"],
        g: ["\u0262"],
        h: ["\u0126", "\u0195", "\u04a2", "\u04ba", "\u04c7", "\u050a"],
        i: ["\u0f0f"],
        j: ["\u0134"],
        k: ["\u0138", "\u04a0", "\u04c3", "\u051e"],
        l: ["\u0139"],
        m: ["\u028d", "\u04cd", "\u04ce", "\u0520", "\u0521", "\u0d69"],
        n: ["\u00d1", "\u014b", "\u019d", "\u0376", "\u03a0", "\u048a"],
        o: ["\u00d8", "\u00f5", "\u00f8", "\u01fe", "\u0298", "\u047a", "\u05dd", "\u06dd", "\u0e4f"],
        p: ["\u01f7", "\u048e"],
        q: ["\u09cd"],
        r: ["\u00ae", "\u01a6", "\u0210", "\u024c", "\u0280", "\u042f"],
        s: ["\u00a7", "\u03de", "\u03df", "\u03e8"],
        t: ["\u0141", "\u0166", "\u0373"],
        u: ["\u01b1", "\u054d"],
        v: ["\u05d8"],
        w: ["\u0428", "\u0460", "\u047c", "\u0d70"],
        x: ["\u04b2", "\u04fe", "\u04fc", "\u04fd"],
        y: ["\u00a5", "\u04b0", "\u04cb"],
        z: ["\u01b5", "\u0240"]
      }
      text.forEach(function(c){
        c = c.toLowerCase();
        var chars = trap[c] || [" "];
        var rand = Math.floor(Math.random() * chars.length);
        if (typeof trap[c] !== "undefined") {
          result += trap[c][rand];
        } else {
          result += c;
        }
      });
      return result;
    
    }
    
  provide("colors/lib/custom/trap", module.exports);
}(global));

// pakmanager:colors/lib/custom/zalgo
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // please no
    module['exports'] = function zalgo(text, options) {
      text = text || "   he is here   ";
      var soul = {
        "up" : [
          '̍', '̎', '̄', '̅',
          '̿', '̑', '̆', '̐',
          '͒', '͗', '͑', '̇',
          '̈', '̊', '͂', '̓',
          '̈', '͊', '͋', '͌',
          '̃', '̂', '̌', '͐',
          '̀', '́', '̋', '̏',
          '̒', '̓', '̔', '̽',
          '̉', 'ͣ', 'ͤ', 'ͥ',
          'ͦ', 'ͧ', 'ͨ', 'ͩ',
          'ͪ', 'ͫ', 'ͬ', 'ͭ',
          'ͮ', 'ͯ', '̾', '͛',
          '͆', '̚'
        ],
        "down" : [
          '̖', '̗', '̘', '̙',
          '̜', '̝', '̞', '̟',
          '̠', '̤', '̥', '̦',
          '̩', '̪', '̫', '̬',
          '̭', '̮', '̯', '̰',
          '̱', '̲', '̳', '̹',
          '̺', '̻', '̼', 'ͅ',
          '͇', '͈', '͉', '͍',
          '͎', '͓', '͔', '͕',
          '͖', '͙', '͚', '̣'
        ],
        "mid" : [
          '̕', '̛', '̀', '́',
          '͘', '̡', '̢', '̧',
          '̨', '̴', '̵', '̶',
          '͜', '͝', '͞',
          '͟', '͠', '͢', '̸',
          '̷', '͡', ' ҉'
        ]
      },
      all = [].concat(soul.up, soul.down, soul.mid),
      zalgo = {};
    
      function randomNumber(range) {
        var r = Math.floor(Math.random() * range);
        return r;
      }
    
      function is_char(character) {
        var bool = false;
        all.filter(function (i) {
          bool = (i === character);
        });
        return bool;
      }
      
    
      function heComes(text, options) {
        var result = '', counts, l;
        options = options || {};
        options["up"] = options["up"] || true;
        options["mid"] = options["mid"] || true;
        options["down"] = options["down"] || true;
        options["size"] = options["size"] || "maxi";
        text = text.split('');
        for (l in text) {
          if (is_char(l)) {
            continue;
          }
          result = result + text[l];
          counts = {"up" : 0, "down" : 0, "mid" : 0};
          switch (options.size) {
          case 'mini':
            counts.up = randomNumber(8);
            counts.min = randomNumber(2);
            counts.down = randomNumber(8);
            break;
          case 'maxi':
            counts.up = randomNumber(16) + 3;
            counts.min = randomNumber(4) + 1;
            counts.down = randomNumber(64) + 3;
            break;
          default:
            counts.up = randomNumber(8) + 1;
            counts.mid = randomNumber(6) / 2;
            counts.down = randomNumber(8) + 1;
            break;
          }
    
          var arr = ["up", "mid", "down"];
          for (var d in arr) {
            var index = arr[d];
            for (var i = 0 ; i <= counts[index]; i++) {
              if (options[index]) {
                result = result + soul[index][randomNumber(soul[index].length)];
              }
            }
          }
        }
        return result;
      }
      // don't summon him
      return heComes(text);
    }
    
  provide("colors/lib/custom/zalgo", module.exports);
}(global));

// pakmanager:colors/lib/maps/america
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  var colors =  require('colors/lib/colors');
    
    module['exports'] = (function() {
      return function (letter, i, exploded) {
        if(letter === " ") return letter;
        switch(i%3) {
          case 0: return colors.red(letter);
          case 1: return colors.white(letter)
          case 2: return colors.blue(letter)
        }
      }
    })();
  provide("colors/lib/maps/america", module.exports);
}(global));

// pakmanager:colors/lib/maps/zebra
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  var colors =  require('colors/lib/colors');
    
    module['exports'] = function (letter, i, exploded) {
      return i % 2 === 0 ? letter : colors.inverse(letter);
    };
  provide("colors/lib/maps/zebra", module.exports);
}(global));

// pakmanager:colors/lib/maps/rainbow
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  var colors =  require('colors/lib/colors');
    
    module['exports'] = (function () {
      var rainbowColors = ['red', 'yellow', 'green', 'blue', 'magenta']; //RoY G BiV
      return function (letter, i, exploded) {
        if (letter === " ") {
          return letter;
        } else {
          return colors[rainbowColors[i++ % rainbowColors.length]](letter);
        }
      };
    })();
    
    
  provide("colors/lib/maps/rainbow", module.exports);
}(global));

// pakmanager:colors/lib/maps/random
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  var colors =  require('colors/lib/colors');
    
    module['exports'] = (function () {
      var available = ['underline', 'inverse', 'grey', 'yellow', 'red', 'green', 'blue', 'white', 'cyan', 'magenta'];
      return function(letter, i, exploded) {
        return letter === " " ? letter : colors[available[Math.round(Math.random() * (available.length - 1))]](letter);
      };
    })();
  provide("colors/lib/maps/random", module.exports);
}(global));

// pakmanager:colors/lib/colors
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  /*
    
    The MIT License (MIT)
    
    Original Library 
      - Copyright (c) Marak Squires
    
    Additional functionality
     - Copyright (c) Sindre Sorhus <sindresorhus@gmail.com> (sindresorhus.com)
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
    
    */
    
    var colors = {};
    module['exports'] = colors;
    
    colors.themes = {};
    
    var ansiStyles = colors.styles =  require('colors/lib/styles');
    var defineProps = Object.defineProperties;
    
    colors.supportsColor =  require('colors/lib/system/supports-colors');
    
    if (typeof colors.enabled === "undefined") {
      colors.enabled = colors.supportsColor;
    }
    
    colors.stripColors = colors.strip = function(str){
      return ("" + str).replace(/\x1B\[\d+m/g, '');
    };
    
    
    var stylize = colors.stylize = function stylize (str, style) {
      return ansiStyles[style].open + str + ansiStyles[style].close;
    }
    
    var matchOperatorsRe = /[|\\{}()[\]^$+*?.]/g;
    var escapeStringRegexp = function (str) {
      if (typeof str !== 'string') {
        throw new TypeError('Expected a string');
      }
      return str.replace(matchOperatorsRe,  '\\$&');
    }
    
    function build(_styles) {
      var builder = function builder() {
        return applyStyle.apply(builder, arguments);
      };
      builder._styles = _styles;
      // __proto__ is used because we must return a function, but there is
      // no way to create a function with a different prototype.
      builder.__proto__ = proto;
      return builder;
    }
    
    var styles = (function () {
      var ret = {};
      ansiStyles.grey = ansiStyles.gray;
      Object.keys(ansiStyles).forEach(function (key) {
        ansiStyles[key].closeRe = new RegExp(escapeStringRegexp(ansiStyles[key].close), 'g');
        ret[key] = {
          get: function () {
            return build(this._styles.concat(key));
          }
        };
      });
      return ret;
    })();
    
    var proto = defineProps(function colors() {}, styles);
    
    function applyStyle() {
      var args = arguments;
      var argsLen = args.length;
      var str = argsLen !== 0 && String(arguments[0]);
      if (argsLen > 1) {
        for (var a = 1; a < argsLen; a++) {
          str += ' ' + args[a];
        }
      }
    
      if (!colors.enabled || !str) {
        return str;
      }
    
      var nestedStyles = this._styles;
    
      var i = nestedStyles.length;
      while (i--) {
        var code = ansiStyles[nestedStyles[i]];
        str = code.open + str.replace(code.closeRe, code.open) + code.close;
      }
    
      return str;
    }
    
    function applyTheme (theme) {
      for (var style in theme) {
        (function(style){
          colors[style] = function(str){
            return colors[theme[style]](str);
          };
        })(style)
      }
    }
    
    colors.setTheme = function (theme) {
      if (typeof theme === 'string') {
        try {
          colors.themes[theme] = require(theme);
          applyTheme(colors.themes[theme]);
          return colors.themes[theme];
        } catch (err) {
          console.log(err);
          return err;
        }
      } else {
        applyTheme(theme);
      }
    };
    
    function init() {
      var ret = {};
      Object.keys(styles).forEach(function (name) {
        ret[name] = {
          get: function () {
            return build([name]);
          }
        };
      });
      return ret;
    }
    
    var sequencer = function sequencer (map, str) {
      var exploded = str.split(""), i = 0;
      exploded = exploded.map(map);
      return exploded.join("");
    };
    
    // custom formatter methods
    colors.trap =  require('colors/lib/custom/trap');
    colors.zalgo =  require('colors/lib/custom/zalgo');
    
    // maps
    colors.maps = {};
    colors.maps.america =  require('colors/lib/maps/america');
    colors.maps.zebra =  require('colors/lib/maps/zebra');
    colors.maps.rainbow =  require('colors/lib/maps/rainbow');
    colors.maps.random =  require('colors/lib/maps/random')
    
    for (var map in colors.maps) {
      (function(map){
        colors[map] = function (str) {
          return sequencer(colors.maps[map], str);
        }
      })(map)
    }
    
    defineProps(colors, init());
  provide("colors/lib/colors", module.exports);
}(global));

// pakmanager:colors/lib/extendStringPrototype
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  var colors =  require('colors/lib/colors'),
        styles =  require('colors/lib/styles');
    
    module['exports'] = function () {
    
      //
      // Extends prototype of native string object to allow for "foo".red syntax
      //
      var addProperty = function (color, func) {
        String.prototype.__defineGetter__(color, func);
      };
    
      var sequencer = function sequencer (map, str) {
          return function () {
            var exploded = this.split(""), i = 0;
            exploded = exploded.map(map);
            return exploded.join("");
          }
      };
    
      var stylize = function stylize (str, style) {
        return styles[style].open + str + styles[style].close;
      }
    
      addProperty('strip', function () {
        return colors.strip(this);
      });
    
      addProperty('stripColors', function () {
        return colors.strip(this);
      });
    
      addProperty("trap", function(){
        return colors.trap(this);
      });
    
      addProperty("zalgo", function(){
        return colors.zalgo(this);
      });
    
      addProperty("zebra", function(){
        return colors.zebra(this);
      });
    
      addProperty("rainbow", function(){
        return colors.rainbow(this);
      });
    
      addProperty("random", function(){
        return colors.random(this);
      });
    
      addProperty("america", function(){
        return colors.america(this);
      });
    
      //
      // Iterate through all default styles and colors
      //
      var x = Object.keys(colors.styles);
      x.forEach(function (style) {
        addProperty(style, function () {
          return stylize(this, style);
        });
      });
    
      function applyTheme(theme) {
        //
        // Remark: This is a list of methods that exist
        // on String that you should not overwrite.
        //
        var stringPrototypeBlacklist = [
          '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__', 'charAt', 'constructor',
          'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString', 'toString', 'valueOf', 'charCodeAt',
          'indexOf', 'lastIndexof', 'length', 'localeCompare', 'match', 'replace', 'search', 'slice', 'split', 'substring',
          'toLocaleLowerCase', 'toLocaleUpperCase', 'toLowerCase', 'toUpperCase', 'trim', 'trimLeft', 'trimRight'
        ];
    
        Object.keys(theme).forEach(function (prop) {
          if (stringPrototypeBlacklist.indexOf(prop) !== -1) {
            console.log('warn: '.red + ('String.prototype' + prop).magenta + ' is probably something you don\'t want to override. Ignoring style name');
          }
          else {
            if (typeof(theme[prop]) === 'string') {
              colors[prop] = colors[theme[prop]];
              addProperty(prop, function () {
                return colors[theme[prop]](this);
              });
            }
            else {
              addProperty(prop, function () {
                var ret = this;
                for (var t = 0; t < theme[prop].length; t++) {
                  ret = exports[theme[prop][t]](ret);
                }
                return ret;
              });
            }
          }
        });
      }
    
      colors.setTheme = function (theme) {
        if (typeof theme === 'string') {
          try {
            colors.themes[theme] = require(theme);
            applyTheme(colors.themes[theme]);
            return colors.themes[theme];
          } catch (err) {
            console.log(err);
            return err;
          }
        } else {
          applyTheme(theme);
        }
      };
    
    };
  provide("colors/lib/extendStringPrototype", module.exports);
}(global));

// pakmanager:colors
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  var colors =  require('colors/lib/colors');
    module['exports'] = colors;
    
    // Remark: By default, colors will add style properties to String.prototype
    //
    // If you don't wish to extend String.prototype you can do this instead and native String will not be touched
    //
    //   var colors = require('colors/safe);
    //   colors.red("foo")
    //
    //
    var extendStringPrototype =  require('colors/lib/extendStringPrototype')();
  provide("colors", module.exports);
}(global));

// pakmanager:translate/languages
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // exports a method "getLangs" that turns a hash of Language / ShortCode objects
    var getLangs = (typeof exports !== "undefined" ? exports : window).getLangs = function() { return {"Afrikaans":"af","Albanian":"sq","Arabic":"ar","Armenian ALPHA":"hy","Azerbaijani ALPHA":"az","Basque ALPHA":"eu","Belarusian":"be","Bulgarian":"bg","Catalan":"ca","Chinese (Simplified)":"zh-CN","Chinese (Traditional)":"zh-TW","Croatian":"hr","Czech":"cs","Danish":"da","Dutch":"nl","English":"en","Estonian":"et","Filipino":"tl","Finnish":"fi","French":"fr","Galician":"gl","Georgian ALPHA":"ka","German":"de","Greek":"el","Haitian Creole ALPHA":"ht","Hebrew":"iw","Hindi":"hi","Hungarian":"hu","Icelandic":"is","Indonesian":"id","Irish":"ga","Italian":"it","Japanese":"ja","Korean":"ko","Latvian":"lv","Lithuanian":"lt","Macedonian":"mk","Malay":"ms","Maltese":"mt","Norwegian":"no","Persian":"fa","Polish":"pl","Portuguese":"pt","Romanian":"ro","Russian":"ru","Serbian":"sr","Slovak":"sk","Slovenian":"sl","Spanish":"es","Swahili":"sw","Swedish":"sv","Thai":"th","Turkish":"tr","Ukrainian":"uk","Urdu ALPHA":"ur","Vietnamese":"vi","Welsh":"cy","Yiddish":"yi"};}
  provide("translate/languages", module.exports);
}(global));

// pakmanager:translate
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  // Andrew Lunny and Marak Squires
    // Mit yo, copy paste us some credit
    
    // simple fn to get the path given text to translate
    var getEnglishTranslatePath = function (lang, text) {
    
      // set the default input and output languages to English and Spanish
      var input = languages[lang.input] || 'en',
      output = languages[lang.output] || 'es';
    
      return '/ajax/services/language/translate?v=1.0'
        + '&langpair=' + encodeURIComponent(input + '|' + output)
        + '&q=' + encodeURIComponent(text);
    }
    
    // stupid if else statement, i felt like actually making his library dual-sided instead of bashing my head against gemini.js 
    if(typeof exports === 'undefined'){
    
      //var languages = window.getLangs();
      var translate = {
        text: function( lang, text, callback) {
    
          // this is not a good curry recipe. needs moar spice
          if(typeof lang !== 'object'){
            callback = text;
            text = lang;
          }
    
          var src = "http://ajax.googleapis.com" + getEnglishTranslatePath(lang, text) + '&callback=translate._callback';
          var script = document.createElement("script");
          script.setAttribute("src", src);
          
          script.onload = function() {
            try{
              var rsp = translate._data.shift();
              callback(rsp.translatedText);
              document.body.removeChild(script);  
            } 
            catch(e) {
              //console.log(e)
            }
          };
          document.body.appendChild(script);
        },
        _data: [],
        _callback: function(rsp) {
          translate._data.push(rsp.responseData);
        }
      };
    }
    else{
    
      var sys = require('sys')
        , http = require('http')
        , request = require('request');
    
      var languages =  require('translate/languages').getLangs();
      var translates = exports;
    
      // translate the text
      exports.text = function (lang, text, callback) {
        // this is not a good curry recipe. needs moar spice
        if(typeof lang !== 'object'){
          callback = text;
          text = lang;
        }
        
        
        var requestOptions = {
          uri: 'http://ajax.googleapis.com' + getEnglishTranslatePath(lang, text)
        };
        
        request(requestOptions, function(err, resp, body){
          if(err){
            return callback(err);
          }
          try {
            var data = JSON.parse(body);
          }
          catch(e) {
            return callback(e)
          }
          if (!data || !data.responseData || data.responseStatus != 200) {
              return callback(new Error(data && data.responseDetails ? data.responseDetails : 'No response data'));
          }
    
          callback(null, data.responseData.translatedText);
        });
      }
    }
    
  provide("translate", module.exports);
}(global));

// pakmanager:say
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
  /*
    
    Copyright (c) 2010 Marak Squires http://github.com/marak/say.js/
    
    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:
    
    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
    LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
    OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
    WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    
    */
    
    var spawn = require('child_process').spawn,
      child;
    
    var say = exports;
    
    if (process.platform === 'darwin') {
      say.speaker = 'say';
    }
    else if (process.platform === 'linux') {
      say.speaker = 'festival';
    }
    
    // say stuff, speak
    exports.speak = function(voice, text, callback) {
      var commands,
        pipedData;
    
      if (arguments.length < 2) {
        console.log('invalid amount of arguments sent to speak()');
        return;
      }
    
      if (process.platform === 'darwin') {
        if (!voice) {
          commands = [ text ];
        } else {
          commands = [ '-v', voice, text];
        }
      } else if (process.platform === 'linux') {
        commands = ['--pipe'];
        pipedData = '(' + voice + ') (SayText \"' + text + '\")';
      }
    
    
      var childD = spawn(say.speaker, commands);
    
      childD.stdin.setEncoding('ascii');
      childD.stderr.setEncoding('ascii');
    
      if (process.platform === 'linux') {
        childD.stdin.end(pipedData);
      }
    
    
      childD.stderr.on('data', function(data){ console.log(data); });
      childD.stdout.on('data', function(data){ console.log(data); });
    
    
      childD.addListener('exit', function (code, signal) {
        if (code === null || signal !== null) {
          console.log('couldnt talk, had an error ' + '[code: '+ code + '] ' + '[signal: ' + signal + ']');
        }
    
        // we could do better than a try / catch here
        try {
          callback();
        } catch(err) {
          // noop
        }
      });
    };
    
    /*
        This code doesnt work....but it could!
        // monkey punch sys.puts to speak, lol
        say.puts();
    
        sys.puts('whats, up dog?'); // did you hear that?
        exports.puts = function(){
    
          var s2 = require('util');
          // don't try this at home
          sys.puts = function(text){
            s2.puts(text);
          };
        }
    */
    
  provide("say", module.exports);
}(global));

// pakmanager:node-red-node-say
(function (context) {
  
  var module = { exports: {} }, exports = module.exports
    , $ = require("ender")
    ;
  
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
    module.exports = function (RED) {
    	'use strict';
    
    	var say = require('say');
    
    	function SayNode(config) {
    		RED.nodes.createNode(this, config);
    		var node = this;
    		this.on('input', function (msg) {
    			say.speak(null, this.name || msg.payload , function() {
    				node.send(msg);
    			});
    		});
    	}
    
    	RED.nodes.registerType('say', SayNode);
    };
    
  provide("node-red-node-say", module.exports);
}(global));