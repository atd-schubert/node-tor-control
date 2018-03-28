/*jslint node:true*/

'use strict';

var net = require('net');
var EventEmitter = require('events').EventEmitter;

var stream = require('stream');

/**
 * Tor control class
 * @link https://gitweb.torproject.org/torspec.git/tree/control-spec.txt
 * @param {{}} [opts] - Options
 * @param {string} [opts.host="localhost"] - Host address to tor-control
 * @param {number} [opts.port=9051] - Port of tor-control
 * @param {string} [opts.password=""] - Host address to tor-control (default localhost)
 * @param {string} [opts.path] - Connect by path (alternative way to opts.host and opts.port)
 * @constructor
 */
var TorControl = function TorControl(opts) {
    var self = this;

    EventEmitter.apply(this);

    opts = opts || {};

    if (!opts.hasOwnProperty('path')) {
        opts.port = opts.port || 9051;
        opts.host = opts.host || 'localhost';
    }

    opts.password = opts.password || '';
    if (!opts.hasOwnProperty('persistent')) {
        opts.persistent = false;
    }

    this.connect = function connectTorControl(params, cb) {

        params = params || opts;

        if (this.connection) {
            if (cb) {
                return cb(null, this.connection);
            }
            return;
        }

        if (!params.hasOwnProperty('path')) {
            if (opts.hasOwnProperty('path')) {
                params.path = opts.path;
            } else {
                params.host = params.host || opts.host;
                params.port = params.port || opts.port;
            }
        }

        this.connection = net.connect(params);
        
        //Handling connection errors
        this.connection.once('error', function(err){
            if (cb) {
              cb(new Error("Error connecting to control port: " + err));
            }
        });
        

        // piping events
        this.connection.on('data', function (data) {
            self.emit('data', data);
        });
        this.connection.on('end', function () {
            self.connection = null;
            self.emit('end');
        });

        if (cb) {
            this.connection.once('data', function (data) {
                data = data.toString();
                if (data.substr(0, 3) === '250') {
                    return cb(null, self.connection);
                }
                return cb(new Error('Authentication failed with message: ' + data));
            });
        }

        this.connection.write('AUTHENTICATE "' + (params.password || opts.password) + '"\r\n'); // Chapter 3.5
        return this;
    };

    this.disconnect = function disconnectTorControl(cb, force) {
        if (!this.connection) {
            if (cb) {
                return cb();
            }
            return;
        }
        if (cb) {
            this.connection.once('end', function () {
                return cb();
            });
        }
        if (force) {
            return this.connection.end();
        }
        this.connection.write('QUIT\r\n');
        return this;
    };

    this.isPersistent = function isTorControlPersistent() {
        return !!opts.persistent;
    };
    this.setPersistent = function setTorControlPersistent(value) {
        opts.persistent = !!value;
        return this;
    };

};

TorControl.prototype = {
    '__proto__': EventEmitter.prototype,
    sendCommand: function sendCommandToTorCOntrol(command, cb, keepConnection) {
        var self = this,
            tryDisconnect = function (callback) {
                if (keepConnection || self.isPersistent() || !self.connection) {
                    return callback();
                }
                return self.disconnect(callback);
            };
        return this.connect(null, function (err, connection) {
            if (err) {
                return cb(err);
            }
            connection.once('data', function (data) {
                return tryDisconnect(function () {
                    var messages = [],
                        arr,
                        i;
                    if (cb) {
                        data = data.toString();
                        if (/250 OK\r?\n/.test(data)) {
                            arr = data.split(/\r?\n/);

                            for (i = 0; i < arr.length; i += 1) {
                                if (arr[i] !== '') {
                                    var message = /^250./.test(arr[i]) ? arr[i].substr(4) : arr[i]
                                    messages.push(message);
                                }
                            }
                            return cb(null, {
                                code: 250,
                                messages: messages,
                                data: data
                            });
                        }
                        return cb(new Error(data), {
                            code: parseInt(data.substr(0, 3), 10),
                            message: data.substr(4),
                            data: data
                        });
                    }
                });
            });
            connection.write(command + '\r\n');
        });
    },

    // Config
    setConf: function setConf(request, cb) { // Chapter 3.1
        return this.sendCommand('SETCONF ' + request, cb);
    },
    resetConf: function resetConf(request, cb) { // Chapter 3.2
        return this.sendCommand('RESETCONF ' + request, cb);
    },
    getConf: function getConf(request, cb) { // Chapter 3.3
        return this.sendCommand('GETCONF ' + request, cb);
    },
    getEvents: function getEvents(request, cb) { // Chapter 3.4
        return this.sendCommand('GETEVENTS ' + request, cb);
    },
    saveConf: function saveConf(request, cb) { // Chapter 3.6
        return this.sendCommand('SAVECONF ' + request, cb);
    },

    // Signals:
    signal: function sendSignalToTorCOntrol(signal, cb, keepConnection) { // Chapter 3.7
        return this.sendCommand('SIGNAL ' + signal, cb, keepConnection);
    },
    signalReload: function sendSignalReload(cb) {
        return this.signal('RELOAD', cb, true);
    },
    signalHup: function sendSignalHup(cb) {
        return this.signal('HUP', cb);
    },
    signalShutdown: function sendSignalShutdown(cb) {
        return this.signal('SHUTDOWN', cb, true);
    },
    signalDump: function sendSignalDump(cb) {
        return this.signal('DUMP', cb);
    },
    signalUsr1: function sendSignalUsr1(cb) {
        return this.signal('USR1', cb);
    },
    signalDebug: function sendSignalDegug(cb) {
        return this.signal('DEBUG', cb);
    },
    signalUsr2: function sendSignalUsr2(cb) {
        return this.signal('USR2', cb);
    },
    signalHalt: function sendSignalHalt(cb) {
        return this.signal('HALT', cb, true);
    },
    signalTerm: function sendSignalTerm(cb) {
        return this.signal('TERM', cb, true);
    },
    signalInt: function sendSignalInt(cb) {
        return this.signal('INT', cb);
    },
    signalNewnym: function sendSignalNewNym(cb) {
        return this.signal('NEWNYM', cb);
    },
    signalCleardnscache: function sendSignalClearDnsCache(cb) {
        return this.signal('CLEARDNSCACHE', cb);
    },

    // MapAddress
    mapAddress: function mapAddress(address, cb) { // Chapter 3.8
        return this.sendCommand('MAPADDRESS ' + address, cb);
    },

    // GetInfo
    getInfo: function (request, cb) { // Chapter 3.9
        if (!Array.prototype.isPrototypeOf(request)) {
            request = [request];
        }
        return this.sendCommand('GETINFO ' + request.join(' '), cb);
    },

    // Circuit
    extendCircuit: function (id, superspec, purpose, cb) { // Chapter 3.10
        var str = 'EXTENDCIRCUIT ' + id;
        if (superspec) {
            str += ' ' + superspec;
        }
        if (purpose) {
            str += ' ' + purpose;
        }
        return this.sendCommand(str, cb);
    },
    setCircuitPurpose: function (id, purpose, cb) { // Chapter 3.11
        return this.sendCommand('SETCIRCUITPURPOSE ' + id + ' purpose=' + purpose, cb);
    },


    setRouterPurpose: function (nicknameOrKey, purpose, cb) { // Chapter 3.12
        return this.sendCommand('SETROUTERPURPOSE ' + nicknameOrKey + ' ' + purpose, cb);
    },
    attachStream: function (streamId, circuitId, hop, cb) { // Chapter 3.13
        var str = 'ATTACHSTREAM ' + streamId + ' ' + circuitId;

        if (hop) {
            str += ' ' + hop;
        }

        return this.sendCommand(str, cb);
    },

    // Alias
    getNewCircuit: function sendSignalNewNym(cb) {
        return this.sendSignalNewNym(cb);
    },


    /**
     * @type {stream}
     */
    connection: null,

    // Methods with usage of private vars (opts)
    /**
     * @type {function}
     */
    connect: null,
    /**
     * @type {function}
     */
    disconnect: null,
    /**
     * @type {function}
     */
    isPersistent: null,
    /**
     * @type {function}
     */
    setPersistent: null
};

module.exports = TorControl;
