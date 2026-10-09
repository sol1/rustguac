/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

var Guacamole = Guacamole || {};

/**
 * Core object providing abstract communication for Guacamole. This object
 * is a null implementation whose functions do nothing. Guacamole applications
 * should use {@link Guacamole.HTTPTunnel} instead, or implement their own tunnel based
 * on this one.
 * 
 * @constructor
 * @see Guacamole.HTTPTunnel
 */
Guacamole.Tunnel = function() {

    /**
     * Connect to the tunnel with the given optional data. This data is
     * typically used for authentication. The format of data accepted is
     * up to the tunnel implementation.
     * 
     * @param {string} [data]
     *     The data to send to the tunnel when connecting.
     */
    this.connect = function(data) {};
    
    /**
     * Disconnect from the tunnel.
     */
    this.disconnect = function() {};
    
    /**
     * Send the given message through the tunnel to the service on the other
     * side. All messages are guaranteed to be received in the order sent.
     * 
     * @param {...*} elements
     *     The elements of the message to send to the service on the other side
     *     of the tunnel.
     */
    this.sendMessage = function(elements) {};

    /**
     * Changes the stored numeric state of this tunnel, firing the onstatechange
     * event if the new state is different and a handler has been defined.
     *
     * @private
     * @param {!number} state
     *     The new state of this tunnel.
     */
    this.setState = function(state) {

        // Notify only if state changes
        if (state !== this.state) {
            this.state = state;
            if (this.onstatechange)
                this.onstatechange(state);
        }

    };

    /**
     * Changes the stored UUID that uniquely identifies this tunnel, firing the
     * onuuid event if a handler has been defined.
     *
     * @private
     * @param {string} uuid
     *     The new state of this tunnel.
     */
    this.setUUID = function setUUID(uuid) {
        this.uuid = uuid;
        if (this.onuuid)
            this.onuuid(uuid);
    };

    /**
     * Returns whether this tunnel is currently connected.
     *
     * @returns {!boolean}
     *     true if this tunnel is currently connected, false otherwise.
     */
    this.isConnected = function isConnected() {
        return this.state === Guacamole.Tunnel.State.OPEN
            || this.state === Guacamole.Tunnel.State.UNSTABLE;
    };

    /**
     * The current state of this tunnel.
     * 
     * @type {!number}
     */
    this.state = Guacamole.Tunnel.State.CLOSED;

    /**
     * The maximum amount of time to wait for data to be received, in
     * milliseconds. If data is not received within this amount of time,
     * the tunnel is closed with an error. The default value is 15000.
     *
     * @type {!number}
     */
    this.receiveTimeout = 15000;

    /**
     * The amount of time to wait for data to be received before considering
     * the connection to be unstable, in milliseconds. If data is not received
     * within this amount of time, the tunnel status is updated to warn that
     * the connection appears unresponsive and may close. The default value is
     * 1500.
     * 
     * @type {!number}
     */
    this.unstableThreshold = 1500;

    /**
     * The UUID uniquely identifying this tunnel. If not yet known, this will
     * be null.
     *
     * @type {string}
     */
    this.uuid = null;

    /**
     * Fired when the UUID that uniquely identifies this tunnel is known.
     *
     * @event
     * @param {!string}
     *     The UUID uniquely identifying this tunnel.
     */
    this.onuuid = null;

    /**
     * Fired whenever an error is encountered by the tunnel.
     * 
     * @event
     * @param {!Guacamole.Status} status
     *     A status object which describes the error.
     */
    this.onerror = null;

    /**
     * Fired whenever the state of the tunnel changes.
     * 
     * @event
     * @param {!number} state
     *     The new state of the client.
     */
    this.onstatechange = null;

    /**
     * Fired once for every complete Guacamole instruction received, in order.
     * 
     * @event
     * @param {!string} opcode
     *     The Guacamole instruction opcode.
     *
     * @param {!string[]} parameters
     *     The parameters provided for the instruction, if any.
     */
    this.oninstruction = null;

    /**
     * Fired when a binary blob frame is received, if the tunnel implementation
     * supports one. Carries the stream index and the raw payload, in place of
     * the base64 a "blob" instruction would have carried.
     *
     * @event
     * @param {!number} index
     *     The index of the stream the payload belongs to.
     *
     * @param {!ArrayBuffer} payload
     *     The blob payload, already decoded.
     */
    this.onbinary = null;

};

/**
 * The Guacamole protocol instruction opcode reserved for arbitrary internal
 * use by tunnel implementations. The value of this opcode is guaranteed to be
 * the empty string (""). Tunnel implementations may use this opcode for any
 * purpose. It is currently used by the HTTP tunnel to mark the end of the HTTP
 * response, and by the WebSocket tunnel to transmit the tunnel UUID and send
 * connection stability test pings/responses.
 *
 * @constant
 * @type {!string}
 */
Guacamole.Tunnel.INTERNAL_DATA_OPCODE = '';

/**
 * All possible tunnel states.
 *
 * @type {!Object.<string, number>}
 */
Guacamole.Tunnel.State = {

    /**
     * A connection is in pending. It is not yet known whether connection was
     * successful.
     * 
     * @type {!number}
     */
    "CONNECTING": 0,

    /**
     * Connection was successful, and data is being received.
     * 
     * @type {!number}
     */
    "OPEN": 1,

    /**
     * The connection is closed. Connection may not have been successful, the
     * tunnel may have been explicitly closed by either side, or an error may
     * have occurred.
     * 
     * @type {!number}
     */
    "CLOSED": 2,

    /**
     * The connection is open, but communication through the tunnel appears to
     * be disrupted, and the connection may close as a result.
     *
     * @type {!number}
     */
    "UNSTABLE" : 3

};

/**
 * Guacamole Tunnel implemented over HTTP via XMLHttpRequest.
 * 
 * @constructor
 * @augments Guacamole.Tunnel
 *
 * @param {!string} tunnelURL
 *     The URL of the HTTP tunneling service.
 *
 * @param {boolean} [crossDomain=false]
 *     Whether tunnel requests will be cross-domain, and thus must use CORS
 *     mechanisms and headers. By default, it is assumed that tunnel requests
 *     will be made to the same domain.
 *
 * @param {object} [extraTunnelHeaders={}]
 *     Key value pairs containing the header names and values of any additional
 *     headers to be sent in tunnel requests. By default, no extra headers will
 *     be added.
 */
Guacamole.HTTPTunnel = function(tunnelURL, crossDomain, extraTunnelHeaders) {

    /**
     * Reference to this HTTP tunnel.
     *
     * @private
     * @type {!Guacamole.HTTPTunnel}
     */
    var tunnel = this;

    var TUNNEL_CONNECT = tunnelURL + "?connect";
    var TUNNEL_READ    = tunnelURL + "?read:";
    var TUNNEL_WRITE   = tunnelURL + "?write:";

    var POLLING_ENABLED     = 1;
    var POLLING_DISABLED    = 0;

    // Default to polling - will be turned off automatically if not needed
    var pollingMode = POLLING_ENABLED;

    var sendingMessages = false;
    var outputMessageBuffer = "";

    // If requests are expected to be cross-domain, the cookie that the HTTP
    // tunnel depends on will only be sent if withCredentials is true
    var withCredentials = !!crossDomain;

    /**
     * The current receive timeout ID, if any.
     *
     * @private
     * @type {number}
     */
    var receive_timeout = null;

    /**
     * The current connection stability timeout ID, if any.
     *
     * @private
     * @type {number}
     */
    var unstableTimeout = null;

    /**
     * The current connection stability test ping interval ID, if any. This
     * will only be set upon successful connection.
     *
     * @private
     * @type {number}
     */
    var pingInterval = null;

    /**
     * The number of milliseconds to wait between connection stability test
     * pings.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var PING_FREQUENCY = 500;

    /**
     * Additional headers to be sent in tunnel requests. This dictionary can be
     * populated with key/value header pairs to pass information such as authentication
     * tokens, etc.
     *
     * @private
     * @type {!object}
     */
    var extraHeaders = extraTunnelHeaders || {};

    /**
     * The name of the HTTP header containing the session token specific to the
     * HTTP tunnel implementation.
     *
     * @private
     * @constant
     * @type {!string}
     */
    var TUNNEL_TOKEN_HEADER = 'Guacamole-Tunnel-Token';

    /**
     * The session token currently assigned to this HTTP tunnel. All distinct
     * HTTP tunnel connections will have their own dedicated session token.
     *
     * @private
     * @type {string}
     */
    var tunnelSessionToken = null;

    /**
     * Adds the configured additional headers to the given request.
     *
     * @private
     * @param {!XMLHttpRequest} request
     *     The request where the configured extra headers will be added.
     *
     * @param {!object} headers
     *     The headers to be added to the request.
     */
    function addExtraHeaders(request, headers) {
        for (var name in headers) {
            request.setRequestHeader(name, headers[name]);
        }
    }

    /**
     * Resets the state of timers tracking network activity and stability. If
     * those timers are not yet started, invoking this function starts them.
     * This function should be invoked when the tunnel is established and every
     * time there is network activity on the tunnel, such that the timers can
     * safely assume the network and/or server are not responding if this
     * function has not been invoked for a significant period of time.
     *
     * @private
     */
    var resetTimers = function resetTimers() {

        // Get rid of old timeouts (if any)
        window.clearTimeout(receive_timeout);
        window.clearTimeout(unstableTimeout);

        // Clear unstable status
        if (tunnel.state === Guacamole.Tunnel.State.UNSTABLE)
            tunnel.setState(Guacamole.Tunnel.State.OPEN);

        // Set new timeout for tracking overall connection timeout
        receive_timeout = window.setTimeout(function () {
            close_tunnel(new Guacamole.Status(Guacamole.Status.Code.UPSTREAM_TIMEOUT, "Server timeout."));
        }, tunnel.receiveTimeout);

        // Set new timeout for tracking suspected connection instability
        unstableTimeout = window.setTimeout(function() {
            tunnel.setState(Guacamole.Tunnel.State.UNSTABLE);
        }, tunnel.unstableThreshold);

    };

    /**
     * Closes this tunnel, signaling the given status and corresponding
     * message, which will be sent to the onerror handler if the status is
     * an error status.
     * 
     * @private
     * @param {!Guacamole.Status} status
     *     The status causing the connection to close;
     */
    function close_tunnel(status) {

        // Get rid of old timeouts (if any)
        window.clearTimeout(receive_timeout);
        window.clearTimeout(unstableTimeout);

        // Cease connection test pings
        window.clearInterval(pingInterval);

        // Ignore if already closed
        if (tunnel.state === Guacamole.Tunnel.State.CLOSED)
            return;

        // If connection closed abnormally, signal error.
        if (status.code !== Guacamole.Status.Code.SUCCESS && tunnel.onerror) {

            // Ignore RESOURCE_NOT_FOUND if we've already connected, as that
            // only signals end-of-stream for the HTTP tunnel.
            if (tunnel.state === Guacamole.Tunnel.State.CONNECTING
                    || status.code !== Guacamole.Status.Code.RESOURCE_NOT_FOUND)
                tunnel.onerror(status);

        }

        // Reset output message buffer
        sendingMessages = false;

        // Mark as closed
        tunnel.setState(Guacamole.Tunnel.State.CLOSED);

    }


    this.sendMessage = function() {

        // Do not attempt to send messages if not connected
        if (!tunnel.isConnected())
            return;

        // Do not attempt to send empty messages
        if (!arguments.length)
            return;

        // Add message to buffer
        outputMessageBuffer += Guacamole.Parser.toInstruction(arguments);

        // Send if not currently sending
        if (!sendingMessages)
            sendPendingMessages();

    };

    function sendPendingMessages() {

        // Do not attempt to send messages if not connected
        if (!tunnel.isConnected())
            return;

        if (outputMessageBuffer.length > 0) {

            sendingMessages = true;

            var message_xmlhttprequest = new XMLHttpRequest();
            message_xmlhttprequest.open("POST", TUNNEL_WRITE + tunnel.uuid);
            message_xmlhttprequest.withCredentials = withCredentials;
            addExtraHeaders(message_xmlhttprequest, extraHeaders);
            message_xmlhttprequest.setRequestHeader("Content-type", "application/octet-stream");
            message_xmlhttprequest.setRequestHeader(TUNNEL_TOKEN_HEADER, tunnelSessionToken);

            // Once response received, send next queued event.
            message_xmlhttprequest.onreadystatechange = function() {
                if (message_xmlhttprequest.readyState === 4) {

                    resetTimers();

                    // If an error occurs during send, handle it
                    if (message_xmlhttprequest.status !== 200)
                        handleHTTPTunnelError(message_xmlhttprequest);

                    // Otherwise, continue the send loop
                    else
                        sendPendingMessages();

                }
            };

            message_xmlhttprequest.send(outputMessageBuffer);
            outputMessageBuffer = ""; // Clear buffer

        }
        else
            sendingMessages = false;

    }

    function handleHTTPTunnelError(xmlhttprequest) {

        // Pull status code directly from headers provided by Guacamole
        var code = parseInt(xmlhttprequest.getResponseHeader("Guacamole-Status-Code"));
        if (code) {
            var message = xmlhttprequest.getResponseHeader("Guacamole-Error-Message");
            close_tunnel(new Guacamole.Status(code, message));
        }

        // Failing that, derive a Guacamole status code from the HTTP status
        // code provided by the browser
        else if (xmlhttprequest.status)
            close_tunnel(new Guacamole.Status(
                Guacamole.Status.Code.fromHTTPCode(xmlhttprequest.status),
                    xmlhttprequest.statusText));

        // Otherwise, assume server is unreachable
        else
            close_tunnel(new Guacamole.Status(Guacamole.Status.Code.UPSTREAM_NOT_FOUND));

    }

    function handleResponse(xmlhttprequest) {

        var interval = null;
        var nextRequest = null;

        var dataUpdateEvents = 0;

        var parser = new Guacamole.Parser();
        parser.oninstruction = function instructionReceived(opcode, args) {

            // Switch to next request if end-of-stream is signalled
            if (opcode === Guacamole.Tunnel.INTERNAL_DATA_OPCODE && args.length === 0) {

                // Reset parser state by simply switching to an entirely new
                // parser
                parser = new Guacamole.Parser();
                parser.oninstruction = instructionReceived;

                // Clean up interval if polling
                if (interval)
                    clearInterval(interval);

                // Clean up object
                xmlhttprequest.onreadystatechange = null;
                xmlhttprequest.abort();

                // Start handling next request
                if (nextRequest)
                    handleResponse(nextRequest);

            }

            // Call instruction handler.
            else if (opcode !== Guacamole.Tunnel.INTERNAL_DATA_OPCODE && tunnel.oninstruction)
                tunnel.oninstruction(opcode, args);

        };

        function parseResponse() {

            // Do not handle responses if not connected
            if (!tunnel.isConnected()) {
                
                // Clean up interval if polling
                if (interval !== null)
                    clearInterval(interval);
                
                return;
            }

            // Do not parse response yet if not ready
            if (xmlhttprequest.readyState < 2) return;

            // Attempt to read status
            var status;
            try { status = xmlhttprequest.status; }

            // If status could not be read, assume successful.
            catch (e) { status = 200; }

            // Start next request as soon as possible IF request was successful
            if (!nextRequest && status === 200)
                nextRequest = makeRequest();

            // Parse stream when data is received and when complete.
            if (xmlhttprequest.readyState === 3 ||
                xmlhttprequest.readyState === 4) {

                resetTimers();

                // Also poll every 30ms (some browsers don't repeatedly call onreadystatechange for new data)
                if (pollingMode === POLLING_ENABLED) {
                    if (xmlhttprequest.readyState === 3 && !interval)
                        interval = setInterval(parseResponse, 30);
                    else if (xmlhttprequest.readyState === 4 && interval)
                        clearInterval(interval);
                }

                // If canceled, stop transfer
                if (xmlhttprequest.status === 0) {
                    tunnel.disconnect();
                    return;
                }

                // Halt on error during request
                else if (xmlhttprequest.status !== 200) {
                    handleHTTPTunnelError(xmlhttprequest);
                    return;
                }

                // Attempt to read in-progress data
                var current;
                try { current = xmlhttprequest.responseText; }

                // Do not attempt to parse if data could not be read
                catch (e) { return; }

                try {
                    parser.receive(current, true);
                }
                catch (e) {
                    close_tunnel(new Guacamole.Status(Guacamole.Status.Code.SERVER_ERROR, e.message));
                    return;
                }

            }

        }

        // If response polling enabled, attempt to detect if still
        // necessary (via wrapping parseResponse())
        if (pollingMode === POLLING_ENABLED) {
            xmlhttprequest.onreadystatechange = function() {

                // If we receive two or more readyState==3 events,
                // there is no need to poll.
                if (xmlhttprequest.readyState === 3) {
                    dataUpdateEvents++;
                    if (dataUpdateEvents >= 2) {
                        pollingMode = POLLING_DISABLED;
                        xmlhttprequest.onreadystatechange = parseResponse;
                    }
                }

                parseResponse();
            };
        }

        // Otherwise, just parse
        else
            xmlhttprequest.onreadystatechange = parseResponse;

        parseResponse();

    }

    /**
     * Arbitrary integer, unique for each tunnel read request.
     * @private
     */
    var request_id = 0;

    function makeRequest() {

        // Make request, increment request ID
        var xmlhttprequest = new XMLHttpRequest();
        xmlhttprequest.open("GET", TUNNEL_READ + tunnel.uuid + ":" + (request_id++));
        xmlhttprequest.setRequestHeader(TUNNEL_TOKEN_HEADER, tunnelSessionToken);
        xmlhttprequest.withCredentials = withCredentials;
        addExtraHeaders(xmlhttprequest, extraHeaders);
        xmlhttprequest.send(null);

        return xmlhttprequest;

    }

    this.connect = function(data) {

        // Start waiting for connect
        resetTimers();

        // Mark the tunnel as connecting
        tunnel.setState(Guacamole.Tunnel.State.CONNECTING);

        // Start tunnel and connect
        var connect_xmlhttprequest = new XMLHttpRequest();
        connect_xmlhttprequest.onreadystatechange = function() {

            if (connect_xmlhttprequest.readyState !== 4)
                return;

            // If failure, throw error
            if (connect_xmlhttprequest.status !== 200) {
                handleHTTPTunnelError(connect_xmlhttprequest);
                return;
            }

            resetTimers();

            // Get UUID and HTTP-specific tunnel session token from response
            tunnel.setUUID(connect_xmlhttprequest.responseText);
            tunnelSessionToken = connect_xmlhttprequest.getResponseHeader(TUNNEL_TOKEN_HEADER);

            // Fail connect attempt if token is not successfully assigned
            if (!tunnelSessionToken) {
                close_tunnel(new Guacamole.Status(Guacamole.Status.Code.UPSTREAM_NOT_FOUND));
                return;
            }

            // Mark as open
            tunnel.setState(Guacamole.Tunnel.State.OPEN);

            // Ping tunnel endpoint regularly to test connection stability
            pingInterval = setInterval(function sendPing() {
                tunnel.sendMessage("nop");
            }, PING_FREQUENCY);

            // Start reading data
            handleResponse(makeRequest());

        };

        connect_xmlhttprequest.open("POST", TUNNEL_CONNECT, true);
        connect_xmlhttprequest.withCredentials = withCredentials;
        addExtraHeaders(connect_xmlhttprequest, extraHeaders);
        connect_xmlhttprequest.setRequestHeader("Content-type", "application/x-www-form-urlencoded; charset=UTF-8");
        connect_xmlhttprequest.send(data);

    };

    this.disconnect = function() {
        close_tunnel(new Guacamole.Status(Guacamole.Status.Code.SUCCESS, "Manually closed."));
    };

};

Guacamole.HTTPTunnel.prototype = new Guacamole.Tunnel();

/**
 * Guacamole Tunnel implemented over WebSocket via XMLHttpRequest.
 * 
 * @constructor
 * @augments Guacamole.Tunnel
 * @param {!string} tunnelURL
 *     The URL of the WebSocket tunneling service.
 */
Guacamole.WebSocketTunnel = function(tunnelURL) {

    /**
     * Bytes of header preceding the payload of a binary blob frame: a version,
     * a type, two reserved bytes, then the stream index as a little-endian
     * uint32. Eight rather than six so the payload starts 8-byte aligned.
     *
     * @constant
     * @type {!number}
     */
    var BINARY_HEADER_LENGTH = 8;

    /**
     * The binary frame format this client understands.
     *
     * @constant
     * @type {!number}
     */
    var BINARY_FRAME_VERSION = 1;

    /**
     * Frame type identifying a blob payload.
     *
     * @constant
     * @type {!number}
     */
    var BINARY_FRAME_BLOB = 0;

    /**
     * Binary blob frames received on this tunnel, and their payload bytes.
     * Present so that whether the conversion is actually running can be read
     * off a live session in one line, rather than inferred from the shape of
     * frames in a network panel:
     *
     *     __guac_tunnel.binaryFrames        // 0 means base64 is still in use
     *
     * @type {!number}
     */
    this.binaryFrames = 0;

    /**
     * Payload bytes received in binary blob frames.
     *
     * @type {!number}
     */
    this.binaryBytes = 0;

    /**
     * Reference to this WebSocket tunnel.
     *
     * @private
     * @type {Guacamole.WebSocketTunnel}
     */
    var tunnel = this;

    /**
     * The parser that this tunnel will use to parse received Guacamole
     * instructions. The parser is created when the tunnel is (re-)connected.
     * Initially, this will be null.
     *
     * @private
     * @type {Guacamole.Parser}
     */
    var parser = null;

    /**
     * The WebSocket used by this tunnel.
     * 
     * @private
     * @type {WebSocket}
     */
    var socket = null;

    /**
     * The current receive timeout ID, if any.
     *
     * @private
     * @type {number}
     */
    var receive_timeout = null;

    /**
     * The current connection stability timeout ID, if any.
     *
     * @private
     * @type {number}
     */
    var unstableTimeout = null;

    /**
     * The current connection stability test ping timeout ID, if any. This
     * will only be set upon successful connection.
     *
     * @private
     * @type {number}
     */
    var pingTimeout = null;

    /**
     * The WebSocket protocol corresponding to the protocol used for the current
     * location.
     *
     * @private
     * @type {!Object.<string, string>}
     */
    var ws_protocol = {
        "http:":  "ws:",
        "https:": "wss:"
    };

    /**
     * The number of milliseconds to wait between connection stability test
     * pings.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var PING_FREQUENCY = 500;

    /**
     * The timestamp of the point in time that the last connection stability
     * test ping was sent, in milliseconds elapsed since midnight of January 1,
     * 1970 UTC.
     *
     * @private
     * @type {!number}
     */
    var lastSentPing = 0;

    // Transform current URL to WebSocket URL

    // If not already a websocket URL
    if (   tunnelURL.substring(0, 3) !== "ws:"
        && tunnelURL.substring(0, 4) !== "wss:") {

        var protocol = ws_protocol[window.location.protocol];

        // If absolute URL, convert to absolute WS URL
        if (tunnelURL.substring(0, 1) === "/")
            tunnelURL =
                protocol
                + "//" + window.location.host
                + tunnelURL;

        // Otherwise, construct absolute from relative URL
        else {

            // Get path from pathname
            var slash = window.location.pathname.lastIndexOf("/");
            var path  = window.location.pathname.substring(0, slash + 1);

            // Construct absolute URL
            tunnelURL =
                protocol
                + "//" + window.location.host
                + path
                + tunnelURL;

        }

    }

    /**
     * Sends an internal "ping" instruction to the Guacamole WebSocket
     * endpoint, verifying network connection stability. If the network is
     * stable, the Guacamole server will receive this instruction and respond
     * with an identical ping.
     *
     * @private
     */
    var sendPing = function sendPing() {
        var currentTime = new Date().getTime();
        tunnel.sendMessage(Guacamole.Tunnel.INTERNAL_DATA_OPCODE, 'ping', currentTime);
        lastSentPing = currentTime;
    };

    /**
     * Resets the state of timers tracking network activity and stability. If
     * those timers are not yet started, invoking this function starts them.
     * This function should be invoked when the tunnel is established and every
     * time there is network activity on the tunnel, such that the timers can
     * safely assume the network and/or server are not responding if this
     * function has not been invoked for a significant period of time.
     *
     * @private
     */
    var resetTimers = function resetTimers() {

        // Get rid of old timeouts (if any)
        window.clearTimeout(receive_timeout);
        window.clearTimeout(unstableTimeout);
        window.clearTimeout(pingTimeout);

        // Clear unstable status
        if (tunnel.state === Guacamole.Tunnel.State.UNSTABLE)
            tunnel.setState(Guacamole.Tunnel.State.OPEN);

        // Set new timeout for tracking overall connection timeout
        receive_timeout = window.setTimeout(function () {
            close_tunnel(new Guacamole.Status(Guacamole.Status.Code.UPSTREAM_TIMEOUT, "Server timeout."));
        }, tunnel.receiveTimeout);

        // Set new timeout for tracking suspected connection instability
        unstableTimeout = window.setTimeout(function() {
            tunnel.setState(Guacamole.Tunnel.State.UNSTABLE);
        }, tunnel.unstableThreshold);

        var currentTime = new Date().getTime();
        var pingDelay = Math.max(lastSentPing + PING_FREQUENCY - currentTime, 0);

        // Ping tunnel endpoint regularly to test connection stability, sending
        // the ping immediately if enough time has already elapsed
        if (pingDelay > 0)
            pingTimeout = window.setTimeout(sendPing, pingDelay);
        else
            sendPing();

    };

    /**
     * Closes this tunnel, signaling the given status and corresponding
     * message, which will be sent to the onerror handler if the status is
     * an error status.
     * 
     * @private
     * @param {!Guacamole.Status} status
     *     The status causing the connection to close;
     */
    function close_tunnel(status) {

        // Get rid of old timeouts (if any)
        window.clearTimeout(receive_timeout);
        window.clearTimeout(unstableTimeout);
        window.clearTimeout(pingTimeout);

        // Ignore if already closed
        if (tunnel.state === Guacamole.Tunnel.State.CLOSED)
            return;

        // If connection closed abnormally, signal error.
        if (status.code !== Guacamole.Status.Code.SUCCESS && tunnel.onerror)
            tunnel.onerror(status);

        // Mark as closed
        tunnel.setState(Guacamole.Tunnel.State.CLOSED);

        socket.close();

    }

    this.sendMessage = function(elements) {

        // Do not attempt to send messages if not connected
        if (!tunnel.isConnected())
            return;

        // Do not attempt to send empty messages
        if (!arguments.length)
            return;

        socket.send(Guacamole.Parser.toInstruction(arguments));

    };

    this.connect = function(data) {

        resetTimers();

        // Mark the tunnel as connecting
        tunnel.setState(Guacamole.Tunnel.State.CONNECTING);

        parser = new Guacamole.Parser();
        parser.oninstruction = function instructionReceived(opcode, args) {

            // Update state and UUID when first instruction received
            if (tunnel.uuid === null) {

                // Associate tunnel UUID if received
                if (opcode === Guacamole.Tunnel.INTERNAL_DATA_OPCODE && args.length === 1)
                    tunnel.setUUID(args[0]);

                // Tunnel is now open and UUID is available
                tunnel.setState(Guacamole.Tunnel.State.OPEN);

            }

            // Call instruction handler.
            if (opcode !== Guacamole.Tunnel.INTERNAL_DATA_OPCODE && tunnel.oninstruction)
                tunnel.oninstruction(opcode, args);

        };

        /**
         * Unpacks a binary blob frame and hands its payload to the tunnel's
         * binary handler. The frame is 8 bytes of header then raw payload:
         * version, type, two reserved bytes, then the stream index as a
         * little-endian uint32. The index travels in the frame rather than
         * being inferred from the preceding text instruction, so this stays
         * stateless and a frame is interpretable on its own.
         *
         * A frame of an unknown version or type is dropped rather than
         * guessed at, since misreading one would corrupt a stream silently.
         *
         * @param {!ArrayBuffer} buffer
         *     The received binary frame.
         */
        function receiveBinary(buffer) {

            if (buffer.byteLength < BINARY_HEADER_LENGTH)
                return;

            var header = new DataView(buffer, 0, BINARY_HEADER_LENGTH);
            if (header.getUint8(0) !== BINARY_FRAME_VERSION
                    || header.getUint8(1) !== BINARY_FRAME_BLOB)
                return;

            var index = header.getUint32(4, true);

            tunnel.binaryFrames++;
            tunnel.binaryBytes += buffer.byteLength - BINARY_HEADER_LENGTH;

            if (tunnel.onbinary)
                tunnel.onbinary(index, buffer.slice(BINARY_HEADER_LENGTH));

        }

        // Connect socket. binaryBlobs advertises that this client can decode
        // binary blob frames; a server that does not know the parameter, or a
        // client older than it, simply keeps exchanging base64 text.
        var query = data ? data + "&binaryBlobs=1" : "binaryBlobs=1";
        socket = new WebSocket(tunnelURL + "?" + query, "guacamole");

        // Binary frames arrive as ArrayBuffers rather than Blobs, so they can
        // be read synchronously and stay in order with the text around them.
        socket.binaryType = "arraybuffer";

        socket.onopen = function(event) {
            resetTimers();
        };

        socket.onclose = function(event) {

            // Pull status code directly from closure reason provided by Guacamole
            if (event.reason)
                close_tunnel(new Guacamole.Status(parseInt(event.reason), event.reason));

            // Failing that, derive a Guacamole status code from the WebSocket
            // status code provided by the browser
            else if (event.code)
                close_tunnel(new Guacamole.Status(Guacamole.Status.Code.fromWebSocketCode(event.code)));

            // Otherwise, assume server is unreachable
            else
                close_tunnel(new Guacamole.Status(Guacamole.Status.Code.UPSTREAM_NOT_FOUND));

        };
        
        socket.onmessage = function(event) {

            resetTimers();

            try {

                // A binary frame carries one stream's blob payload as raw
                // bytes, saving the quarter of the wire that base64 costs.
                // Text and binary frames are delivered in one order, so a
                // blob sent this way arrives between exactly the neighbours
                // it had as text -- nothing here can reorder the stream.
                if (event.data instanceof ArrayBuffer) {
                    receiveBinary(event.data);
                    return;
                }

                parser.receive(event.data);
            }
            catch (e) {
                // An exception thrown by any instruction handler lands here
                // and ends the session, and the status below carries only its
                // message. Kept whole, so onerror can report where it came
                // from -- otherwise a client-side bug reads to the server as a
                // browser that simply hung up.
                tunnel.lastException = e;
                close_tunnel(new Guacamole.Status(Guacamole.Status.Code.SERVER_ERROR, e.message));
            }

        };

    };

    this.disconnect = function() {
        close_tunnel(new Guacamole.Status(Guacamole.Status.Code.SUCCESS, "Manually closed."));
    };

};

Guacamole.WebSocketTunnel.prototype = new Guacamole.Tunnel();

/**
 * Guacamole Tunnel which cycles between all specified tunnels until
 * no tunnels are left. Another tunnel is used if an error occurs but
 * no instructions have been received. If an instruction has been
 * received, or no tunnels remain, the error is passed directly out
 * through the onerror handler (if defined).
 * 
 * @constructor
 * @augments Guacamole.Tunnel
 * @param {...Guacamole.Tunnel} tunnelChain
 *     The tunnels to use, in order of priority.
 */
Guacamole.ChainedTunnel = function(tunnelChain) {

    /**
     * Reference to this chained tunnel.
     * @private
     */
    var chained_tunnel = this;

    /**
     * Data passed in via connect(), to be used for
     * wrapped calls to other tunnels' connect() functions.
     * @private
     */
    var connect_data;

    /**
     * Array of all tunnels passed to this ChainedTunnel through the
     * constructor arguments.
     * @private
     */
    var tunnels = [];

    /**
     * The tunnel committed via commit_tunnel(), if any, or null if no tunnel
     * has yet been committed.
     *
     * @private
     * @type {Guacamole.Tunnel}
     */
    var committedTunnel = null;

    // Load all tunnels into array
    for (var i=0; i<arguments.length; i++)
        tunnels.push(arguments[i]);

    /**
     * Sets the current tunnel.
     * 
     * @private
     * @param {!Guacamole.Tunnel} tunnel
     *     The tunnel to set as the current tunnel.
     */
    function attach(tunnel) {

        // Set own functions to tunnel's functions
        chained_tunnel.disconnect  = tunnel.disconnect;
        chained_tunnel.sendMessage = tunnel.sendMessage;

        /**
         * Fails the currently-attached tunnel, attaching a new tunnel if
         * possible.
         *
         * @private
         * @param {Guacamole.Status} [status]
         *     An object representing the failure that occured in the
         *     currently-attached tunnel, if known.
         *
         * @return {Guacamole.Tunnel}
         *     The next tunnel, or null if there are no more tunnels to try or
         *     if no more tunnels should be tried.
         */
        var failTunnel = function failTunnel(status) {

            // Do not attempt to continue using next tunnel on server timeout
            if (status && status.code === Guacamole.Status.Code.UPSTREAM_TIMEOUT) {
                tunnels = [];
                return null;
            }

            // Get next tunnel
            var next_tunnel = tunnels.shift();

            // If there IS a next tunnel, try using it.
            if (next_tunnel) {
                tunnel.onerror = null;
                tunnel.oninstruction = null;
                tunnel.onstatechange = null;
                attach(next_tunnel);
            }

            return next_tunnel;

        };

        /**
         * Use the current tunnel from this point forward. Do not try any more
         * tunnels, even if the current tunnel fails.
         * 
         * @private
         */
        function commit_tunnel() {

            tunnel.onstatechange = chained_tunnel.onstatechange;
            tunnel.oninstruction = chained_tunnel.oninstruction;
            tunnel.onerror = chained_tunnel.onerror;

            // Assign UUID if already known
            if (tunnel.uuid)
                chained_tunnel.setUUID(tunnel.uuid);

            // Assign any future received UUIDs such that they are
            // accessible from the main uuid property of the chained tunnel
            tunnel.onuuid = function uuidReceived(uuid) {
                chained_tunnel.setUUID(uuid);
            };

            committedTunnel = tunnel;

        }

        // Wrap own onstatechange within current tunnel
        tunnel.onstatechange = function(state) {

            switch (state) {

                // If open, use this tunnel from this point forward.
                case Guacamole.Tunnel.State.OPEN:
                    commit_tunnel();
                    if (chained_tunnel.onstatechange)
                        chained_tunnel.onstatechange(state);
                    break;

                // If closed, mark failure, attempt next tunnel
                case Guacamole.Tunnel.State.CLOSED:
                    if (!failTunnel() && chained_tunnel.onstatechange)
                        chained_tunnel.onstatechange(state);
                    break;
                
            }

        };

        // Wrap own oninstruction within current tunnel
        tunnel.oninstruction = function(opcode, elements) {

            // Accept current tunnel
            commit_tunnel();

            // Invoke handler
            if (chained_tunnel.oninstruction)
                chained_tunnel.oninstruction(opcode, elements);

        };

        // Attach next tunnel on error
        tunnel.onerror = function(status) {

            // Mark failure, attempt next tunnel
            if (!failTunnel(status) && chained_tunnel.onerror)
                chained_tunnel.onerror(status);

        };

        // Attempt connection
        tunnel.connect(connect_data);
        
    }

    this.connect = function(data) {
       
        // Remember connect data
        connect_data = data;

        // Get committed tunnel if exists or the first tunnel on the list
        var next_tunnel = committedTunnel ? committedTunnel : tunnels.shift();

        // Attach first tunnel
        if (next_tunnel)
            attach(next_tunnel);

        // If there IS no first tunnel, error
        else if (chained_tunnel.onerror)
            chained_tunnel.onerror(Guacamole.Status.Code.SERVER_ERROR, "No tunnels to try.");

    };
    
};

Guacamole.ChainedTunnel.prototype = new Guacamole.Tunnel();

/**
 * Guacamole Tunnel which replays a Guacamole protocol dump from a static file
 * received via HTTP. Instructions within the file are parsed and handled as
 * quickly as possible, while the file is being downloaded.
 *
 * @constructor
 * @augments Guacamole.Tunnel
 * @param {!string} url
 *     The URL of a Guacamole protocol dump.
 *
 * @param {boolean} [crossDomain=false]
 *     Whether tunnel requests will be cross-domain, and thus must use CORS
 *     mechanisms and headers. By default, it is assumed that tunnel requests
 *     will be made to the same domain.
 *
 * @param {object} [extraTunnelHeaders={}]
 *     Key value pairs containing the header names and values of any additional
 *     headers to be sent in tunnel requests. By default, no extra headers will
 *     be added.
 */
Guacamole.StaticHTTPTunnel = function StaticHTTPTunnel(url, crossDomain, extraTunnelHeaders) {

    /**
     * Reference to this Guacamole.StaticHTTPTunnel.
     *
     * @private
     */
    var tunnel = this;

    /**
     * AbortController instance which allows the current, in-progress HTTP
     * request to be aborted. If no request is currently in progress, this will
     * be null.
     *
     * @private
     * @type {AbortController}
     */
    var abortController = null;

    /**
     * Additional headers to be sent in tunnel requests. This dictionary can be
     * populated with key/value header pairs to pass information such as authentication
     * tokens, etc.
     *
     * @private
     * @type {!object}
     */
    var extraHeaders = extraTunnelHeaders || {};

    /**
     * The number of bytes in the file being downloaded, or null if this is not
     * known.
     *
     * @type {number}
     */
    this.size = null;

    this.sendMessage = function sendMessage(elements) {
        // Do nothing
    };

    this.connect = function connect(data) {

        // Ensure any existing connection is killed
        tunnel.disconnect();

        // Connection is now starting
        tunnel.setState(Guacamole.Tunnel.State.CONNECTING);

        // Create Guacamole protocol and UTF-8 parsers specifically for this
        // connection
        var parser = new Guacamole.Parser();
        var utf8Parser = new Guacamole.UTF8Parser();

        // Invoke tunnel's oninstruction handler for each parsed instruction
        parser.oninstruction = function instructionReceived(opcode, args) {
            if (tunnel.oninstruction)
                tunnel.oninstruction(opcode, args);
        };

        // Allow new request to be aborted
        abortController = new AbortController();

        // Stream using the Fetch API
        fetch(url, {
            headers : extraHeaders,
            credentials : crossDomain ? 'include' : 'same-origin',
            signal : abortController.signal
        })
        .then(function gotResponse(response) {

            // Reset state and close upon error
            if (!response.ok) {

                if (tunnel.onerror)
                    tunnel.onerror(new Guacamole.Status(
                        Guacamole.Status.Code.fromHTTPCode(response.status), response.statusText));

                tunnel.disconnect();
                return;

            }

            // Report overall size of stream in bytes, if known
            tunnel.size = response.headers.get('Content-Length');

            // Connection is open
            tunnel.setState(Guacamole.Tunnel.State.OPEN);

            var reader = response.body.getReader();
            var processReceivedText = function processReceivedText(result) {

                // Clean up and close when done
                if (result.done) {
                    tunnel.disconnect();
                    return;
                }

                // Parse only the portion of data which is newly received
                parser.receive(utf8Parser.decode(result.value));

                // Continue parsing when next chunk is received
                reader.read().then(processReceivedText);

            };

            // Schedule parse of first chunk
            reader.read().then(processReceivedText);

        });

    };

    this.disconnect = function disconnect() {

        // Abort any in-progress request
        if (abortController) {
            abortController.abort();
            abortController = null;
        }

        // Connection is now closed
        tunnel.setState(Guacamole.Tunnel.State.CLOSED);

    };

};

Guacamole.StaticHTTPTunnel.prototype = new Guacamole.Tunnel();
