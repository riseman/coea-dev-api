function js_content_handler(r) {
    let request = r;

    let authTokenResult = getAuthToken(request);
    let tokenObject = authTokenResult.tokenObject;

    if (!authTokenResult.hasToken || authTokenResult.errors.length || !authTokenResult.tokenObject.groups) {
        r.return(401);
        return;
    }

    if (!tokenObject.groups.includes("testAdmin")) {
        r.return(403);
        return;
    }

    if (tokenObject.groups && tokenObject.groups.includes("testAdmin")) {
        r.return(200);
        return;
    }

   r.return(401);
}

export default {
    js_content_handler
};


function getAuthToken(r) {
    let request = r;

    let result = {
        tokenObject: null,
        get hasToken() {
            return this.tokenObject !== null && this.tokenObject !== undefined;
        },
        errors: [],
        addError(error) {
            this.errors.push(error);
        }
    };

    if (!request.headersIn || !request.headersIn.Authorization) {
        result.addError("Has no token")
        return result;
    }

    var bearer = request.headersIn.Authorization
    var segments = bearer.split(' ');

    if (segments.length != 2) {
        result.addError("Invalid token format")
    }

    var token = segments[1];

    if (!token) {
        result.addError("Invalid token format")
    }

    try {
        var decodedToken = jwt.decode(token, "test", true, 'HS256');
        result.tokenObject = decodedToken;
    }
    catch (ex) {
        result.addError("Invalid token format")
    }

    if (!decodedToken || !decodedToken.groups.length) {
        result.addError("Invalid token format")
    }

    return result;
}



/*
 * jwt-simple
 *
 * JSON Web Token encode and decode module for node.js
 *
 * Copyright(c) 2011 Kazuhito Hokamura
 * MIT Licensed
 */

/**
 * module dependencies
 */
var crypto = require('crypto');


/**
 * support algorithm mapping
 */
var algorithmMap = {
    HS256: 'sha256',
    HS384: 'sha384',
    HS512: 'sha512',
    RS256: 'RSA-SHA256'
};

/**
 * Map algorithm to hmac or sign type, to determine which crypto function to use
 */
var typeMap = {
    HS256: 'hmac',
    HS384: 'hmac',
    HS512: 'hmac',
    RS256: 'sign'
};


/**
 * expose object
 */
var jwt = {};

/**
 * version
 */
jwt.version = '0.5.6';

/**
 * Decode jwt
 *
 * @param {Object} token
 * @param {String} key
 * @param {Boolean} [noVerify]
 * @param {String} [algorithm]
 * @return {Object} payload
 * @api public
 */
jwt.decode = function jwt_decode(token, key, noVerify, algorithm) {
    // check token
    if (!token) {
        throw new Error('No token supplied');
    }
    // check segments
    var segments = token.split('.');
    if (segments.length !== 3) {
        throw new Error('Not enough or too many segments');
    }

    // All segment should be base64
    var headerSeg = segments[0];
    var payloadSeg = segments[1];
    var signatureSeg = segments[2];

    var h = base64urlDecode(headerSeg);
    var p = base64urlDecode(payloadSeg);

    var header = JSON.parse(h);
    var payload = JSON.parse(p);

    if (!noVerify) {
        if (!algorithm && /BEGIN( RSA)? PUBLIC KEY/.test(key.toString())) {
            algorithm = 'RS256';
        }

        var signingMethod = algorithmMap[algorithm || header.alg];
        var signingType = typeMap[algorithm || header.alg];
        if (!signingMethod || !signingType) {
            throw new Error('Algorithm not supported');
        }

        // verify signature. `sign` will return base64 string.
        var signingrequest = [headerSeg, payloadSeg].join('.');
        if (!verify(signingrequest, key, signingMethod, signingType, signatureSeg)) {
            throw new Error('Signature verification failed');
        }

        // Support for nbf and exp claims.
        // According to the RFC, they should be in seconds.
        if (payload.nbf && Date.now() < payload.nbf * 1000) {
            throw new Error('Token not yet active');
        }

        if (payload.exp && Date.now() > payload.exp * 1000) {
            throw new Error('Token expired');
        }
    }

    return payload;
};


/**
 * Encode jwt
 *
 * @param {Object} payload
 * @param {String} key
 * @param {String} algorithm
 * @param {Object} options
 * @return {String} token
 * @api public
 */

function verify(request, key, method, type, signature) {

    if (type === "hmac") {
        return (signature === sign(request, key, method, type));
    }
    else if (type == "sign") {
        return crypto.createVerify(method)
            .update(request)
            .verify(key, base64urlUnescape(signature), 'base64');
    }
    else {
        throw new Error('Algorithm type not recognized');
    }
}

function sign(request, key, method, type) {
    var base64str;
    if (type === "hmac") {
        base64str = crypto.createHmac(method, key).update(request).digest('base64');
    }
    else if (type == "sign") {
        base64str = crypto.createSign(method).update(request).sign(key, 'base64');
    }
    else {
        throw new Error('Algorithm type not recognized');
    }

    var ret = base64urlEscape(base64str);

    //jwt.return.return(200, ret);

    return ret;
}

function base64urlDecode(str) {

    const base64 = str
        .replace(/-/g, '+')
        .replace(/_/g, '/')
        .replace(/\s/g, '');

    const padding = '='.repeat((4 - base64.length % 4) % 4);
    const base64WithPadding = base64 + padding;

    const binaryString = atob(base64WithPadding);
    const bytes = new Uint8Array(binaryString.length);

    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }

    return bytesToString(bytes);


}

function base64urlUnescape(str) {
    str += new Array(5 - str.length % 4).join('=');
    return str.replace(/\-/g, '+').replace(/_/g, '/');
}

function base64urlEncode(str) {
    return str.toString('base64');
}

function base64urlEscape(str) {

    str = str.replace(/\+/g, '-');
    str = str.replace(/\//g, '_');
    str = str.replace(/\=/g, '');
    return str;
}

function bytesFrom(base64String, encoding) {
    if (encoding === 'base64') {
        let binaryString = atob(base64String);
        let bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytesToString(bytes);
    } else {
        throw new Error('Unsupported encoding');
    }
}

function bytesToString(bytes) {
    return String.fromCharCode.apply(null, bytes);
}