// JWT Security Scanner - ZAP Active Scan Script
// Tests: None algorithm, weak signatures, key confusion, expired tokens

var ScriptVars = Java.type('org.zaproxy.zap.extension.script.ScriptVars');
var HttpMessage = Java.type('org.parosproxy.paros.network.HttpMessage');
var URI = Java.type('org.apache.commons.httpclient.URI');

var JWT_PATTERN = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/;

function scan(as, msg, param, value) {
    var auth = msg.getRequestHeader().getHeader("Authorization");
    if (!auth) return;

    var match = JWT_PATTERN.exec(auth);
    if (!match) return;

    var jwt = match[0];
    var parts = jwt.split('.');
    if (parts.length !== 3) return;

    // Decode header
    var header = decodeBase64(parts[0]);
    var payload = decodeBase64(parts[1]);

    if (!header || !payload) return;

    // Test 1: None algorithm
    testNoneAlgorithm(as, msg, parts, payload);

    // Test 2: Algorithm confusion (RS256 -> HS256)
    testAlgorithmConfusion(as, msg, parts, payload);

    // Test 3: Empty signature
    testEmptySignature(as, msg, parts);

    // Test 4: Expired token acceptance
    testExpiredToken(as, msg, parts, payload);
}

function testNoneAlgorithm(as, msg, parts, payload) {
    var noneHeader = base64UrlEncode('{"alg":"none","typ":"JWT"}');
    var noneToken = noneHeader + '.' + parts[1] + '.';

    var testMsg = msg.cloneRequest();
    testMsg.getRequestHeader().setHeader("Authorization", "Bearer " + noneToken);

    as.sendAndReceive(testMsg, false, false);

    var status = testMsg.getResponseHeader().getStatusCode();
    if (status >= 200 && status < 300) {
        as.raiseAlert(
            3, // High risk
            2, // Medium confidence
            "JWT None Algorithm Bypass",
            "The application accepts JWT tokens with 'none' algorithm, " +
            "allowing attackers to forge valid tokens without a signature.",
            msg.getRequestHeader().getURI().toString(),
            "Authorization header",
            noneToken,
            "Reject tokens with 'none' algorithm. Validate algorithm server-side.",
            "https://cwe.mitre.org/data/definitions/347.html",
            "CWE-347: Improper Verification of Cryptographic Signature",
            0,
            testMsg
        );
    }
}

function testAlgorithmConfusion(as, msg, parts, payload) {
    // Change RS256 to HS256 with public key as secret
    var confusedHeader = base64UrlEncode('{"alg":"HS256","typ":"JWT"}');
    var confusedToken = confusedHeader + '.' + parts[1] + '.' + parts[2];

    var testMsg = msg.cloneRequest();
    testMsg.getRequestHeader().setHeader("Authorization", "Bearer " + confusedToken);

    as.sendAndReceive(testMsg, false, false);

    var status = testMsg.getResponseHeader().getStatusCode();
    if (status >= 200 && status < 300) {
        as.raiseAlert(
            3, // High
            1, // Low confidence
            "JWT Algorithm Confusion",
            "The application may be vulnerable to algorithm confusion attacks " +
            "where RS256 tokens can be verified as HS256 using the public key.",
            msg.getRequestHeader().getURI().toString(),
            "Authorization header",
            confusedToken,
            "Explicitly verify the expected algorithm server-side.",
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
            0,
            testMsg
        );
    }
}

function testEmptySignature(as, msg, parts) {
    var emptyToken = parts[0] + '.' + parts[1] + '.';

    var testMsg = msg.cloneRequest();
    testMsg.getRequestHeader().setHeader("Authorization", "Bearer " + emptyToken);

    as.sendAndReceive(testMsg, false, false);

    var status = testMsg.getResponseHeader().getStatusCode();
    if (status >= 200 && status < 300) {
        as.raiseAlert(
            3, // High
            2, // Medium confidence
            "JWT Empty Signature Accepted",
            "The application accepts JWT tokens with empty signatures.",
            msg.getRequestHeader().getURI().toString(),
            "Authorization header",
            emptyToken,
            "Always verify JWT signatures server-side.",
            "https://cwe.mitre.org/data/definitions/347.html",
            "CWE-347: Improper Verification of Cryptographic Signature",
            0,
            testMsg
        );
    }
}

function testExpiredToken(as, msg, parts, payload) {
    try {
        var payloadObj = JSON.parse(payload);
        if (payloadObj.exp) {
            // Token has expiry, check if server validates it
            var now = Math.floor(Date.now() / 1000);
            if (payloadObj.exp < now) {
                // Token already expired, test if still accepted
                var testMsg = msg.cloneRequest();
                as.sendAndReceive(testMsg, false, false);

                var status = testMsg.getResponseHeader().getStatusCode();
                if (status >= 200 && status < 300) {
                    as.raiseAlert(
                        2, // Medium
                        2, // Medium confidence
                        "Expired JWT Token Accepted",
                        "The application accepts expired JWT tokens (exp: " + payloadObj.exp + ").",
                        msg.getRequestHeader().getURI().toString(),
                        "Authorization header",
                        "",
                        "Validate JWT expiration (exp claim) server-side.",
                        "https://cwe.mitre.org/data/definitions/613.html",
                        "CWE-613: Insufficient Session Expiration",
                        0,
                        testMsg
                    );
                }
            }
        }
    } catch (e) {
        // Ignore JSON parse errors
    }
}

function decodeBase64(str) {
    try {
        // Add padding if needed
        var pad = str.length % 4;
        if (pad) str += '===='.substring(pad);
        str = str.replace(/-/g, '+').replace(/_/g, '/');

        var Base64 = Java.type('java.util.Base64');
        var decoded = Base64.getDecoder().decode(str);
        return new java.lang.String(decoded, 'UTF-8');
    } catch (e) {
        return null;
    }
}

function base64UrlEncode(str) {
    var Base64 = Java.type('java.util.Base64');
    var bytes = new java.lang.String(str).getBytes('UTF-8');
    var encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    return encoded;
}
