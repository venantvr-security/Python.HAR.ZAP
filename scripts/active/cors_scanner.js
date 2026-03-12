// CORS Misconfiguration Scanner - ZAP Active Scan Script
// Tests: Origin reflection, null origin, subdomain wildcards, credentials exposure

function scan(as, msg, param, value) {
    var uri = msg.getRequestHeader().getURI().toString();

    // Test 1: Arbitrary origin reflection
    testOriginReflection(as, msg, uri);

    // Test 2: Null origin
    testNullOrigin(as, msg, uri);

    // Test 3: Subdomain bypass
    testSubdomainBypass(as, msg, uri);

    // Test 4: Prefix/suffix bypass
    testPrefixSuffixBypass(as, msg, uri);
}

function testOriginReflection(as, msg, uri) {
    var evilOrigin = "https://evil.com";

    var testMsg = msg.cloneRequest();
    testMsg.getRequestHeader().setHeader("Origin", evilOrigin);

    as.sendAndReceive(testMsg, false, false);

    var acao = testMsg.getResponseHeader().getHeader("Access-Control-Allow-Origin");
    var acac = testMsg.getResponseHeader().getHeader("Access-Control-Allow-Credentials");

    if (acao && acao === evilOrigin) {
        var risk = (acac && acac.toLowerCase() === "true") ? 3 : 2;
        var desc = (acac && acac.toLowerCase() === "true")
            ? "CORS allows arbitrary origins WITH credentials - critical vulnerability!"
            : "CORS reflects arbitrary origins without credential exposure.";

        as.raiseAlert(
            risk,
            3, // High confidence
            "CORS Arbitrary Origin Reflection",
            desc + " Attacker-controlled origins are reflected in Access-Control-Allow-Origin.",
            uri,
            "Origin header",
            evilOrigin,
            "Use a whitelist of allowed origins. Never reflect arbitrary origins.",
            "https://cwe.mitre.org/data/definitions/942.html",
            "CWE-942: Overly Permissive Cross-domain Whitelist",
            0,
            testMsg
        );
    }
}

function testNullOrigin(as, msg, uri) {
    var testMsg = msg.cloneRequest();
    testMsg.getRequestHeader().setHeader("Origin", "null");

    as.sendAndReceive(testMsg, false, false);

    var acao = testMsg.getResponseHeader().getHeader("Access-Control-Allow-Origin");
    var acac = testMsg.getResponseHeader().getHeader("Access-Control-Allow-Credentials");

    if (acao && acao === "null") {
        var risk = (acac && acac.toLowerCase() === "true") ? 3 : 2;

        as.raiseAlert(
            risk,
            3, // High confidence
            "CORS Null Origin Allowed",
            "The application allows 'null' origin which can be triggered from " +
            "sandboxed iframes, data: URIs, and file: URIs. " +
            (acac ? "Credentials are exposed!" : ""),
            uri,
            "Origin header",
            "null",
            "Do not allow 'null' origin in CORS policy.",
            "https://portswigger.net/web-security/cors",
            "CWE-942: Overly Permissive Cross-domain Whitelist",
            0,
            testMsg
        );
    }
}

function testSubdomainBypass(as, msg, uri) {
    // Extract domain from original URL
    var URI = Java.type('org.apache.commons.httpclient.URI');
    var originalUri = new URI(uri, true);
    var host = originalUri.getHost();

    if (!host) return;

    // Try attacker-controlled subdomain
    var evilSubdomain = "evil." + host;
    var evilOrigin = "https://" + evilSubdomain;

    var testMsg = msg.cloneRequest();
    testMsg.getRequestHeader().setHeader("Origin", evilOrigin);

    as.sendAndReceive(testMsg, false, false);

    var acao = testMsg.getResponseHeader().getHeader("Access-Control-Allow-Origin");

    if (acao && acao === evilOrigin) {
        as.raiseAlert(
            2, // Medium
            2, // Medium confidence
            "CORS Subdomain Wildcard",
            "CORS policy allows subdomains. If an attacker can control a subdomain " +
            "(via subdomain takeover or XSS), they can bypass CORS.",
            uri,
            "Origin header",
            evilOrigin,
            "Use exact origin matching instead of subdomain wildcards.",
            "https://portswigger.net/web-security/cors",
            "CWE-942: Overly Permissive Cross-domain Whitelist",
            0,
            testMsg
        );
    }
}

function testPrefixSuffixBypass(as, msg, uri) {
    var URI = Java.type('org.apache.commons.httpclient.URI');
    var originalUri = new URI(uri, true);
    var host = originalUri.getHost();

    if (!host) return;

    // Try prefix bypass (evil-example.com for example.com)
    var prefixBypass = "https://evil-" + host;

    var testMsg = msg.cloneRequest();
    testMsg.getRequestHeader().setHeader("Origin", prefixBypass);

    as.sendAndReceive(testMsg, false, false);

    var acao = testMsg.getResponseHeader().getHeader("Access-Control-Allow-Origin");

    if (acao && acao === prefixBypass) {
        as.raiseAlert(
            2, // Medium
            2, // Medium confidence
            "CORS Prefix/Suffix Bypass",
            "CORS policy uses weak origin validation that can be bypassed " +
            "with attacker-controlled domains (e.g., evil-example.com matches example.com).",
            uri,
            "Origin header",
            prefixBypass,
            "Use exact origin matching, not substring or regex matching.",
            "https://portswigger.net/web-security/cors",
            "CWE-942: Overly Permissive Cross-domain Whitelist",
            0,
            testMsg
        );
    }

    // Try suffix bypass (example.com.evil.com)
    var suffixBypass = "https://" + host + ".evil.com";

    testMsg = msg.cloneRequest();
    testMsg.getRequestHeader().setHeader("Origin", suffixBypass);

    as.sendAndReceive(testMsg, false, false);

    acao = testMsg.getResponseHeader().getHeader("Access-Control-Allow-Origin");

    if (acao && acao === suffixBypass) {
        as.raiseAlert(
            2, // Medium
            2, // Medium confidence
            "CORS Suffix Bypass",
            "CORS policy allows origins ending with the target domain, " +
            "enabling bypass via attacker-controlled domains.",
            uri,
            "Origin header",
            suffixBypass,
            "Use exact origin matching.",
            "https://portswigger.net/web-security/cors",
            "CWE-942: Overly Permissive Cross-domain Whitelist",
            0,
            testMsg
        );
    }
}
