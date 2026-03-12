// Cache Poisoning Scanner - ZAP Active Scan Script
// Tests: Unkeyed headers, web cache deception, parameter pollution

function scan(as, msg, param, value) {
    var uri = msg.getRequestHeader().getURI().toString();

    // Test 1: Unkeyed headers
    testUnkeyedHeaders(as, msg, uri);

    // Test 2: Web cache deception
    testWebCacheDeception(as, msg, uri);

    // Test 3: Fat GET / parameter cloaking
    testParameterCloaking(as, msg, uri);
}

function testUnkeyedHeaders(as, msg, uri) {
    var unkeyedHeaders = [
        {"name": "X-Forwarded-Host", "value": "evil.com"},
        {"name": "X-Forwarded-Scheme", "value": "nothttps"},
        {"name": "X-Original-URL", "value": "/admin"},
        {"name": "X-Rewrite-URL", "value": "/admin"},
        {"name": "X-Host", "value": "evil.com"},
        {"name": "X-Forwarded-Server", "value": "evil.com"},
        {"name": "X-HTTP-Method-Override", "value": "DELETE"},
        {"name": "X-Custom-IP-Authorization", "value": "127.0.0.1"}
    ];

    for (var i = 0; i < unkeyedHeaders.length; i++) {
        var header = unkeyedHeaders[i];
        var testMsg = msg.cloneRequest();
        testMsg.getRequestHeader().setHeader(header.name, header.value);

        // Add cache buster
        var buster = "cb=" + java.lang.System.currentTimeMillis();
        var currentUri = testMsg.getRequestHeader().getURI().toString();
        var separator = currentUri.indexOf("?") >= 0 ? "&" : "?";
        testMsg.getRequestHeader().getURI().setQuery(
            testMsg.getRequestHeader().getURI().getQuery() + separator + buster
        );

        as.sendAndReceive(testMsg, false, false);

        var body = testMsg.getResponseBody().toString();

        // Check if header value is reflected in response
        if (body.indexOf(header.value) >= 0) {
            // Make second request without the header to check if cached
            var verifyMsg = msg.cloneRequest();
            verifyMsg.getRequestHeader().getURI().setQuery(
                verifyMsg.getRequestHeader().getURI().getQuery() + separator + buster
            );

            as.sendAndReceive(verifyMsg, false, false);

            var verifyBody = verifyMsg.getResponseBody().toString();

            if (verifyBody.indexOf(header.value) >= 0) {
                as.raiseAlert(
                    3, // High
                    2, // Medium confidence
                    "Web Cache Poisoning via " + header.name,
                    "The " + header.name + " header is reflected in the response and appears " +
                    "to be cached. Attackers can poison the cache to serve malicious content.",
                    uri,
                    header.name,
                    header.value,
                    "Include " + header.name + " in the cache key or reject unexpected headers.",
                    "https://portswigger.net/web-security/web-cache-poisoning",
                    "CWE-349: Acceptance of Extraneous Untrusted Data With Trusted Data",
                    0,
                    testMsg
                );
            } else {
                // Reflected but not cached
                as.raiseAlert(
                    1, // Low
                    2, // Medium confidence
                    "Unkeyed Header Reflection: " + header.name,
                    "The " + header.name + " header is reflected in the response. " +
                    "If caching is present, this could lead to cache poisoning.",
                    uri,
                    header.name,
                    header.value,
                    "Avoid reflecting unkeyed headers or include them in cache key.",
                    "https://portswigger.net/web-security/web-cache-poisoning",
                    "CWE-349: Acceptance of Extraneous Untrusted Data With Trusted Data",
                    0,
                    testMsg
                );
            }
        }
    }
}

function testWebCacheDeception(as, msg, uri) {
    // Test for web cache deception paths
    var deceptionPaths = [
        "/nonexistent.css",
        "/nonexistent.js",
        "/nonexistent.png",
        "/anything.css",
        "/../static/anything.js"
    ];

    // Only test on pages that might contain sensitive data
    var sensitivePatterns = [
        "account", "profile", "dashboard", "user", "admin",
        "settings", "api", "private"
    ];

    var isSensitive = false;
    for (var i = 0; i < sensitivePatterns.length; i++) {
        if (uri.toLowerCase().indexOf(sensitivePatterns[i]) >= 0) {
            isSensitive = true;
            break;
        }
    }

    if (!isSensitive) return;

    for (var j = 0; j < deceptionPaths.length; j++) {
        var path = deceptionPaths[j];
        var testMsg = msg.cloneRequest();

        // Append deception path to URL
        var currentUri = testMsg.getRequestHeader().getURI();
        var currentPath = currentUri.getPath() || "/";
        currentUri.setPath(currentPath + path);

        as.sendAndReceive(testMsg, false, false);

        var status = testMsg.getResponseHeader().getStatusCode();
        var cacheControl = testMsg.getResponseHeader().getHeader("Cache-Control");
        var body = testMsg.getResponseBody().toString();

        // Check if sensitive content is returned with cacheable response
        if (status === 200 && body.length > 100) {
            var isCacheable = !cacheControl ||
                              cacheControl.indexOf("no-store") < 0 ||
                              cacheControl.indexOf("private") < 0;

            if (isCacheable) {
                as.raiseAlert(
                    2, // Medium
                    1, // Low confidence
                    "Potential Web Cache Deception",
                    "Appending a static file extension to a dynamic URL returns the same " +
                    "content without cache-control restrictions. This could allow an attacker " +
                    "to cache sensitive user data.",
                    uri + path,
                    "URL path",
                    path,
                    "Set Cache-Control: no-store, private on sensitive pages. " +
                    "Validate file extensions server-side.",
                    "https://portswigger.net/research/practical-web-cache-poisoning",
                    "CWE-525: Use of Web Browser Cache Containing Sensitive Information",
                    0,
                    testMsg
                );
            }
        }
    }
}

function testParameterCloaking(as, msg, uri) {
    // Test for parameter pollution / fat GET
    var testMsg = msg.cloneRequest();
    testMsg.getRequestHeader().setMethod("GET");

    // Add body to GET request (fat GET)
    testMsg.setRequestBody("admin=true&debug=1");
    testMsg.getRequestHeader().setHeader("Content-Type", "application/x-www-form-urlencoded");
    testMsg.getRequestHeader().setContentLength(testMsg.getRequestBody().length());

    as.sendAndReceive(testMsg, false, false);

    var body = testMsg.getResponseBody().toString();
    var status = testMsg.getResponseHeader().getStatusCode();

    // Check if body parameters affected response
    if (body.indexOf("admin") >= 0 || body.indexOf("debug") >= 0 || status !== 200) {
        as.raiseAlert(
            1, // Low
            1, // Low confidence
            "Fat GET Request Processed",
            "The server processes body parameters in GET requests. " +
            "This could lead to cache key normalization attacks.",
            uri,
            "Request body in GET",
            "admin=true&debug=1",
            "Ignore request body in GET requests.",
            "https://portswigger.net/research/practical-web-cache-poisoning",
            "CWE-436: Interpretation Conflict",
            0,
            testMsg
        );
    }
}
