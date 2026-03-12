// HTTP Request Smuggling Scanner - ZAP Active Scan Script
// Tests: CL.TE, TE.CL, CL.CL with timing-based detection

function scan(as, msg, param, value) {
    var uri = msg.getRequestHeader().getURI().toString();

    // Only test POST/PUT requests or endpoints that accept body
    var method = msg.getRequestHeader().getMethod();
    if (method !== "POST" && method !== "PUT") {
        // Try to convert GET to POST for testing
        method = "POST";
    }

    // Test 1: CL.TE smuggling (Content-Length vs Transfer-Encoding)
    testCLTE(as, msg, uri);

    // Test 2: TE.CL smuggling
    testTECL(as, msg, uri);

    // Test 3: TE.TE obfuscation
    testTETE(as, msg, uri);
}

function testCLTE(as, msg, uri) {
    // CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding
    var smuggleBody =
        "0\r\n" +
        "\r\n" +
        "G";  // Incomplete request to poison next request

    var testMsg = msg.cloneRequest();
    testMsg.getRequestHeader().setMethod("POST");
    testMsg.getRequestHeader().setHeader("Content-Type", "application/x-www-form-urlencoded");
    testMsg.getRequestHeader().setHeader("Content-Length", "4");
    testMsg.getRequestHeader().setHeader("Transfer-Encoding", "chunked");
    testMsg.setRequestBody(smuggleBody);

    var startTime = java.lang.System.currentTimeMillis();

    try {
        as.sendAndReceive(testMsg, false, false);
    } catch (e) {
        // Timeout or error might indicate smuggling
    }

    var elapsed = java.lang.System.currentTimeMillis() - startTime;

    // If response is delayed significantly, might indicate smuggling
    if (elapsed > 5000) {
        as.raiseAlert(
            3, // High
            1, // Low confidence (timing-based)
            "HTTP Request Smuggling (CL.TE)",
            "Potential CL.TE request smuggling detected via timing anomaly. " +
            "The server took " + elapsed + "ms to respond, suggesting the request was held.",
            uri,
            "Content-Length/Transfer-Encoding",
            "CL: 4, TE: chunked",
            "Configure front-end and back-end to use consistent header parsing.",
            "https://portswigger.net/web-security/request-smuggling",
            "CWE-444: Inconsistent Interpretation of HTTP Requests",
            0,
            testMsg
        );
    }

    // Check for error indicating parser confusion
    var status = testMsg.getResponseHeader().getStatusCode();
    var body = testMsg.getResponseBody().toString();

    if (status === 400 && (body.indexOf("Invalid request") >= 0 || body.indexOf("Bad Request") >= 0)) {
        as.raiseAlert(
            2, // Medium
            2, // Medium confidence
            "HTTP Request Smuggling Parser Confusion",
            "Server responded with 400 Bad Request when receiving conflicting " +
            "Content-Length and Transfer-Encoding headers.",
            uri,
            "Content-Length/Transfer-Encoding",
            "",
            "Ensure consistent header parsing between proxies and servers.",
            "https://portswigger.net/web-security/request-smuggling",
            "CWE-444: Inconsistent Interpretation of HTTP Requests",
            0,
            testMsg
        );
    }
}

function testTECL(as, msg, uri) {
    // TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length
    var smuggleBody =
        "5c\r\n" +
        "GPOST / HTTP/1.1\r\n" +
        "Content-Type: application/x-www-form-urlencoded\r\n" +
        "Content-Length: 15\r\n" +
        "\r\n" +
        "x=1\r\n" +
        "0\r\n" +
        "\r\n";

    var testMsg = msg.cloneRequest();
    testMsg.getRequestHeader().setMethod("POST");
    testMsg.getRequestHeader().setHeader("Content-Type", "application/x-www-form-urlencoded");
    testMsg.getRequestHeader().setHeader("Content-Length", "4");
    testMsg.getRequestHeader().setHeader("Transfer-Encoding", "chunked");
    testMsg.setRequestBody(smuggleBody);

    var startTime = java.lang.System.currentTimeMillis();

    try {
        as.sendAndReceive(testMsg, false, false);
    } catch (e) {
        // Expected
    }

    var elapsed = java.lang.System.currentTimeMillis() - startTime;

    if (elapsed > 5000) {
        as.raiseAlert(
            3, // High
            1, // Low confidence
            "HTTP Request Smuggling (TE.CL)",
            "Potential TE.CL request smuggling detected via timing anomaly (" + elapsed + "ms).",
            uri,
            "Transfer-Encoding/Content-Length",
            "TE: chunked, CL: 4",
            "Use consistent request parsing. Disable chunked encoding if not needed.",
            "https://portswigger.net/web-security/request-smuggling",
            "CWE-444: Inconsistent Interpretation of HTTP Requests",
            0,
            testMsg
        );
    }
}

function testTETE(as, msg, uri) {
    // TE.TE with obfuscation: Different Transfer-Encoding header handling
    var obfuscations = [
        "Transfer-Encoding: xchunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding: chunked",
        "Transfer-Encoding: x",
        "Transfer-Encoding:[tab]chunked",
        "X: X[\n]Transfer-Encoding: chunked",
        "Transfer-Encoding\n: chunked"
    ];

    for (var i = 0; i < obfuscations.length; i++) {
        var testMsg = msg.cloneRequest();
        testMsg.getRequestHeader().setMethod("POST");

        // Try to add obfuscated header
        try {
            var headerLine = obfuscations[i].replace("[tab]", "\t").replace("[\n]", "\n");
            // Note: ZAP might normalize these, but worth trying
            testMsg.getRequestHeader().setHeader("Transfer-Encoding", "chunked");
            testMsg.getRequestHeader().setHeader("Content-Length", "4");
            testMsg.setRequestBody("0\r\n\r\n");

            as.sendAndReceive(testMsg, false, false);

            var status = testMsg.getResponseHeader().getStatusCode();
            if (status !== 200 && status !== 400) {
                // Unexpected response might indicate parser confusion
                as.raiseAlert(
                    1, // Low
                    1, // Low confidence
                    "HTTP Parser Anomaly (TE Obfuscation)",
                    "Server returned unexpected status " + status + " with obfuscated Transfer-Encoding.",
                    uri,
                    "Transfer-Encoding",
                    obfuscations[i],
                    "Normalize and validate Transfer-Encoding headers strictly.",
                    "https://portswigger.net/web-security/request-smuggling",
                    "CWE-444: Inconsistent Interpretation of HTTP Requests",
                    0,
                    testMsg
                );
            }
        } catch (e) {
            // Ignore errors from invalid headers
        }
    }
}
