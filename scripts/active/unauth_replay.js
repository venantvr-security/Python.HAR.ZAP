/**
 * ZAP Active Script: Unauthenticated Replay Attack
 *
 * Tests if authenticated endpoints remain accessible without auth headers.
 * Arachni-inspired business logic vulnerability detection.
 */

function scan(as, msg, src) {
    var HttpRequestHeader = Java.type('org.parosproxy.paros.network.HttpRequestHeader');
    var URI = Java.type('org.apache.commons.httpclient.URI');

    var originalHeader = msg.getRequestHeader();
    var authHeaders = ['Authorization', 'X-Auth-Token', 'X-API-Key', 'Cookie'];

    // Only test endpoints that originally had auth headers
    var hasAuth = false;
    for (var i = 0; i < authHeaders.length; i++) {
        if (originalHeader.getHeader(authHeaders[i]) !== null) {
            hasAuth = true;
            break;
        }
    }

    if (!hasAuth) {
        return;  // Skip unauthenticated endpoints
    }

    var url = originalHeader.getURI().toString();

    // Test 1: Remove all auth headers
    var testMsg1 = msg.cloneRequest();
    for (var i = 0; i < authHeaders.length; i++) {
        testMsg1.getRequestHeader().setHeader(authHeaders[i], null);
    }

    as.sendAndReceive(testMsg1);

    var statusCode = testMsg1.getResponseHeader().getStatusCode();
    var responseBody = testMsg1.getResponseBody().toString();

    // Success response without auth = vulnerability
    if (statusCode >= 200 && statusCode < 300) {
        as.raiseAlert(
            1,  // High risk
            'Unauthenticated Endpoint Access',
            'Endpoint accessible without authentication headers. ' +
            'Original request required auth, but removing auth headers still returns success.',
            url,
            'Authorization',
            '',  // attack
            'Implement proper authentication checks on server-side. ' +
            'Verify auth token presence and validity before processing requests.',
            responseBody.substring(0, 200),
            testMsg1
        );
        return;
    }

    // Test 2: Invalid/expired token
    if (originalHeader.getHeader('Authorization') !== null) {
        var testMsg2 = msg.cloneRequest();
        testMsg2.getRequestHeader().setHeader('Authorization', 'Bearer invalid_token_12345');

        as.sendAndReceive(testMsg2);

        var statusCode2 = testMsg2.getResponseHeader().getStatusCode();

        if (statusCode2 >= 200 && statusCode2 < 300) {
            as.raiseAlert(
                1,  // High risk
                'Invalid Token Accepted',
                'Endpoint accepts invalid authentication tokens.',
                url,
                'Authorization',
                'Bearer invalid_token_12345',
                'Validate token signature and expiration on server-side.',
                testMsg2.getResponseBody().toString().substring(0, 200),
                testMsg2
            );
        }
    }
}
