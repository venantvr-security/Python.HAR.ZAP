/**
 * ZAP Active Script: Mass Assignment / Hidden Parameter Injection
 *
 * Tests for mass assignment vulnerabilities by injecting common hidden parameters.
 * Arachni-inspired parameter fuzzing for privilege escalation.
 */

function scan(as, msg, src) {
    var URI = Java.type('org.apache.commons.httpclient.URI');

    var url = msg.getRequestHeader().getURI().toString();
    var method = msg.getRequestHeader().getMethod();

    // Hidden parameters commonly used for privilege escalation
    var hiddenParams = [
        'admin', 'isAdmin', 'is_admin',
        'role', 'user_role', 'userRole',
        'debug', 'isDebug', 'is_debug',
        'test', 'isTest', 'is_test',
        'priv', 'privilege', 'privileges',
        'access_level', 'accessLevel',
        'permissions', 'perms',
        'group', 'user_group', 'userGroup'
    ];

    var testValues = ['true', '1', 'admin', 'administrator'];

    // Test each hidden parameter
    for (var i = 0; i < hiddenParams.length; i++) {
        var param = hiddenParams[i];

        for (var j = 0; j < testValues.length; j++) {
            var value = testValues[j];

            var testMsg = msg.cloneRequest();

            if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
                // Inject into request body (JSON)
                var body = testMsg.getRequestBody().toString();

                try {
                    // Try JSON injection
                    if (body.indexOf('{') === 0) {
                        var jsonBody = JSON.parse(body);
                        jsonBody[param] = value;
                        testMsg.setRequestBody(JSON.stringify(jsonBody));
                        testMsg.getRequestHeader().setHeader('Content-Length',
                            String(testMsg.getRequestBody().length()));
                    } else if (body.length > 0) {
                        // Form data injection
                        var newBody = body + '&' + param + '=' + value;
                        testMsg.setRequestBody(newBody);
                        testMsg.getRequestHeader().setHeader('Content-Length',
                            String(testMsg.getRequestBody().length()));
                    }
                } catch (e) {
                    // JSON parse error, skip
                    continue;
                }
            } else if (method === 'GET') {
                // Inject into URL parameters
                var newUrl = url + (url.indexOf('?') > 0 ? '&' : '?') + param + '=' + value;
                try {
                    testMsg.getRequestHeader().setURI(new URI(newUrl, true));
                } catch (e) {
                    continue;
                }
            }

            as.sendAndReceive(testMsg);

            var statusCode = testMsg.getResponseHeader().getStatusCode();
            var responseBody = testMsg.getResponseBody().toString().toLowerCase();

            // Check for privilege escalation indicators
            var indicators = [
                'admin', 'administrator', 'debug mode', 'privileged',
                'elevated', 'superuser', 'root', 'role changed',
                'permission granted', 'access granted'
            ];

            var foundIndicator = false;
            var matchedIndicator = '';

            for (var k = 0; k < indicators.length; k++) {
                if (responseBody.indexOf(indicators[k]) >= 0) {
                    foundIndicator = true;
                    matchedIndicator = indicators[k];
                    break;
                }
            }

            // Also check for different response than original
            if (foundIndicator || statusCode === 200) {
                // Compare with baseline (original request)
                var baselineMsg = msg.cloneRequest();
                as.sendAndReceive(baselineMsg);
                var baselineBody = baselineMsg.getResponseBody().toString();

                // If response differs significantly, flag it
                if (foundIndicator ||
                    Math.abs(responseBody.length - baselineBody.length) > 100) {

                    as.raiseAlert(
                        1,  // High risk
                        'Mass Assignment / Hidden Parameter Injection',
                        'Hidden parameter "' + param + '" affects application behavior. ' +
                        'This may allow privilege escalation or unauthorized access.' +
                        (foundIndicator ? ' Found indicator: "' + matchedIndicator + '"' : ''),
                        method === 'GET' ? newUrl : url,
                        param,
                        param + '=' + value,
                        'Implement parameter whitelisting. Only accept explicitly defined parameters. ' +
                        'Do not blindly bind request parameters to internal objects.',
                        responseBody.substring(0, 300),
                        testMsg
                    );

                    // Only raise one alert per parameter
                    break;
                }
            }
        }
    }
}
