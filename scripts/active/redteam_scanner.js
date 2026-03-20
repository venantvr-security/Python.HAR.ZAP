/**
 * ZAP Active Script: Red Team Scanner
 *
 * Unified red team scanner combining:
 * - Mass Assignment / Hidden Parameter Injection
 * - Unauthenticated Replay Attack
 * - Race Condition Detection (parallel request timing)
 * - IDOR Pattern Detection
 *
 * @author HAR.ZAP Project
 */

var HttpRequestHeader = Java.type('org.parosproxy.paros.network.HttpRequestHeader');
var URI = Java.type('org.apache.commons.httpclient.URI');
var Thread = Java.type('java.lang.Thread');
var System = Java.type('java.lang.System');
var ArrayList = Java.type('java.util.ArrayList');
var Executors = Java.type('java.util.concurrent.Executors');
var Callable = Java.type('java.util.concurrent.Callable');
var TimeUnit = Java.type('java.util.concurrent.TimeUnit');

// ============================================================================
// CONFIGURATION
// ============================================================================

var CONFIG = {
    // Mass Assignment
    hiddenParams: [
        // Admin/privilege escalation
        'admin', 'isAdmin', 'is_admin', 'administrator',
        'role', 'user_role', 'userRole', 'roles',
        'privilege', 'privileges', 'priv', 'level',
        'access_level', 'accessLevel', 'permission', 'permissions',
        // Debug/test modes
        'debug', 'isDebug', 'is_debug', 'test', 'testing',
        'dev', 'development', 'staging', 'internal',
        // Account status
        'verified', 'is_verified', 'active', 'is_active',
        'approved', 'is_approved', 'banned', 'is_banned',
        'premium', 'is_premium', 'vip', 'is_vip',
        // Ownership
        'user_id', 'userId', 'owner_id', 'ownerId',
        'account_id', 'accountId', 'tenant_id', 'tenantId',
        // Financial
        'balance', 'credit', 'discount', 'price',
        'amount', 'total', 'fee', 'commission'
    ],

    testValues: {
        boolean: ['true', '1', 'yes'],
        admin: ['admin', 'administrator', 'root', 'superuser'],
        numeric: ['0', '-1', '999999', '1337']
    },

    // Auth headers to check/remove
    authHeaders: ['Authorization', 'X-Auth-Token', 'X-API-Key', 'Cookie',
                  'X-Access-Token', 'X-Session-Id', 'Bearer'],

    // Race condition
    raceThreads: 5,
    raceTimeoutMs: 5000,

    // Detection thresholds
    lengthDiffThreshold: 100,
    timingDiffThresholdMs: 500
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function log(msg) {
    print('[RedTeam] ' + msg);
}

function getResponseLength(msg) {
    try {
        return msg.getResponseBody().length();
    } catch (e) {
        return 0;
    }
}

function hasAuthHeaders(msg) {
    var header = msg.getRequestHeader();
    for (var i = 0; i < CONFIG.authHeaders.length; i++) {
        if (header.getHeader(CONFIG.authHeaders[i]) !== null) {
            return true;
        }
    }
    return false;
}

function isJsonBody(body) {
    if (!body || body.length === 0) return false;
    var trimmed = body.trim();
    return trimmed.charAt(0) === '{' || trimmed.charAt(0) === '[';
}

function safeJsonParse(body) {
    try {
        return JSON.parse(body);
    } catch (e) {
        return null;
    }
}

function getMethod(msg) {
    return msg.getRequestHeader().getMethod();
}

function getUrl(msg) {
    return msg.getRequestHeader().getURI().toString();
}

// ============================================================================
// MASS ASSIGNMENT SCANNER
// ============================================================================

function scanMassAssignment(as, msg) {
    var method = getMethod(msg);
    var url = getUrl(msg);

    // Only test mutation methods
    if (method !== 'POST' && method !== 'PUT' && method !== 'PATCH') {
        return;
    }

    var body = msg.getRequestBody().toString();
    if (!body || body.length === 0) return;

    // Get baseline response
    var baselineMsg = msg.cloneRequest();
    as.sendAndReceive(baselineMsg);
    var baselineLength = getResponseLength(baselineMsg);
    var baselineStatus = baselineMsg.getResponseHeader().getStatusCode();

    // Test each hidden parameter
    for (var i = 0; i < CONFIG.hiddenParams.length; i++) {
        var param = CONFIG.hiddenParams[i];

        // Determine appropriate test values based on param name
        var values = CONFIG.testValues.boolean;
        if (param.indexOf('id') >= 0 || param.indexOf('Id') >= 0) {
            values = CONFIG.testValues.numeric;
        } else if (param.indexOf('role') >= 0 || param.indexOf('admin') >= 0) {
            values = CONFIG.testValues.admin;
        }

        for (var j = 0; j < values.length; j++) {
            var value = values[j];
            var testMsg = msg.cloneRequest();
            var newBody = null;

            if (isJsonBody(body)) {
                var json = safeJsonParse(body);
                if (!json) continue;

                // Skip if param already exists
                if (json[param] !== undefined) continue;

                json[param] = value;
                newBody = JSON.stringify(json);
            } else {
                // Form data
                newBody = body + '&' + encodeURIComponent(param) + '=' + encodeURIComponent(value);
            }

            testMsg.setRequestBody(newBody);
            testMsg.getRequestHeader().setContentLength(testMsg.getRequestBody().length());

            as.sendAndReceive(testMsg);

            var testStatus = testMsg.getResponseHeader().getStatusCode();
            var testLength = getResponseLength(testMsg);
            var testBody = testMsg.getResponseBody().toString().toLowerCase();

            // Detection: significant difference or privilege indicators
            var lengthDiff = Math.abs(testLength - baselineLength);
            var statusChanged = testStatus !== baselineStatus && testStatus >= 200 && testStatus < 300;

            var indicators = ['admin', 'administrator', 'elevated', 'granted',
                             'privilege', 'permission', 'role', 'success'];
            var foundIndicator = false;
            var matchedIndicator = '';

            for (var k = 0; k < indicators.length; k++) {
                if (testBody.indexOf(indicators[k]) >= 0) {
                    foundIndicator = true;
                    matchedIndicator = indicators[k];
                    break;
                }
            }

            if (lengthDiff > CONFIG.lengthDiffThreshold || statusChanged || foundIndicator) {
                as.raiseAlert(
                    3,  // High risk
                    2,  // Medium confidence
                    'Mass Assignment - Hidden Parameter Accepted',
                    'The application accepts undocumented parameter "' + param + '" which may allow ' +
                    'privilege escalation or unauthorized data modification.\n\n' +
                    'Baseline length: ' + baselineLength + ', Test length: ' + testLength + '\n' +
                    'Baseline status: ' + baselineStatus + ', Test status: ' + testStatus +
                    (foundIndicator ? '\nIndicator found: "' + matchedIndicator + '"' : ''),
                    url,
                    param,
                    param + '=' + value,
                    '',  // otherInfo
                    'Implement strict parameter whitelisting. Use DTOs or explicit binding. ' +
                    'Never bind request parameters directly to internal objects.',
                    testBody.substring(0, Math.min(500, testBody.length)),
                    testMsg
                );

                // One alert per param is enough
                break;
            }
        }
    }
}

// ============================================================================
// UNAUTHENTICATED REPLAY SCANNER
// ============================================================================

function scanUnauthReplay(as, msg) {
    // Only test authenticated endpoints
    if (!hasAuthHeaders(msg)) {
        return;
    }

    var url = getUrl(msg);
    var method = getMethod(msg);

    // Test 1: Remove all auth headers
    var testMsg1 = msg.cloneRequest();
    for (var i = 0; i < CONFIG.authHeaders.length; i++) {
        testMsg1.getRequestHeader().setHeader(CONFIG.authHeaders[i], null);
    }

    as.sendAndReceive(testMsg1);

    var status1 = testMsg1.getResponseHeader().getStatusCode();
    var body1 = testMsg1.getResponseBody().toString();

    // Success without auth = critical vulnerability
    if (status1 >= 200 && status1 < 300) {
        // Verify it's not just a public endpoint by checking response similarity
        var originalMsg = msg.cloneRequest();
        as.sendAndReceive(originalMsg);
        var originalBody = originalMsg.getResponseBody().toString();

        // If responses are similar, it's truly accessible without auth
        if (Math.abs(body1.length - originalBody.length) < 100) {
            as.raiseAlert(
                3,  // High risk
                3,  // High confidence
                'Broken Authentication - Endpoint Accessible Without Auth',
                'This endpoint returns success (HTTP ' + status1 + ') without any authentication. ' +
                'Original request contained auth headers but they are not required.\n\n' +
                'Method: ' + method + '\n' +
                'Removed headers: ' + CONFIG.authHeaders.join(', '),
                url,
                'Authorization',
                'Removed all auth headers',
                '',
                'Implement proper server-side authentication checks. Verify token presence ' +
                'and validity before processing any request. Do not rely on client-side auth.',
                body1.substring(0, Math.min(300, body1.length)),
                testMsg1
            );
            return;
        }
    }

    // Test 2: Invalid/expired token
    var authHeader = msg.getRequestHeader().getHeader('Authorization');
    if (authHeader !== null) {
        var testMsg2 = msg.cloneRequest();
        testMsg2.getRequestHeader().setHeader('Authorization', 'Bearer invalid_expired_token_12345');

        as.sendAndReceive(testMsg2);

        var status2 = testMsg2.getResponseHeader().getStatusCode();

        if (status2 >= 200 && status2 < 300) {
            as.raiseAlert(
                3,  // High risk
                2,  // Medium confidence
                'Broken Authentication - Invalid Token Accepted',
                'This endpoint accepts invalid/malformed authentication tokens. ' +
                'Server does not properly validate token signature or expiration.',
                url,
                'Authorization',
                'Bearer invalid_expired_token_12345',
                '',
                'Implement proper JWT/token validation including signature verification ' +
                'and expiration checks. Reject all malformed tokens.',
                testMsg2.getResponseBody().toString().substring(0, 300),
                testMsg2
            );
        }
    }
}

// ============================================================================
// RACE CONDITION SCANNER
// ============================================================================

function scanRaceCondition(as, msg) {
    var method = getMethod(msg);
    var url = getUrl(msg);

    // Only test state-changing operations
    if (method !== 'POST' && method !== 'PUT' && method !== 'DELETE') {
        return;
    }

    // Skip if no body (likely not a business operation)
    var body = msg.getRequestBody().toString();
    if (!body || body.length === 0) return;

    // Look for indicators of race-sensitive operations
    var urlLower = url.toLowerCase();
    var bodyLower = body.toLowerCase();

    var sensitivePatterns = [
        'checkout', 'payment', 'transfer', 'withdraw', 'deposit',
        'coupon', 'discount', 'promo', 'redeem', 'apply',
        'cart', 'order', 'purchase', 'buy',
        'balance', 'credit', 'points', 'reward',
        'vote', 'like', 'follow', 'subscribe'
    ];

    var isSensitive = false;
    for (var i = 0; i < sensitivePatterns.length; i++) {
        if (urlLower.indexOf(sensitivePatterns[i]) >= 0 ||
            bodyLower.indexOf(sensitivePatterns[i]) >= 0) {
            isSensitive = true;
            break;
        }
    }

    if (!isSensitive) return;

    // Get baseline (single request)
    var baselineMsg = msg.cloneRequest();
    var startTime = System.currentTimeMillis();
    as.sendAndReceive(baselineMsg);
    var baselineTime = System.currentTimeMillis() - startTime;
    var baselineStatus = baselineMsg.getResponseHeader().getStatusCode();
    var baselineBody = baselineMsg.getResponseBody().toString();

    // Send multiple parallel requests
    var executor = Executors.newFixedThreadPool(CONFIG.raceThreads);
    var futures = new ArrayList();
    var results = [];

    for (var t = 0; t < CONFIG.raceThreads; t++) {
        var callable = new Callable({
            call: function() {
                var raceMsg = msg.cloneRequest();
                var raceStart = System.currentTimeMillis();
                as.sendAndReceive(raceMsg);
                var raceEnd = System.currentTimeMillis();
                return {
                    status: raceMsg.getResponseHeader().getStatusCode(),
                    length: getResponseLength(raceMsg),
                    time: raceEnd - raceStart,
                    body: raceMsg.getResponseBody().toString()
                };
            }
        });
        futures.add(executor.submit(callable));
    }

    // Collect results
    var successCount = 0;
    var responseVariations = {};

    for (var f = 0; f < futures.size(); f++) {
        try {
            var result = futures.get(f).get(CONFIG.raceTimeoutMs, TimeUnit.MILLISECONDS);
            results.push(result);

            if (result.status >= 200 && result.status < 300) {
                successCount++;
            }

            var key = result.status + ':' + result.length;
            responseVariations[key] = (responseVariations[key] || 0) + 1;
        } catch (e) {
            // Timeout or error
        }
    }

    executor.shutdown();

    // Detection: multiple successes on a single-use operation suggests race condition
    var variationCount = Object.keys(responseVariations).length;

    if (successCount > 1 || variationCount > 2) {
        as.raiseAlert(
            2,  // Medium risk
            1,  // Low confidence (needs manual verification)
            'Potential Race Condition - Multiple Concurrent Requests Succeed',
            'Sending ' + CONFIG.raceThreads + ' concurrent requests to this endpoint resulted in ' +
            successCount + ' successful responses with ' + variationCount + ' different response patterns.\n\n' +
            'This may indicate a Time-of-Check-Time-of-Use (TOCTOU) vulnerability allowing:\n' +
            '- Double spending / multiple redemptions\n' +
            '- Bypassing quantity limits\n' +
            '- Inconsistent state updates\n\n' +
            'Results: ' + JSON.stringify(responseVariations),
            url,
            '',
            method + ' x' + CONFIG.raceThreads + ' concurrent',
            'Baseline time: ' + baselineTime + 'ms',
            'Implement proper locking mechanisms:\n' +
            '- Database-level locks (SELECT FOR UPDATE)\n' +
            '- Distributed locks (Redis/Memcached)\n' +
            '- Optimistic locking with version fields\n' +
            '- Idempotency keys for financial operations',
            baselineBody.substring(0, Math.min(200, baselineBody.length)),
            baselineMsg
        );
    }
}

// ============================================================================
// IDOR PATTERN SCANNER
// ============================================================================

function scanIDOR(as, msg) {
    var url = getUrl(msg);
    var method = getMethod(msg);

    // Look for numeric IDs in URL
    var idPattern = /\/(\d{1,10})(?:\/|$|\?)/g;
    var match;
    var ids = [];

    while ((match = idPattern.exec(url)) !== null) {
        ids.push({
            value: match[1],
            index: match.index
        });
    }

    if (ids.length === 0) return;

    // Get baseline
    var baselineMsg = msg.cloneRequest();
    as.sendAndReceive(baselineMsg);
    var baselineStatus = baselineMsg.getResponseHeader().getStatusCode();
    var baselineLength = getResponseLength(baselineMsg);

    // Only proceed if baseline is successful
    if (baselineStatus < 200 || baselineStatus >= 300) return;

    // Test each ID with modifications
    for (var i = 0; i < ids.length; i++) {
        var id = ids[i];
        var originalId = parseInt(id.value);

        // Test values: adjacent IDs, zero, negative
        var testIds = [
            originalId + 1,
            originalId - 1,
            originalId + 100,
            0,
            1
        ];

        for (var j = 0; j < testIds.length; j++) {
            if (testIds[j] === originalId || testIds[j] < 0) continue;

            var newUrl = url.substring(0, id.index + 1) +
                        testIds[j] +
                        url.substring(id.index + 1 + id.value.length);

            try {
                var testMsg = msg.cloneRequest();
                testMsg.getRequestHeader().setURI(new URI(newUrl, true));

                as.sendAndReceive(testMsg);

                var testStatus = testMsg.getResponseHeader().getStatusCode();
                var testLength = getResponseLength(testMsg);
                var testBody = testMsg.getResponseBody().toString();

                // Success with different ID = potential IDOR
                if (testStatus >= 200 && testStatus < 300 && testLength > 50) {
                    // Check it's not the same response (could be same resource)
                    if (Math.abs(testLength - baselineLength) > 20 ||
                        testBody !== baselineMsg.getResponseBody().toString()) {

                        as.raiseAlert(
                            3,  // High risk
                            2,  // Medium confidence
                            'Potential IDOR - Accessible Resource with Modified ID',
                            'Modifying the numeric ID from ' + originalId + ' to ' + testIds[j] +
                            ' returns a successful response with different content.\n\n' +
                            'This may allow unauthorized access to other users\' resources.',
                            newUrl,
                            'id',
                            originalId + ' -> ' + testIds[j],
                            'Original length: ' + baselineLength + ', Modified length: ' + testLength,
                            'Implement proper authorization checks:\n' +
                            '- Verify resource ownership before access\n' +
                            '- Use indirect references (mapping tables)\n' +
                            '- Implement access control lists (ACLs)',
                            testBody.substring(0, Math.min(300, testBody.length)),
                            testMsg
                        );

                        // One alert per ID position is enough
                        break;
                    }
                }
            } catch (e) {
                // Invalid URL, skip
            }
        }
    }
}

// ============================================================================
// MAIN SCAN FUNCTION
// ============================================================================

function scan(as, msg, src) {
    try {
        // Run all scanners
        scanMassAssignment(as, msg);
        scanUnauthReplay(as, msg);
        scanRaceCondition(as, msg);
        scanIDOR(as, msg);
    } catch (e) {
        log('Error: ' + e.message);
    }
}
