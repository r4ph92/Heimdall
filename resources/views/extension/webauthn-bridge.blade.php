<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Heimdall — Biometric Setup</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: system-ui, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 24px;
        }
        .card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 32px;
            max-width: 400px;
            width: 100%;
            text-align: center;
        }
        h1 { font-size: 1.25rem; font-weight: 600; margin-bottom: 8px; }
        p  { font-size: 0.875rem; color: #94a3b8; margin-bottom: 24px; line-height: 1.5; }
        .icon { font-size: 2.5rem; margin-bottom: 16px; }
        .status {
            font-size: 0.875rem;
            padding: 10px 16px;
            border-radius: 8px;
            margin-top: 16px;
        }
        .status.error   { background: #450a0a; color: #fca5a5; }
        .status.success { background: #052e16; color: #86efac; }
        .status.info    { background: #1e3a5f; color: #93c5fd; }
    </style>
</head>
<body>
<div class="card">
    <div class="icon">🔐</div>
    <h1>Heimdall Biometric</h1>
    <p id="message">Waiting for biometric prompt…</p>
    <div id="status" class="status info">Starting…</div>
</div>

<script>
(async () => {
    const params     = new URLSearchParams(location.search);
    const action     = params.get('action');       // 'register' | 'authenticate'
    const extId      = params.get('ext_id');       // chrome extension ID
    const credIdB64  = params.get('cred_id');      // base64url credential ID (authenticate only)

    const $msg    = document.getElementById('message');
    const $status = document.getElementById('status');

    const PRF_INPUT = new TextEncoder().encode('heimdall-vault-key-v1');

    function b64urlToBytes(b64) {
        const b64std = b64.replace(/-/g, '+').replace(/_/g, '/');
        const bin    = atob(b64std);
        return Uint8Array.from(bin, c => c.charCodeAt(0));
    }

    function bytesToB64url(buf) {
        const bytes = new Uint8Array(buf);
        let bin = '';
        bytes.forEach(b => bin += String.fromCharCode(b));
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    function randomBytes(n) {
        return crypto.getRandomValues(new Uint8Array(n));
    }

    function sendResult(payload) {
        if (extId && chrome?.runtime) {
            chrome.runtime.sendMessage(extId, payload);
        } else {
            // Fallback: postMessage to opener
            window.opener?.postMessage(payload, '*');
        }
    }

    function fail(msg) {
        $msg.textContent  = msg;
        $status.textContent = 'Failed — you can close this tab.';
        $status.className = 'status error';
        sendResult({ type: 'heimdall-prf', error: msg });
    }

    try {
        if (action === 'register') {
            $msg.textContent = 'Follow the biometric prompt to register your authenticator.';

            const credential = await navigator.credentials.create({
                publicKey: {
                    challenge: randomBytes(32),
                    rp: { name: 'Heimdall', id: location.hostname },
                    user: {
                        id: randomBytes(16),
                        name: 'heimdall-user',
                        displayName: 'Heimdall User',
                    },
                    pubKeyCredParams: [
                        { type: 'public-key', alg: -7  },  // ES256
                        { type: 'public-key', alg: -257 }, // RS256
                    ],
                    authenticatorSelection: {
                        authenticatorAttachment: 'platform',
                        userVerification: 'required',
                        residentKey: 'preferred',
                    },
                    extensions: {
                        prf: { eval: { first: PRF_INPUT } },
                    },
                },
            });

            const ext = credential.getClientExtensionResults();
            const prfResult = ext?.prf?.results?.first;

            if (!prfResult) {
                fail('This device does not support the PRF extension. Biometrics unavailable.');
                return;
            }

            $status.textContent = 'Done — closing…';
            $status.className   = 'status success';

            sendResult({
                type:         'heimdall-prf',
                action:       'register',
                credentialId: bytesToB64url(credential.rawId),
                prfOutput:    bytesToB64url(prfResult),
            });

            setTimeout(() => window.close(), 800);

        } else if (action === 'authenticate') {
            $msg.textContent = 'Verify your identity with biometrics.';

            if (!credIdB64) { fail('Missing credential ID.'); return; }

            const assertion = await navigator.credentials.get({
                publicKey: {
                    challenge:          randomBytes(32),
                    rpId:               location.hostname,
                    userVerification:   'required',
                    allowCredentials:   [{ type: 'public-key', id: b64urlToBytes(credIdB64) }],
                    extensions: {
                        prf: { eval: { first: PRF_INPUT } },
                    },
                },
            });

            const ext = assertion.getClientExtensionResults();
            const prfResult = ext?.prf?.results?.first;

            if (!prfResult) {
                fail('Biometric assertion did not return a PRF output.');
                return;
            }

            $status.textContent = 'Verified — closing…';
            $status.className   = 'status success';

            sendResult({
                type:      'heimdall-prf',
                action:    'authenticate',
                prfOutput: bytesToB64url(prfResult),
            });

            setTimeout(() => window.close(), 800);

        } else {
            fail('Unknown action.');
        }

    } catch (err) {
        if (err.name === 'NotAllowedError') {
            fail('Biometric prompt cancelled or not allowed.');
        } else {
            fail(err.message || 'Unknown error.');
        }
    }
})();
</script>
</body>
</html>
