/**
 * Biometric key derivation via WebAuthn PRF extension.
 *
 * WHY this approach: WebAuthn PRF lets us derive a deterministic, device-bound secret
 * tied to a biometric-protected credential. The same credential + same PRF input always
 * produces the same output — making it usable as a key-wrapping key without storing
 * any secret on the server.
 *
 * WHY a bridge page: Browser extensions cannot use WebAuthn with a custom rpId from their
 * chrome-extension:// origin. By routing the ceremony through a page served on localhost
 * (the same origin as the app), we get a valid rpId and full platform authenticator support.
 */

import { APP_ORIGIN } from '../config.js';
import { base64ToBytes, bytesToBase64 } from './vault.js';

const BRIDGE_URL  = `${APP_ORIGIN}/extension/webauthn-bridge`;
const TIMEOUT_MS  = 120_000;

/**
 * Opens the bridge tab to register a new WebAuthn credential with PRF.
 * Returns { credentialId: Uint8Array, prfOutput: Uint8Array }.
 */
export function registerBiometric(extensionId) {
    return openBridgeAndWait('register', { ext_id: extensionId });
}

/**
 * Opens the bridge tab to assert an existing credential and get the PRF output.
 * Returns { prfOutput: Uint8Array }.
 */
export function authenticateBiometric(extensionId, credentialId) {
    const credIdB64url = bytesToB64url(credentialId);
    return openBridgeAndWait('authenticate', { ext_id: extensionId, cred_id: credIdB64url });
}

function openBridgeAndWait(action, params) {
    return new Promise((resolve, reject) => {
        const query  = new URLSearchParams({ action, ...params }).toString();
        const url    = `${BRIDGE_URL}?${query}`;

        let tabId;
        let timer;

        function cleanup() {
            clearTimeout(timer);
            if (tabId !== undefined) {
                chrome.tabs.remove(tabId).catch(() => {});
            }
        }

        function onMessage(message, sender) {
            if (message?.type !== 'heimdall-prf') return;
            if (sender.tab?.id !== tabId) return;

            // onMessageExternal handles messages sent from web pages (the bridge) to the extension
            chrome.runtime.onMessageExternal.removeListener(onMessage);
            cleanup();

            if (message.error) {
                reject(new Error(message.error));
            } else {
                resolve({
                    credentialId: message.credentialId ? b64urlToBytes(message.credentialId) : undefined,
                    prfOutput:    b64urlToBytes(message.prfOutput),
                });
            }
        }

        chrome.runtime.onMessageExternal.addListener(onMessage);

        chrome.tabs.create({ url, active: true }, tab => {
            tabId = tab.id;
            timer = setTimeout(() => {
                chrome.runtime.onMessage.removeListener(onMessage);
                cleanup();
                reject(new Error('Biometric prompt timed out.'));
            }, TIMEOUT_MS);
        });
    });
}

// base64url ↔ Uint8Array helpers used by the bridge response
function b64urlToBytes(b64url) {
    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    return base64ToBytes(b64);
}

function bytesToB64url(bytes) {
    return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
