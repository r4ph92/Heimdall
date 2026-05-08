/**
 * Manages the vault key lifecycle:
 *  - Wraps the vault key with AES-KW using the WebAuthn PRF output as the wrapping key.
 *  - Stores the encrypted blob + credential ID + 7-day expiry in chrome.storage.local.
 *  - Unwraps on biometric unlock and stores raw bytes in chrome.storage.session.
 *
 * WHY AES-KW: it is a standard key-wrapping algorithm that prevents the vault key
 * from ever appearing in chrome.storage.local in plaintext. Even if local storage is
 * read by another process, the key is useless without the device-bound PRF output.
 *
 * WHY chrome.storage.session for the unlocked key: session storage is cleared when the
 * browser closes, so the plaintext key is never persisted across power-off.
 */

import { base64ToBytes, bytesToBase64, importVaultKey } from './vault.js';

const LOCAL_KEY   = 'heimdall_wrapped_vault_key';
const SESSION_KEY = 'heimdall_vault_key_bytes';
const WEEK_MS     = 7 * 24 * 60 * 60 * 1000;

// ─── Wrapped key persistence ──────────────────────────────────────────────────

export async function hasStoredKey() {
    const data = await chrome.storage.local.get(LOCAL_KEY);
    const record = data[LOCAL_KEY];
    return !!record && record.expiresAt > Date.now();
}

export async function getStoredCredentialId() {
    const data = await chrome.storage.local.get(LOCAL_KEY);
    const record = data[LOCAL_KEY];
    if (!record) return null;
    return base64ToBytes(record.credentialId);
}

/**
 * Wraps the vault key bytes with the PRF output and persists to local storage.
 */
export async function wrapAndStore(vaultKeyBytes, prfOutput, credentialId) {
    const wrappingKey = await importWrappingKey(prfOutput, ['wrapKey']);

    // Must be extractable to be wrappable
    const vaultCryptoKey = await crypto.subtle.importKey(
        'raw', vaultKeyBytes, 'AES-GCM', true, ['decrypt'],
    );

    const wrappedBuffer = await crypto.subtle.wrapKey('raw', vaultCryptoKey, wrappingKey, 'AES-KW');

    await chrome.storage.local.set({
        [LOCAL_KEY]: {
            wrappedKey:   bytesToBase64(new Uint8Array(wrappedBuffer)),
            credentialId: bytesToBase64(new Uint8Array(credentialId)),
            expiresAt:    Date.now() + WEEK_MS,
        },
    });
}

export async function clearStoredKey() {
    await chrome.storage.local.remove(LOCAL_KEY);
    await chrome.storage.session.remove(SESSION_KEY);
}

// ─── Session unlock ───────────────────────────────────────────────────────────

/**
 * Unwraps the stored vault key using the PRF output and caches the raw bytes
 * in chrome.storage.session for use during this browser session.
 */
export async function unlockWithPRF(prfOutput) {
    const data = await chrome.storage.local.get(LOCAL_KEY);
    const record = data[LOCAL_KEY];

    if (!record) throw new Error('No stored key found.');
    if (record.expiresAt <= Date.now()) {
        await clearStoredKey();
        throw new Error('Stored key has expired. Please log in again.');
    }

    const wrappingKey  = await importWrappingKey(prfOutput, ['unwrapKey']);
    const wrappedBytes = base64ToBytes(record.wrappedKey);

    // Unwrap as extractable=true so we can export raw bytes for session caching.
    // The key is re-imported as non-extractable each time it's used for decryption.
    const extractableKey = await crypto.subtle.unwrapKey(
        'raw', wrappedBytes, wrappingKey, 'AES-KW',
        { name: 'AES-GCM' }, true, ['decrypt'],
    );
    const rawBytes = await crypto.subtle.exportKey('raw', extractableKey);

    await chrome.storage.session.set({
        [SESSION_KEY]: bytesToBase64(new Uint8Array(rawBytes)),
    });
}

/**
 * Stores vault key bytes directly in session (called after master password login).
 */
export async function storeSessionKey(vaultKeyBytes) {
    await chrome.storage.session.set({
        [SESSION_KEY]: bytesToBase64(new Uint8Array(vaultKeyBytes)),
    });
}

/**
 * Returns the session vault key as a CryptoKey, or null if not unlocked.
 */
export async function getSessionVaultKey() {
    const data = await chrome.storage.session.get(SESSION_KEY);
    if (!data[SESSION_KEY]) return null;
    return importVaultKey(base64ToBytes(data[SESSION_KEY]));
}

export async function isSessionUnlocked() {
    const data = await chrome.storage.session.get(SESSION_KEY);
    return !!data[SESSION_KEY];
}

/**
 * Returns the raw vault key bytes from session storage, or null if not unlocked.
 * Used by setupBiometric to wrap an already-derived session key.
 */
export async function getSessionKeyBytes() {
    const data = await chrome.storage.session.get(SESSION_KEY);
    if (!data[SESSION_KEY]) return null;
    return base64ToBytes(data[SESSION_KEY]);
}

// ─── Internal ─────────────────────────────────────────────────────────────────

async function importWrappingKey(prfOutput, usages) {
    return crypto.subtle.importKey('raw', prfOutput, 'AES-KW', false, usages);
}
