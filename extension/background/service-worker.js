/**
 * Background service worker — the only context that touches crypto operations.
 * Content scripts and the popup never handle vault keys or plaintext passwords directly.
 */

import { APP_ORIGIN } from '../config.js';
import { deriveKeyBytes, decryptEntry } from '../crypto/vault.js';
import { registerBiometric, authenticateBiometric } from '../crypto/biometric.js';
import {
    hasStoredKey,
    getStoredCredentialId,
    wrapAndStore,
    unlockWithPRF,
    storeSessionKey,
    getSessionKeyBytes,
    getSessionVaultKey,
    isSessionUnlocked,
    clearStoredKey,
} from '../crypto/keystore.js';

const API_BASE = `${APP_ORIGIN}/api/extension`;

// ─── Extension state (in-memory, lost when service worker sleeps) ─────────────
// Encrypted entries are re-fetched from the API when needed so sleeping is harmless.

// ─── API helpers ─────────────────────────────────────────────────────────────

async function getToken() {
    const { apiToken } = await chrome.storage.session.get('apiToken');
    return apiToken ?? null;
}

async function apiFetch(path, options = {}) {
    const token = await getToken();
    const res   = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers: {
            'Content-Type':  'application/json',
            'Accept':        'application/json',
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
            ...(options.headers ?? {}),
        },
        body: options.body ? JSON.stringify(options.body) : undefined,
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error ?? `HTTP ${res.status}`);
    }
    return res.json();
}

// ─── Message handlers ─────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleMessage(message, sender).then(sendResponse).catch(err => {
        sendResponse({ error: err.message });
    });
    return true; // keep channel open for async response
});

async function handleMessage(msg, sender) {
    switch (msg.type) {

        case 'getState': {
            const unlocked     = await isSessionUnlocked();
            const hasBiometric = await hasStoredKey();
            return { unlocked, hasBiometric };
        }

        case 'login': {
            const { email, password } = msg;
            const data = await apiFetch('/login', {
                method: 'POST',
                body:   { email, password },
            });

            // Derive vault key client-side — server never sees it
            const vaultKeyBytes = await deriveKeyBytes(password, data.vault_salt);
            await storeSessionKey(vaultKeyBytes);

            // Cache encrypted entries and token in session
            await chrome.storage.session.set({
                apiToken:       data.token,
                cachedEntries:  data.entries,
            });

            return { ok: true };
        }

        case 'setupBiometric': {
            const rawBytes = await getSessionKeyBytes();
            if (!rawBytes) throw new Error('Not unlocked — log in first.');

            const { credentialId, prfOutput } = await registerBiometric(chrome.runtime.id);
            await wrapAndStore(rawBytes, prfOutput, credentialId);
            return { ok: true };
        }

        case 'biometricUnlock': {
            const credentialId = await getStoredCredentialId();
            if (!credentialId) throw new Error('No biometric registered.');

            const { prfOutput } = await authenticateBiometric(chrome.runtime.id, credentialId);
            await unlockWithPRF(prfOutput);

            // Refresh entries after unlock
            const data = await apiFetch('/entries');
            await chrome.storage.session.set({ cachedEntries: data.entries });

            return { ok: true };
        }

        case 'getEntries': {
            if (!(await isSessionUnlocked())) return { entries: null, locked: true };

            const { cachedEntries } = await chrome.storage.session.get('cachedEntries');
            const entries = cachedEntries ?? [];

            // Filter by domain if requested
            const domain = msg.domain ?? null;
            const filtered = domain
                ? entries.filter(e => e.url && matchesDomain(e.url, domain))
                : entries;

            // Return metadata only — passwords decrypted only when explicitly requested
            return {
                entries: filtered.map(({ id, service_name, username, url }) => ({
                    id, service_name, username, url,
                })),
            };
        }

        case 'getPassword': {
            if (!(await isSessionUnlocked())) return { error: 'Locked' };

            const { cachedEntries } = await chrome.storage.session.get('cachedEntries');
            const entry = (cachedEntries ?? []).find(e => e.id === msg.entryId);
            if (!entry) return { error: 'Entry not found' };

            const vaultKey = await getSessionVaultKey();
            const decrypted = await decryptEntry(entry, vaultKey);
            return { username: decrypted.username, password: decrypted.password };
        }

        case 'fillCredentials': {
            // Triggered by popup: tell the content script on the active tab to fill
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tab) throw new Error('No active tab.');

            const { cachedEntries } = await chrome.storage.session.get('cachedEntries');
            const entry = (cachedEntries ?? []).find(e => e.id === msg.entryId);
            if (!entry) throw new Error('Entry not found.');

            const vaultKey = await getSessionVaultKey();
            const decrypted = await decryptEntry(entry, vaultKey);

            await chrome.tabs.sendMessage(tab.id, {
                type:     'fill',
                username: decrypted.username,
                password: decrypted.password,
            });

            return { ok: true };
        }

        case 'logout': {
            await apiFetch('/logout', { method: 'POST' }).catch(() => {});
            await chrome.storage.session.clear();
            return { ok: true };
        }

        case 'forgetBiometric': {
            await clearStoredKey();
            return { ok: true };
        }

        default:
            throw new Error(`Unknown message type: ${msg.type}`);
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function matchesDomain(entryUrl, currentDomain) {
    try {
        const entryHost = new URL(entryUrl).hostname.replace(/^www\./, '');
        const currHost  = currentDomain.replace(/^www\./, '');
        return entryHost === currHost || currHost.endsWith('.' + entryHost);
    } catch {
        return false;
    }
}
