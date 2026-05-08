/**
 * Mirrors EncryptionService.php using the WebCrypto API.
 * Algorithm: AES-256-GCM, key derived via PBKDF2-SHA256 (200 000 iterations, 32-byte output).
 * Ciphertext format: base64(ciphertext || 16-byte GCM auth tag), IV stored separately as base64.
 */

export function base64ToBytes(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

export function bytesToBase64(bytes) {
    return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

/**
 * Derives the AES-256-GCM vault key from the master password and vault_salt.
 * Returns raw key bytes (ArrayBuffer) — the caller decides extractability.
 */
export async function deriveKeyBytes(masterPassword, vaultSalt) {
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(masterPassword),
        'PBKDF2',
        false,
        ['deriveBits'],
    );

    return crypto.subtle.deriveBits(
        {
            name:       'PBKDF2',
            salt:       base64ToBytes(vaultSalt),
            iterations: 200_000,
            hash:       'SHA-256',
        },
        keyMaterial,
        256,
    );
}

/**
 * Imports raw key bytes as a non-extractable AES-GCM CryptoKey for decryption.
 */
export async function importVaultKey(keyBytes) {
    return crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
}

/**
 * Decrypts an encrypted field.
 * @param {string} ciphertextB64 - base64(ciphertext || 16-byte tag)
 * @param {string} ivB64         - base64(12-byte IV)
 * @param {CryptoKey} key        - AES-GCM CryptoKey
 */
export async function decryptField(ciphertextB64, ivB64, key) {
    const data      = base64ToBytes(ciphertextB64); // ciphertext || tag
    const iv        = base64ToBytes(ivB64);
    const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        key,
        data,
    );
    return new TextDecoder().decode(plaintext);
}

/**
 * Decrypts a vault entry's password (and notes if present).
 */
export async function decryptEntry(entry, vaultKey) {
    const password = await decryptField(entry.encrypted_password, entry.iv, vaultKey);
    const notes    = entry.encrypted_notes
        ? await decryptField(entry.encrypted_notes, entry.notes_iv, vaultKey)
        : null;
    return { ...entry, password, notes };
}
