<?php

namespace App\Services;

/**
 * EncryptionService — zero-knowledge vault encryption.
 *
 * Flow:
 *  1. On signup: generate a random vault_salt and store it with the user.
 *  2. On login: re-derive the encryption key from (master_password + vault_salt)
 *     using PBKDF2-SHA256, then store the key in the session.
 *  3. The server never stores the raw master password or the derived key.
 *     If the master password is lost, the vault is unrecoverable — by design.
 */
class EncryptionService
{
    private const CIPHER      = 'aes-256-gcm';
    private const KEY_LENGTH  = 32;   // 256 bits
    private const PBKDF2_ALGO = 'sha256';
    private const PBKDF2_ITER = 200_000; // OWASP recommended minimum for PBKDF2-SHA256

    /**
     * Generate a cryptographically random salt for a new user.
     */
    public function generateSalt(): string
    {
        return base64_encode(random_bytes(32));
    }

    /**
     * Derive a 256-bit AES key from the master password and the user's salt.
     * This must be called on every login and the result stored in the session.
     */
    public function deriveKey(string $masterPassword, string $salt): string
    {
        $rawSalt = base64_decode($salt);

        return hash_pbkdf2(
            self::PBKDF2_ALGO,
            $masterPassword,
            $rawSalt,
            self::PBKDF2_ITER,
            self::KEY_LENGTH,
            true // raw binary output
        );
    }

    /**
     * Encrypt plaintext with AES-256-GCM.
     * Returns ['ciphertext' => string, 'iv' => string] — both base64 encoded.
     * A unique IV is generated for every encryption call.
     */
    public function encrypt(string $plaintext, string $key): array
    {
        $iv = random_bytes(12); // 96-bit IV recommended for GCM

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        // GCM authentication tag is appended to the ciphertext so it is verified on decrypt
        return [
            'ciphertext' => base64_encode($ciphertext . $tag),
            'iv'         => base64_encode($iv),
        ];
    }

    /**
     * Decrypt a ciphertext produced by encrypt().
     * Returns null if the authentication tag fails (data tampered or wrong key).
     */
    public function decrypt(string $ciphertext, string $iv, string $key): ?string
    {
        $raw       = base64_decode($ciphertext);
        $rawIv     = base64_decode($iv);

        // GCM tag is always 16 bytes, appended at the end
        $tag       = substr($raw, -16);
        $encrypted = substr($raw, 0, -16);

        $plaintext = openssl_decrypt(
            $encrypted,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $rawIv,
            $tag
        );

        return $plaintext === false ? null : $plaintext;
    }
}
