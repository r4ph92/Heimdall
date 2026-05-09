<?php

namespace App\Services;

use CBOR\Decoder;
use Webauthn\AuthenticatorDataLoader;
use Webauthn\StringStream;

class WebAuthnService
{
    public function rpId(): string
    {
        return parse_url(config('app.url'), PHP_URL_HOST) ?? 'localhost';
    }

    public function origin(): string
    {
        $url = config('app.url');
        // Strip trailing slash
        return rtrim($url, '/');
    }

    public function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public function base64urlDecode(string $str): string
    {
        $padLen = (4 - strlen($str) % 4) % 4;
        return base64_decode(strtr($str, '-_', '+/') . str_repeat('=', $padLen));
    }

    /**
     * Generate a random challenge (returns standard base64 for storage/transmission,
     * raw bytes can be recovered via base64_decode).
     */
    public function generateChallenge(): string
    {
        return base64_encode(random_bytes(32));
    }

    /**
     * Verify a WebAuthn registration response.
     *
     * @return array{credential_id: string, public_key: string, sign_count: int}
     */
    public function verifyRegistration(array $credential, string $storedChallengeB64): array
    {
        $clientDataRaw = $this->base64urlDecode($credential['response']['clientDataJSON']);
        $clientData    = json_decode($clientDataRaw, true);

        if (($clientData['type'] ?? '') !== 'webauthn.create') {
            throw new \RuntimeException('Invalid type');
        }

        if (! hash_equals(base64_decode($storedChallengeB64), $this->base64urlDecode($clientData['challenge']))) {
            throw new \RuntimeException('Challenge mismatch');
        }

        if (($clientData['origin'] ?? '') !== $this->origin()) {
            throw new \RuntimeException('Origin mismatch');
        }

        $attObjBytes = $this->base64urlDecode($credential['response']['attestationObject']);
        $attObj      = Decoder::create()->decode(new StringStream($attObjBytes))->normalize();
        $authData    = AuthenticatorDataLoader::create()->load($attObj['authData']);

        if (! hash_equals(hash('sha256', $this->rpId(), true), $authData->rpIdHash)) {
            throw new \RuntimeException('RP ID mismatch');
        }

        if (! $authData->isUserPresent()) {
            throw new \RuntimeException('User presence not set');
        }

        $acd = $authData->attestedCredentialData
            ?? throw new \RuntimeException('No attested credential data');

        return [
            'credential_id' => $credential['id'],
            'public_key'    => $this->coseKeyToPem($acd->credentialPublicKey),
            'sign_count'    => $authData->signCount,
        ];
    }

    /**
     * Verify a WebAuthn assertion response and return the new sign count.
     */
    public function verifyAssertion(array $credential, string $storedChallengeB64, string $publicKeyPem, int $storedSignCount): int
    {
        $clientDataRaw = $this->base64urlDecode($credential['response']['clientDataJSON']);
        $clientData    = json_decode($clientDataRaw, true);

        if (($clientData['type'] ?? '') !== 'webauthn.get') {
            throw new \RuntimeException('Invalid type');
        }

        if (! hash_equals(base64_decode($storedChallengeB64), $this->base64urlDecode($clientData['challenge']))) {
            throw new \RuntimeException('Challenge mismatch');
        }

        if (($clientData['origin'] ?? '') !== $this->origin()) {
            throw new \RuntimeException('Origin mismatch');
        }

        $authDataBytes = $this->base64urlDecode($credential['response']['authenticatorData']);
        $authData      = AuthenticatorDataLoader::create()->load($authDataBytes);

        if (! hash_equals(hash('sha256', $this->rpId(), true), $authData->rpIdHash)) {
            throw new \RuntimeException('RP ID mismatch');
        }

        if (! $authData->isUserPresent()) {
            throw new \RuntimeException('User presence not set');
        }

        // Clone detection: counter must advance (0 means authenticator doesn't track it)
        if ($storedSignCount > 0 && $authData->signCount > 0 && $authData->signCount <= $storedSignCount) {
            throw new \RuntimeException('Sign count regression — possible cloned authenticator');
        }

        $signedData = $authDataBytes . hash('sha256', $clientDataRaw, true);
        $signature  = $this->base64urlDecode($credential['response']['signature']);

        if (openssl_verify($signedData, $signature, $publicKeyPem, OPENSSL_ALGO_SHA256) !== 1) {
            throw new \RuntimeException('Signature verification failed');
        }

        return $authData->signCount;
    }

    /**
     * Decode a COSE EC2 P-256 public key from CBOR bytes to PEM.
     * Supports only ES256 (alg -7, crv P-256) — the algorithm required by Heimdall.
     */
    private function coseKeyToPem(string $cborBytes): string
    {
        $coseMap = Decoder::create()->decode(new StringStream($cborBytes));
        $x = $coseMap->get('-2')->normalize(); // 32-byte x coordinate
        $y = $coseMap->get('-3')->normalize(); // 32-byte y coordinate
        return $this->ec2P256ToPem($x, $y);
    }

    /**
     * Construct a SubjectPublicKeyInfo PEM from raw P-256 x/y coordinates.
     * The DER structure is fixed-size for P-256 so lengths are hardcoded.
     */
    private function ec2P256ToPem(string $x, string $y): string
    {
        $point  = "\x04" . $x . $y; // uncompressed EC point: 04 || x || y

        // OID 1.2.840.10045.2.1 (id-ecPublicKey)
        $oidEcPk = "\x2a\x86\x48\xce\x3d\x02\x01";
        // OID 1.2.840.10045.3.1.7 (prime256v1 / P-256)
        $oidP256 = "\x2a\x86\x48\xce\x3d\x03\x01\x07";

        // AlgorithmIdentifier SEQUENCE { id-ecPublicKey, prime256v1 }
        $alg = "\x30\x13\x06\x07" . $oidEcPk . "\x06\x08" . $oidP256;

        // BIT STRING wrapping the uncompressed point (one zero byte for unused bits)
        $bitStr = "\x03" . $this->derLen(strlen($point) + 1) . "\x00" . $point;

        // SubjectPublicKeyInfo SEQUENCE
        $spki = "\x30" . $this->derLen(strlen($alg) + strlen($bitStr)) . $alg . $bitStr;

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    private function derLen(int $len): string
    {
        if ($len < 128) {
            return chr($len);
        }
        $bytes = '';
        while ($len > 0) {
            $bytes = chr($len & 0xff) . $bytes;
            $len >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }
}
