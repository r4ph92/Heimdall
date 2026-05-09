<?php

namespace App\Http\Controllers;

use App\Models\WebauthnCredential;
use App\Services\WebAuthnService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;

class WebAuthnAuthController extends Controller
{
    public function __construct(private readonly WebAuthnService $webauthn) {}

    /**
     * Generate and cache a WebAuthn authentication challenge.
     * Called via fetch() from the login page before invoking navigator.credentials.get().
     */
    public function options(Request $request): JsonResponse
    {
        $challengeB64 = $this->webauthn->generateChallenge();
        Cache::put('webauthn_auth_' . $request->session()->getId(), $challengeB64, now()->addMinutes(5));

        return response()->json([
            'challenge'        => $challengeB64,
            'rpId'             => $this->webauthn->rpId(),
            'timeout'          => 60000,
            'userVerification' => 'preferred',
            'allowCredentials' => [],
        ]);
    }

    /**
     * Verify a WebAuthn assertion, log the user in, and redirect to vault unlock.
     * The vault key cannot be derived without the master password, so a separate
     * vault-unlock step is required after passkey authentication.
     */
    public function verify(Request $request): RedirectResponse
    {
        $cacheKey       = 'webauthn_auth_' . $request->session()->getId();
        $storedChallenge = Cache::pull($cacheKey);

        if (! $storedChallenge) {
            return back()->withErrors(['passkey' => 'Authentication timed out. Please try again.']);
        }

        $credential = $request->input('credential');
        $credId     = $credential['id'] ?? null;

        if (! $credId) {
            return back()->withErrors(['passkey' => 'Invalid credential.']);
        }

        $stored = WebauthnCredential::where('credential_id', $credId)->first();

        if (! $stored) {
            return back()->withErrors(['passkey' => 'Passkey not registered.']);
        }

        try {
            $newSignCount = $this->webauthn->verifyAssertion(
                $credential,
                $storedChallenge,
                $stored->public_key,
                $stored->sign_count,
            );
        } catch (\Exception $e) {
            return back()->withErrors(['passkey' => 'Passkey verification failed: ' . $e->getMessage()]);
        }

        $stored->update(['sign_count' => $newSignCount, 'last_used_at' => now()]);

        Auth::login($stored->user);
        $request->session()->regenerate();

        // Mark session as passkey-authenticated so EnsureVaultKeyInSession
        // redirects to vault-unlock instead of logging out
        session(['passkey_authenticated' => true]);

        return redirect()->route('vault.unlock');
    }
}
