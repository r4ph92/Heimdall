<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureVaultKeyInSession
{
    /**
     * Handle an incoming request.
     *
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        // The vault encryption key is derived from the master password at login
        // and stored only in the session — never in the database.
        // If the session expired (e.g. server restart, cookie timeout) while the
        // auth cookie is still valid, the key is gone and the vault cannot be
        // decrypted. We force a re-login so the key can be re-derived.
        if (! session()->has('vault_key')) {
            // After passkey login the user is authenticated but has no vault key yet —
            // send them to the vault unlock page instead of forcing a full logout.
            if (auth()->check() && session('passkey_authenticated')) {
                return redirect()->route('vault.unlock');
            }

            auth()->logout();
            session()->invalidate();
            session()->regenerateToken();

            return redirect()->route('login')->withErrors([
                'email' => 'Your session expired. Please log in again to unlock your vault.',
            ]);
        }

        return $next($request);
    }
}
