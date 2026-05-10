<?php

use App\Services\EncryptionService;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;
use Livewire\Component;

new class extends Component
{
    public string $email = '';
    public string $password = '';
    public bool $remember = false;

    public function login(EncryptionService $encryption): void
    {
        $this->validate([
            'email'    => ['required', 'email'],
            'password' => ['required', 'string'],
        ]);

        // Key per email+IP so both targeted account attacks and IP-based brute force are limited
        $rateLimitKey = 'login.' . str($this->email)->lower() . '.' . request()->ip();

        if (RateLimiter::tooManyAttempts($rateLimitKey, 10)) {
            $seconds = RateLimiter::availableIn($rateLimitKey);
            throw ValidationException::withMessages([
                'email' => "Too many login attempts. Please try again in {$seconds} seconds.",
            ]);
        }

        if (! Auth::attempt(['email' => $this->email, 'password' => $this->password], $this->remember)) {
            RateLimiter::hit($rateLimitKey, 60);
            throw ValidationException::withMessages([
                'email' => 'These credentials do not match our records.',
            ]);
        }

        RateLimiter::clear($rateLimitKey);

        $user = Auth::user();

        // Re-derive the encryption key from the master password + stored salt.
        // This key is never persisted in the DB — only held in the session.
        $encryptionKey = $encryption->deriveKey($this->password, $user->vault_salt);
        session(['vault_key' => base64_encode($encryptionKey)]);

        session()->regenerate();

        // If MFA is enabled, redirect to the challenge page instead of the dashboard.
        // The vault key is already in session so the challenge page can load,
        // but EnsureMfaVerified will block the dashboard until the code is confirmed.
        if ($user->hasMfaEnabled()) {
            $this->redirect(route('mfa.challenge'), navigate: true);
            return;
        }

        session(['mfa_verified' => true]);
        $this->redirect(route('dashboard'), navigate: true);
    }
};
?>

<div class="min-h-screen flex items-center justify-center bg-gray-950">
    <div class="w-full max-w-md bg-gray-900 rounded-2xl shadow-xl p-8">
        <div class="mb-8 text-center">
            <h1 class="text-3xl font-bold text-white tracking-tight">Heimdall</h1>
            <p class="text-gray-400 mt-1 text-sm">Unlock your vault</p>
        </div>

        @if (session('errors') && session('errors')->has('email') && str_contains(session('errors')->first('email'), 'session expired'))
            <div class="mb-4 bg-yellow-900/30 border border-yellow-700/50 text-yellow-400 text-sm rounded-lg px-4 py-3">
                {{ session('errors')->first('email') }}
            </div>
        @endif

        <form wire:submit="login" class="space-y-5">
            <div>
                <label class="block text-sm font-medium text-gray-300 mb-1" for="email">Email</label>
                <input
                    wire:model="email"
                    id="email"
                    type="email"
                    autocomplete="email"
                    class="w-full bg-gray-800 border border-gray-700 text-white rounded-lg px-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    placeholder="you@example.com"
                >
                @error('email') <p class="text-red-400 text-xs mt-1">{{ $message }}</p> @enderror
            </div>

            <div>
                <label class="block text-sm font-medium text-gray-300 mb-1" for="password">Master Password</label>
                <input
                    wire:model="password"
                    id="password"
                    type="password"
                    autocomplete="current-password"
                    class="w-full bg-gray-800 border border-gray-700 text-white rounded-lg px-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    placeholder="Your master password"
                >
                @error('password') <p class="text-red-400 text-xs mt-1">{{ $message }}</p> @enderror
            </div>

            <div class="flex items-center gap-2">
                <input wire:model="remember" id="remember" type="checkbox" class="accent-indigo-500">
                <label for="remember" class="text-sm text-gray-400">Remember me</label>
            </div>

            <button
                type="submit"
                class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold py-2.5 rounded-lg transition"
                wire:loading.attr="disabled"
            >
                <span wire:loading.remove>Unlock</span>
                <span wire:loading>Unlocking…</span>
            </button>
        </form>

        {{-- Passkey login --}}
        <div class="mt-5"
            x-data="{
                error: '',
                async loginWithPasskey() {
                    this.error = '';
                    try {
                        const resp = await fetch('{{ route('webauthn.auth.options') }}', {
                            method: 'POST',
                            headers: { 'X-CSRF-TOKEN': document.querySelector('meta[name=csrf-token]').content, 'Content-Type': 'application/json' },
                        });
                        const options = await resp.json();

                        const credential = await navigator.credentials.get({
                            publicKey: {
                                challenge: Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0)),
                                rpId: options.rpId,
                                timeout: options.timeout,
                                userVerification: options.userVerification,
                                allowCredentials: [],
                            }
                        });

                        if (!credential) {
                            this.error = 'No passkey found on this device.';
                            return;
                        }

                        const payload = {
                            id: credential.id,
                            rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                            type: credential.type,
                            response: {
                                clientDataJSON:    btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                                authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                                signature:         btoa(String.fromCharCode(...new Uint8Array(credential.response.signature))),
                                userHandle:        credential.response.userHandle
                                    ? btoa(String.fromCharCode(...new Uint8Array(credential.response.userHandle)))
                                    : null,
                            }
                        };

                        const form = document.createElement('form');
                        form.method = 'POST';
                        form.action = '{{ route('webauthn.auth.verify') }}';
                        const csrf = document.createElement('input');
                        csrf.type = 'hidden'; csrf.name = '_token';
                        csrf.value = document.querySelector('meta[name=csrf-token]').content;
                        const data = document.createElement('input');
                        data.type = 'hidden'; data.name = 'credential';
                        data.value = JSON.stringify(payload);
                        form.appendChild(csrf); form.appendChild(data);
                        document.body.appendChild(form);
                        form.submit();
                    } catch (e) {
                        if (e.name !== 'NotAllowedError') {
                            this.error = e.message;
                        }
                    }
                }
            }"
        >
            <div class="flex items-center gap-3 my-4">
                <div class="flex-1 h-px bg-gray-800"></div>
                <span class="text-xs text-gray-600">or</span>
                <div class="flex-1 h-px bg-gray-800"></div>
            </div>

            <button
                type="button"
                @click="loginWithPasskey()"
                class="w-full flex items-center justify-center gap-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-300 font-medium py-2.5 rounded-lg transition"
            >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>
                </svg>
                Sign in with Passkey
            </button>
            <p x-show="error" x-text="error" class="text-red-400 text-xs mt-2 text-center"></p>

            @error('passkey') <p class="text-red-400 text-xs mt-2 text-center">{{ $message }}</p> @enderror
        </div>

        <p class="text-center text-gray-500 text-sm mt-5">
            No account yet?
            <a wire:navigate href="{{ route('register') }}" class="text-indigo-400 hover:underline">Create a vault</a>
        </p>
    </div>
</div>