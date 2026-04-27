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

        <p class="text-center text-gray-500 text-sm mt-6">
            No account yet?
            <a wire:navigate href="{{ route('register') }}" class="text-indigo-400 hover:underline">Create a vault</a>
        </p>
    </div>
</div>