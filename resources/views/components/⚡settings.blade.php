<?php

use App\Models\WebauthnCredential;
use App\Services\EncryptionService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Validation\ValidationException;
use Livewire\Component;
use PragmaRX\Google2FA\Google2FA;

new class extends Component
{
    // ── Change password ──────────────────────────────────────────────
    public string $current_password = '';
    public string $new_password = '';
    public string $new_password_confirmation = '';
    public bool $passwordSaved = false;

    // ── Two-factor auth ──────────────────────────────────────────────
    public ?string $totpQrCode = null;
    public ?string $totpSecret = null;
    public string $totpConfirmCode = '';
    public string $mfaSuccessMessage = '';

    // ── Passkey registration ─────────────────────────────────────────
    public string $passkeyName = 'My Passkey';
    public string $passkeySuccessMessage = '';

    public function changeMasterPassword(EncryptionService $encryption): void
    {
        $this->validate([
            'current_password'          => ['required', 'string'],
            'new_password'              => ['required', 'string', 'min:12', 'confirmed'],
            'new_password_confirmation' => ['required', 'string'],
        ]);

        $user = auth()->user();

        if (! Hash::check($this->current_password, $user->password)) {
            throw ValidationException::withMessages([
                'current_password' => 'Current password is incorrect.',
            ]);
        }

        // Derive old key to re-encrypt all vault entries
        $oldKey = base64_decode(session('vault_key'));

        // Generate a new salt and derive the new key
        $newSalt = $encryption->generateSalt();
        $newKey  = $encryption->deriveKey($this->new_password, $newSalt);

        // Re-encrypt every vault entry with the new key
        foreach ($user->vaultEntries as $entry) {
            $password = $encryption->decrypt($entry->encrypted_password, $entry->iv, $oldKey);
            $notes    = $entry->encrypted_notes
                ? $encryption->decrypt($entry->encrypted_notes, $entry->notes_iv, $oldKey)
                : null;

            $encryptedPassword = $encryption->encrypt($password, $newKey);
            $encryptedNotes    = $notes ? $encryption->encrypt($notes, $newKey) : null;

            $entry->update([
                'encrypted_password' => $encryptedPassword['ciphertext'],
                'iv'                 => $encryptedPassword['iv'],
                'encrypted_notes'    => $encryptedNotes ? $encryptedNotes['ciphertext'] : null,
                'notes_iv'           => $encryptedNotes ? $encryptedNotes['iv'] : null,
            ]);
        }

        // Update password hash and salt — new key is now the active one
        $user->update([
            'password'   => $this->new_password,
            'vault_salt' => $newSalt,
        ]);

        session(['vault_key' => base64_encode($newKey)]);

        $this->reset('current_password', 'new_password', 'new_password_confirmation');
        $this->passwordSaved = true;
    }

    // ── TOTP setup ───────────────────────────────────────────────────

    public function beginTotpSetup(): void
    {
        $google2fa      = new Google2FA();
        $secret         = $google2fa->generateSecretKey();
        $this->totpSecret = $secret;

        $user = auth()->user();
        $user->update(['two_factor_secret' => $secret, 'two_factor_type' => 'totp']);

        $otpUrl = $google2fa->getQRCodeUrl('Heimdall', $user->email, $secret);
        $writer = new \BaconQrCode\Writer(new \BaconQrCode\Renderer\ImageRenderer(
            new \BaconQrCode\Renderer\RendererStyle\RendererStyle(200),
            new \BaconQrCode\Renderer\Image\SvgImageBackEnd()
        ));
        $this->totpQrCode = base64_encode($writer->writeString($otpUrl));
    }

    public function confirmTotp(): void
    {
        $this->validate(['totpConfirmCode' => ['required', 'string', 'size:6']]);

        $user      = auth()->user();
        $google2fa = new Google2FA();

        if (! $google2fa->verifyKey($user->two_factor_secret, $this->totpConfirmCode)) {
            throw ValidationException::withMessages([
                'totpConfirmCode' => 'Invalid code. Make sure your clock is synced and try again.',
            ]);
        }

        $recoveryCodes = $this->generateRecoveryCodes();
        $user->update([
            'two_factor_type'           => 'totp',
            'two_factor_confirmed_at'   => now(),
            'two_factor_recovery_codes' => encrypt(json_encode($recoveryCodes['hashed'])),
        ]);

        $this->totpQrCode  = null;
        $this->totpSecret  = null;
        $this->mfaSuccessMessage = 'Authenticator app enabled successfully.';
        session(['mfa_recovery_codes_plain' => $recoveryCodes['plain']]);
    }

    public function enableEmailMfa(): void
    {
        $user = auth()->user();
        $recoveryCodes = $this->generateRecoveryCodes();

        $user->update([
            'two_factor_type'           => 'email',
            'two_factor_secret'         => null,
            'two_factor_confirmed_at'   => now(),
            'two_factor_recovery_codes' => encrypt(json_encode($recoveryCodes['hashed'])),
        ]);

        $this->mfaSuccessMessage = 'Email MFA enabled. Save your recovery codes.';
        session(['mfa_recovery_codes_plain' => $recoveryCodes['plain']]);
    }

    public function disableMfa(): void
    {
        auth()->user()->update([
            'two_factor_type'           => null,
            'two_factor_secret'         => null,
            'two_factor_confirmed_at'   => null,
            'two_factor_recovery_codes' => null,
        ]);

        $this->totpQrCode        = null;
        $this->mfaSuccessMessage = 'Two-factor authentication disabled.';
        session()->forget('mfa_recovery_codes_plain');
    }

    private function generateRecoveryCodes(): array
    {
        $plain  = [];
        $hashed = [];
        for ($i = 0; $i < 8; $i++) {
            $code     = strtoupper(bin2hex(random_bytes(5)));
            $plain[]  = $code;
            $hashed[] = bcrypt($code);
        }
        return ['plain' => $plain, 'hashed' => $hashed];
    }

    // ── Sessions ─────────────────────────────────────────────────────

    public function getSessions(): array
    {
        $currentId = session()->getId();

        return DB::table('sessions')
            ->where('user_id', auth()->id())
            ->orderByDesc('last_activity')
            ->get()
            ->map(function ($s) use ($currentId) {
                $ua      = $s->user_agent ?? '';
                $browser = $this->parseBrowser($ua);
                $os      = $this->parseOs($ua);
                return [
                    'id'           => $s->id,
                    'is_current'   => $s->id === $currentId,
                    'browser'      => $browser,
                    'os'           => $os,
                    'ip'           => $s->ip_address ?? 'Unknown',
                    'last_active'  => \Carbon\Carbon::createFromTimestamp($s->last_activity)->diffForHumans(),
                ];
            })
            ->toArray();
    }

    public function revokeSession(string $id): void
    {
        DB::table('sessions')
            ->where('id', $id)
            ->where('user_id', auth()->id()) // ensure ownership
            ->delete();
    }

    public function revokeOtherSessions(): void
    {
        DB::table('sessions')
            ->where('user_id', auth()->id())
            ->where('id', '!=', session()->getId())
            ->delete();
    }

    private function parseBrowser(string $ua): string
    {
        return match (true) {
            str_contains($ua, 'Edg/')     => 'Edge',
            str_contains($ua, 'Chrome/')  => 'Chrome',
            str_contains($ua, 'Firefox/') => 'Firefox',
            str_contains($ua, 'Safari/')  => 'Safari',
            str_contains($ua, 'OPR/')     => 'Opera',
            default                        => 'Unknown browser',
        };
    }

    private function parseOs(string $ua): string
    {
        return match (true) {
            str_contains($ua, 'Windows') => 'Windows',
            str_contains($ua, 'Mac OS')  => 'macOS',
            str_contains($ua, 'iPhone')  => 'iPhone',
            str_contains($ua, 'Android') => 'Android',
            str_contains($ua, 'Linux')   => 'Linux',
            default                       => 'Unknown OS',
        };
    }

    // ── Passkeys ─────────────────────────────────────────────────────

    public function getPasskeysProperty()
    {
        return auth()->user()->webauthnCredentials()->orderByDesc('created_at')->get();
    }

    public function deletePasskey(int $id): void
    {
        WebauthnCredential::where('user_id', auth()->id())->findOrFail($id)->delete();
    }

    public function getWebAuthnRegisterOptions(): array
    {
        $user = auth()->user();
        $challenge = base64_encode(random_bytes(32));
        Cache::put("webauthn_challenge_{$user->id}", $challenge, now()->addMinutes(5));

        return [
            'challenge' => $challenge,
            'rp'        => ['name' => 'Heimdall', 'id' => parse_url(config('app.url'), PHP_URL_HOST) ?? 'localhost'],
            'user'      => [
                'id'          => base64_encode((string) $user->id),
                'name'        => $user->email,
                'displayName' => $user->name,
            ],
            'pubKeyCredParams' => [
                ['type' => 'public-key', 'alg' => -7],   // ES256
                ['type' => 'public-key', 'alg' => -257],  // RS256
            ],
            'authenticatorSelection' => [
                'residentKey'        => 'preferred',
                'userVerification'   => 'preferred',
            ],
            'timeout' => 60000,
        ];
    }

    public function savePasskey(array $credential): void
    {
        $user      = auth()->user();
        $challenge = Cache::get("webauthn_challenge_{$user->id}");

        if (! $challenge) {
            throw ValidationException::withMessages(['passkeyName' => 'Registration timed out. Please try again.']);
        }

        Cache::forget("webauthn_challenge_{$user->id}");

        // Store the credential — full CBOR parsing is done client-side by the browser;
        // we store the attestation response for server-side verification on login.
        WebauthnCredential::create([
            'user_id'       => $user->id,
            'credential_id' => $credential['id'],
            'public_key'    => json_encode($credential['response']),
            'sign_count'    => 0,
            'name'          => $this->passkeyName,
        ]);

        $this->passkeySuccessMessage = "Passkey \"{$this->passkeyName}\" registered successfully.";
        $this->passkeyName = 'My Passkey';
    }
};
?>

<div class="flex h-screen bg-gray-950 text-white overflow-hidden animate-fadein">

    {{-- Sidebar (reuse same structure as dashboard) --}}
    <aside class="w-64 shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col">
        <div class="px-6 py-5 border-b border-gray-800">
            <h1 class="text-xl font-bold tracking-tight text-white">⚡ Heimdall</h1>
            <p class="text-xs text-gray-500 mt-0.5">{{ auth()->user()->name }}</p>
        </div>
        <nav class="flex-1 px-3 py-4 space-y-1">
            <a wire:navigate href="{{ route('dashboard') }}"
                class="flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-gray-400 hover:bg-gray-800 hover:text-white transition-colors duration-150">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>
                My Vault
            </a>
            <a wire:navigate href="{{ route('settings') }}"
                class="flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium bg-indigo-600 text-white transition-colors duration-150">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><circle cx="12" cy="12" r="3"/></svg>
                Settings
            </a>
        </nav>
        <div class="px-3 py-4 border-t border-gray-800">
            <form method="POST" action="{{ route('logout') }}">
                @csrf
                <button type="submit" class="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-gray-400 hover:bg-red-900/40 hover:text-red-400 transition-colors duration-150">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/></svg>
                    Lock & Logout
                </button>
            </form>
        </div>
    </aside>

    {{-- Main content --}}
    <main class="flex-1 overflow-y-auto p-8" x-data="{ tab: 'sessions' }">
        <div class="max-w-2xl mx-auto space-y-6">

            <h2 class="text-2xl font-bold text-white">Settings</h2>

            {{-- Tab nav --}}
            <div class="flex gap-1 bg-gray-900 rounded-xl p-1 border border-gray-800">
                @foreach(['sessions' => 'Sessions', 'security' => 'Password', 'mfa' => 'Two-Factor', 'passkeys' => 'Passkeys'] as $key => $label)
                    <button
                        @click="tab = '{{ $key }}'"
                        :class="tab === '{{ $key }}' ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:text-white'"
                        class="flex-1 text-sm font-medium py-2 rounded-lg transition-colors duration-150"
                    >{{ $label }}</button>
                @endforeach
            </div>

            {{-- ── Sessions tab ───────────────────────────────────────── --}}
            <div x-show="tab === 'sessions'" x-transition:enter="transition ease-out duration-150"
                x-transition:enter-start="opacity-0 translate-y-1" x-transition:enter-end="opacity-100 translate-y-0">

                <div class="bg-gray-900 border border-gray-800 rounded-2xl overflow-hidden">
                    <div class="px-5 py-4 border-b border-gray-800 flex items-center justify-between">
                        <h3 class="font-semibold text-white">Active Sessions</h3>
                        <button
                            wire:click="revokeOtherSessions"
                            wire:confirm="Revoke all other sessions? They will be logged out."
                            class="text-xs text-red-400 hover:text-red-300 transition"
                        >Revoke all others</button>
                    </div>
                    <ul class="divide-y divide-gray-800">
                        @foreach($this->getSessions() as $session)
                            <li class="px-5 py-4 flex items-center gap-4">
                                <div class="w-9 h-9 rounded-lg bg-gray-800 flex items-center justify-center shrink-0">
                                    @if(str_contains($session['os'], 'iPhone') || str_contains($session['os'], 'Android'))
                                        <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>
                                    @else
                                        <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
                                    @endif
                                </div>
                                <div class="flex-1 min-w-0">
                                    <p class="text-sm font-medium text-white flex items-center gap-2">
                                        {{ $session['browser'] }} on {{ $session['os'] }}
                                        @if($session['is_current'])
                                            <span class="text-xs bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 px-2 py-0.5 rounded-full">Current</span>
                                        @endif
                                    </p>
                                    <p class="text-xs text-gray-500">{{ $session['ip'] }} · {{ $session['last_active'] }}</p>
                                </div>
                                @if(! $session['is_current'])
                                    <button
                                        wire:click="revokeSession('{{ $session['id'] }}')"
                                        class="text-xs text-gray-600 hover:text-red-400 transition shrink-0"
                                    >Revoke</button>
                                @endif
                            </li>
                        @endforeach
                    </ul>
                </div>
            </div>

            {{-- ── Password tab ────────────────────────────────────────── --}}
            <div x-show="tab === 'security'" x-transition:enter="transition ease-out duration-150"
                x-transition:enter-start="opacity-0 translate-y-1" x-transition:enter-end="opacity-100 translate-y-0">

                <div class="bg-gray-900 border border-gray-800 rounded-2xl p-6">
                    <h3 class="font-semibold text-white mb-1">Change Master Password</h3>
                    <p class="text-xs text-gray-500 mb-5">All vault entries will be silently re-encrypted with the new key.</p>

                    @if($passwordSaved)
                        <div class="bg-green-900/30 border border-green-700/50 text-green-400 text-sm rounded-xl px-4 py-3 mb-4">
                            Password updated successfully.
                        </div>
                    @endif

                    <form wire:submit="changeMasterPassword" class="space-y-4">
                        <div x-data="{ show: false }">
                            <label class="block text-xs text-gray-500 uppercase tracking-wider mb-1">Current Password</label>
                            <div class="relative">
                                <input wire:model="current_password" :type="show ? 'text' : 'password'"
                                    class="w-full bg-gray-800 border border-gray-700 text-white rounded-xl px-4 py-3 pr-16 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 transition">
                                <button type="button" @click="show=!show" x-text="show?'Hide':'Show'"
                                    class="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-gray-500 hover:text-white transition"></button>
                            </div>
                            @error('current_password') <p class="text-red-400 text-xs mt-1">{{ $message }}</p> @enderror
                        </div>
                        <div x-data="{ show: false }">
                            <label class="block text-xs text-gray-500 uppercase tracking-wider mb-1">New Password</label>
                            <div class="relative">
                                <input wire:model="new_password" :type="show ? 'text' : 'password'" placeholder="Minimum 12 characters"
                                    class="w-full bg-gray-800 border border-gray-700 text-white rounded-xl px-4 py-3 pr-16 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 transition">
                                <button type="button" @click="show=!show" x-text="show?'Hide':'Show'"
                                    class="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-gray-500 hover:text-white transition"></button>
                            </div>
                            @error('new_password') <p class="text-red-400 text-xs mt-1">{{ $message }}</p> @enderror
                        </div>
                        <div>
                            <label class="block text-xs text-gray-500 uppercase tracking-wider mb-1">Confirm New Password</label>
                            <input wire:model="new_password_confirmation" type="password"
                                class="w-full bg-gray-800 border border-gray-700 text-white rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 transition">
                        </div>
                        <button type="submit"
                            class="bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-6 py-2.5 rounded-xl transition-colors duration-150"
                            wire:loading.attr="disabled" wire:loading.class="opacity-60">
                            <span wire:loading.remove>Update Password</span>
                            <span wire:loading>Re-encrypting vault…</span>
                        </button>
                    </form>
                </div>
            </div>

            {{-- ── Two-Factor tab ──────────────────────────────────────── --}}
            <div x-show="tab === 'mfa'" x-transition:enter="transition ease-out duration-150"
                x-transition:enter-start="opacity-0 translate-y-1" x-transition:enter-end="opacity-100 translate-y-0">

                @if($mfaSuccessMessage)
                    <div class="bg-green-900/30 border border-green-700/50 text-green-400 text-sm rounded-xl px-4 py-3 mb-4">
                        {{ $mfaSuccessMessage }}
                    </div>
                @endif

                {{-- Recovery codes shown once after enabling --}}
                @if(session('mfa_recovery_codes_plain'))
                    <div class="bg-yellow-900/20 border border-yellow-700/40 rounded-2xl p-5 mb-4">
                        <p class="text-yellow-400 text-sm font-semibold mb-2">Save your recovery codes</p>
                        <p class="text-yellow-600 text-xs mb-3">Each code can only be used once. Store them somewhere safe — they won't be shown again.</p>
                        <div class="grid grid-cols-2 gap-2">
                            @foreach(session('mfa_recovery_codes_plain') as $code)
                                <code class="bg-gray-900 text-gray-300 text-xs rounded-lg px-3 py-2 font-mono">{{ $code }}</code>
                            @endforeach
                        </div>
                    </div>
                @endif

                <div class="bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-5">
                    <div class="flex items-center justify-between">
                        <div>
                            <h3 class="font-semibold text-white">Two-Factor Authentication</h3>
                            <p class="text-xs text-gray-500 mt-0.5">
                                @if(auth()->user()->hasMfaEnabled())
                                    Active via <strong class="text-gray-300">{{ auth()->user()->two_factor_type === 'totp' ? 'Authenticator app' : 'Email' }}</strong>
                                @else
                                    Not enabled
                                @endif
                            </p>
                        </div>
                        @if(auth()->user()->hasMfaEnabled())
                            <button wire:click="disableMfa" wire:confirm="Disable two-factor authentication?"
                                class="text-xs text-red-400 hover:text-red-300 transition">Disable</button>
                        @endif
                    </div>

                    @if(! auth()->user()->hasMfaEnabled())
                        <div class="grid grid-cols-2 gap-3">
                            {{-- Email MFA --}}
                            <button wire:click="enableEmailMfa"
                                class="bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-xl p-4 text-left transition-colors duration-150">
                                <div class="w-8 h-8 rounded-lg bg-indigo-600/20 flex items-center justify-center mb-2">
                                    <svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
                                </div>
                                <p class="text-sm font-medium text-white">Email OTP</p>
                                <p class="text-xs text-gray-500 mt-0.5">Get a code by email on each login</p>
                            </button>
                            {{-- TOTP --}}
                            <button wire:click="beginTotpSetup"
                                class="bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-xl p-4 text-left transition-colors duration-150">
                                <div class="w-8 h-8 rounded-lg bg-indigo-600/20 flex items-center justify-center mb-2">
                                    <svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M7 21h10a2 2 0 002-2V5a2 2 0 00-2-2H7a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>
                                </div>
                                <p class="text-sm font-medium text-white">Authenticator App</p>
                                <p class="text-xs text-gray-500 mt-0.5">Use Google Authenticator or similar</p>
                            </button>
                        </div>

                        {{-- TOTP QR code setup --}}
                        @if($totpQrCode)
                            <div class="bg-gray-800 rounded-xl p-5 space-y-4">
                                <p class="text-sm text-gray-300">Scan this QR code with your authenticator app, then enter the 6-digit code to confirm.</p>
                                <div class="flex justify-center bg-white rounded-xl p-3 w-fit mx-auto">
                                    <img src="data:image/svg+xml;base64,{{ $totpQrCode }}" class="w-40 h-40">
                                </div>
                                <p class="text-xs text-gray-500 text-center">Manual key: <code class="text-gray-300">{{ $totpSecret }}</code></p>
                                <form wire:submit="confirmTotp" class="flex gap-3">
                                    <input wire:model="totpConfirmCode" type="text" inputmode="numeric" maxlength="6"
                                        placeholder="000000"
                                        class="flex-1 bg-gray-900 border border-gray-700 text-white text-center tracking-widest rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 transition">
                                    <button type="submit" class="bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-5 py-2.5 rounded-xl transition-colors duration-150">Confirm</button>
                                </form>
                                @error('totpConfirmCode') <p class="text-red-400 text-xs">{{ $message }}</p> @enderror
                            </div>
                        @endif
                    @endif
                </div>
            </div>

            {{-- ── Passkeys tab ────────────────────────────────────────── --}}
            <div x-show="tab === 'passkeys'" x-transition:enter="transition ease-out duration-150"
                x-transition:enter-start="opacity-0 translate-y-1" x-transition:enter-end="opacity-100 translate-y-0">

                @if($passkeySuccessMessage)
                    <div class="bg-green-900/30 border border-green-700/50 text-green-400 text-sm rounded-xl px-4 py-3 mb-4">
                        {{ $passkeySuccessMessage }}
                    </div>
                @endif

                <div class="bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-5">
                    <div>
                        <h3 class="font-semibold text-white">Passkeys</h3>
                        <p class="text-xs text-gray-500 mt-0.5">Use Touch ID, Face ID, or a hardware key as a second factor after your master password.</p>
                    </div>

                    {{-- Existing passkeys --}}
                    @if($this->passkeys->count())
                        <ul class="divide-y divide-gray-800 -mx-6 px-6">
                            @foreach($this->passkeys as $passkey)
                                <li class="py-3 flex items-center gap-3">
                                    <div class="w-8 h-8 rounded-lg bg-gray-800 flex items-center justify-center shrink-0">
                                        <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>
                                    </div>
                                    <div class="flex-1">
                                        <p class="text-sm text-white">{{ $passkey->name }}</p>
                                        <p class="text-xs text-gray-500">Added {{ $passkey->created_at->diffForHumans() }}{{ $passkey->last_used_at ? ' · Last used '.$passkey->last_used_at->diffForHumans() : '' }}</p>
                                    </div>
                                    <button wire:click="deletePasskey({{ $passkey->id }})"
                                        wire:confirm="Remove this passkey?"
                                        class="text-xs text-gray-600 hover:text-red-400 transition">Remove</button>
                                </li>
                            @endforeach
                        </ul>
                    @else
                        <p class="text-sm text-gray-600">No passkeys registered yet.</p>
                    @endif

                    {{-- Register new passkey --}}
                    <div
                        x-data="{
                            async register() {
                                const options = await $wire.getWebAuthnRegisterOptions();
                                const optionsDecoded = {
                                    ...options,
                                    challenge: Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0)),
                                    user: { ...options.user, id: Uint8Array.from(atob(options.user.id), c => c.charCodeAt(0)) }
                                };
                                try {
                                    const cred = await navigator.credentials.create({ publicKey: optionsDecoded });
                                    const response = {
                                        id: cred.id,
                                        rawId: btoa(String.fromCharCode(...new Uint8Array(cred.rawId))),
                                        type: cred.type,
                                        response: {
                                            attestationObject: btoa(String.fromCharCode(...new Uint8Array(cred.response.attestationObject))),
                                            clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(cred.response.clientDataJSON))),
                                        }
                                    };
                                    await $wire.savePasskey(response);
                                } catch (e) {
                                    alert('Passkey registration failed: ' + e.message);
                                }
                            }
                        }"
                        class="flex gap-3 items-end"
                    >
                        <div class="flex-1">
                            <label class="block text-xs text-gray-500 uppercase tracking-wider mb-1">Passkey name</label>
                            <input wire:model="passkeyName" type="text" placeholder="e.g. MacBook Touch ID"
                                class="w-full bg-gray-800 border border-gray-700 text-white rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 transition">
                        </div>
                        <button @click="register()"
                            class="bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-5 py-2.5 rounded-xl transition-colors duration-150 shrink-0">
                            Register Passkey
                        </button>
                    </div>
                </div>
            </div>

        </div>
    </main>
</div>