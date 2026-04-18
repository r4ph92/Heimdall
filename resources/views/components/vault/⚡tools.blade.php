<?php

use App\Services\EncryptionService;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Livewire\Component;

new class extends Component
{
    // ── Master password change ────────────────────────────────────
    public string $current_password = '';
    public string $new_password = '';
    public string $new_password_confirmation = '';
    public bool $passwordSaved = false;

    public function getVaultCountProperty(): int
    {
        return auth()->user()->vaultEntries()->count();
    }

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

        $oldKey = base64_decode(session('vault_key'));
        $newSalt = $encryption->generateSalt();
        $newKey  = $encryption->deriveKey($this->new_password, $newSalt);

        foreach ($user->vaultEntries as $entry) {
            $password = $encryption->decrypt($entry->encrypted_password, $entry->iv, $oldKey);
            $notes    = $entry->encrypted_notes
                ? $encryption->decrypt($entry->encrypted_notes, $entry->notes_iv, $oldKey)
                : null;

            $ep = $encryption->encrypt($password, $newKey);
            $en = $notes ? $encryption->encrypt($notes, $newKey) : null;

            $entry->update([
                'encrypted_password' => $ep['ciphertext'],
                'iv'                 => $ep['iv'],
                'encrypted_notes'    => $en ? $en['ciphertext'] : null,
                'notes_iv'           => $en ? $en['iv'] : null,
            ]);
        }

        $user->update(['password' => $this->new_password, 'vault_salt' => $newSalt]);
        session(['vault_key' => base64_encode($newKey)]);

        $this->reset('current_password', 'new_password', 'new_password_confirmation');
        $this->passwordSaved = true;
    }

    public function deleteAccount(): void
    {
        $user = auth()->user();
        $user->vaultEntries()->delete();
        $user->webauthnCredentials()->delete();
        auth()->logout();
        session()->invalidate();
        $user->delete();
        $this->redirect(route('login'));
    }
};
?>

<div class="h-full overflow-y-auto animate-fadein" x-data="{
    autoLock:      localStorage.getItem('h_autolock')  ?? '15',
    timeoutAction: localStorage.getItem('h_timeout')   ?? 'lock',
    biometric:     localStorage.getItem('h_biometric') === 'true',
    autofill:      localStorage.getItem('h_autofill')  !== 'false',

    setAutoLock(v)  { this.autoLock = v;      localStorage.setItem('h_autolock',  v); },
    setTimeout_(v)  { this.timeoutAction = v; localStorage.setItem('h_timeout',   v); },
    toggleBio()     { this.biometric = !this.biometric; localStorage.setItem('h_biometric', this.biometric); },
    toggleFill()    { this.autofill  = !this.autofill;  localStorage.setItem('h_autofill',  this.autofill);  },
}">
<div class="max-w-5xl mx-auto p-8 space-y-6">

    {{-- Page header --}}
    <div class="mb-2">
        <h1 class="text-2xl font-bold text-gray-900 dark:text-white">Security Tools</h1>
        <p class="text-sm text-gray-500 mt-1">Manage vault security, preferences and account data.</p>
    </div>

    <div class="grid grid-cols-3 gap-6 items-start">

        {{-- ── Left column (2/3) ─────────────────────────────────── --}}
        <div class="col-span-2 space-y-6">

            {{-- Security & Authentication --}}
            <div class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl overflow-hidden">

                {{-- Card header --}}
                <div class="px-6 py-5 border-b border-gray-100 dark:border-gray-800 flex items-center gap-3">
                    <div class="w-9 h-9 rounded-xl bg-blue-50 dark:bg-blue-900/20 flex items-center justify-center shrink-0">
                        <svg class="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                        </svg>
                    </div>
                    <div>
                        <h3 class="text-sm font-semibold text-gray-900 dark:text-white">Security & Authentication</h3>
                        <p class="text-xs text-gray-500 mt-0.5">Master password and two-factor authentication</p>
                    </div>
                </div>

                {{-- Change Master Password --}}
                <div class="px-6 py-5 border-b border-gray-100 dark:border-gray-800">
                    <h4 class="text-sm font-semibold text-gray-900 dark:text-white mb-4">Change Master Password</h4>

                    @if($passwordSaved)
                        <div class="mb-4 flex items-center gap-2 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800/40 text-green-700 dark:text-green-400 text-xs rounded-xl px-4 py-3">
                            <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
                            Password updated — all vault entries re-encrypted.
                        </div>
                    @endif

                    <form wire:submit="changeMasterPassword" class="space-y-3">
                        <div x-data="{ show: false }">
                            <label class="block text-xs font-medium text-gray-500 mb-1.5">Current Password</label>
                            <div class="relative">
                                <input wire:model="current_password" :type="show ? 'text' : 'password'"
                                    class="w-full bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-gray-900 dark:text-white rounded-xl px-4 py-2.5 pr-16 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition">
                                <button type="button" @click="show=!show" x-text="show?'Hide':'Show'"
                                    class="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-gray-400 hover:text-gray-700 dark:hover:text-white transition"></button>
                            </div>
                            @error('current_password') <p class="text-red-500 text-xs mt-1">{{ $message }}</p> @enderror
                        </div>

                        <div>
                            <label class="block text-xs font-medium text-gray-500 mb-1.5">New Master Password</label>
                            <x-password-input wire:model.live="new_password" placeholder="Minimum 12 characters" />
                            @error('new_password') <p class="text-red-500 text-xs mt-1">{{ $message }}</p> @enderror
                        </div>

                        <div>
                            <label class="block text-xs font-medium text-gray-500 mb-1.5">Confirm New Password</label>
                            <input wire:model="new_password_confirmation" type="password"
                                class="w-full bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-gray-900 dark:text-white rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition">
                        </div>

                        <div class="pt-1">
                            <button type="submit"
                                class="bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold px-5 py-2.5 rounded-xl transition-colors duration-150"
                                wire:loading.attr="disabled" wire:loading.class="opacity-60">
                                <span wire:loading.remove>Update Password</span>
                                <span wire:loading>Re-encrypting vault…</span>
                            </button>
                        </div>
                    </form>
                </div>

                {{-- MFA status --}}
                <div class="px-6 py-5">
                    <div class="flex items-center justify-between">
                        <div>
                            <h4 class="text-sm font-semibold text-gray-900 dark:text-white">Two-Factor Authentication</h4>
                            <p class="text-xs text-gray-500 mt-1">
                                @if(auth()->user()->hasMfaEnabled())
                                    Active via
                                    <span class="font-medium text-gray-700 dark:text-gray-300">
                                        {{ auth()->user()->two_factor_type === 'totp' ? 'Authenticator app' : 'Email OTP' }}
                                    </span>
                                @else
                                    Not enabled — your account is less secure
                                @endif
                            </p>
                        </div>
                        <div class="flex items-center gap-3">
                            @if(auth()->user()->hasMfaEnabled())
                                <span class="inline-flex items-center gap-1.5 text-xs font-medium text-green-700 dark:text-green-400 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800/40 px-2.5 py-1 rounded-full">
                                    <span class="w-1.5 h-1.5 rounded-full bg-green-500 inline-block"></span>
                                    Enabled
                                </span>
                            @else
                                <span class="inline-flex items-center gap-1.5 text-xs font-medium text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800/40 px-2.5 py-1 rounded-full">
                                    <span class="w-1.5 h-1.5 rounded-full bg-amber-500 inline-block"></span>
                                    Disabled
                                </span>
                            @endif
                            <a wire:navigate href="{{ route('settings') }}"
                                class="text-sm font-medium text-blue-600 hover:text-blue-500 transition">
                                Manage →
                            </a>
                        </div>
                    </div>
                </div>
            </div>

            {{-- Auto-Lock & Access --}}
            <div class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl overflow-hidden">

                <div class="px-6 py-5 border-b border-gray-100 dark:border-gray-800 flex items-center gap-3">
                    <div class="w-9 h-9 rounded-xl bg-blue-50 dark:bg-blue-900/20 flex items-center justify-center shrink-0">
                        <svg class="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                        </svg>
                    </div>
                    <div>
                        <h3 class="text-sm font-semibold text-gray-900 dark:text-white">Auto-Lock & Access</h3>
                        <p class="text-xs text-gray-500 mt-0.5">Configure inactivity timeout and unlock methods</p>
                    </div>
                </div>

                <div class="px-6 py-5 space-y-5">

                    {{-- Auto-lock timer --}}
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-sm font-medium text-gray-900 dark:text-white">Auto-lock after</p>
                            <p class="text-xs text-gray-500 mt-0.5">Lock the vault after this period of inactivity</p>
                        </div>
                        <select
                            x-model="autoLock"
                            @change="setAutoLock($event.target.value)"
                            class="bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-gray-900 dark:text-white text-sm rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
                        >
                            <option value="1">1 minute</option>
                            <option value="5">5 minutes</option>
                            <option value="15">15 minutes</option>
                            <option value="30">30 minutes</option>
                            <option value="60">1 hour</option>
                            <option value="never">Never</option>
                        </select>
                    </div>

                    {{-- Timeout action --}}
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-sm font-medium text-gray-900 dark:text-white">Timeout action</p>
                            <p class="text-xs text-gray-500 mt-0.5">What happens when the timer expires</p>
                        </div>
                        <div class="flex rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden text-sm font-medium">
                            <button
                                @click="setTimeout_('lock')"
                                :class="timeoutAction === 'lock'
                                    ? 'bg-blue-600 text-white'
                                    : 'bg-white dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700'"
                                class="px-4 py-2 transition-colors duration-150">
                                Lock
                            </button>
                            <button
                                @click="setTimeout_('logout')"
                                :class="timeoutAction === 'logout'
                                    ? 'bg-blue-600 text-white'
                                    : 'bg-white dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700'"
                                class="px-4 py-2 border-l border-gray-200 dark:border-gray-700 transition-colors duration-150">
                                Log Out
                            </button>
                        </div>
                    </div>

                    {{-- Biometric --}}
                    <div class="flex items-center justify-between pt-1 border-t border-gray-100 dark:border-gray-800">
                        <div>
                            <p class="text-sm font-medium text-gray-900 dark:text-white">Biometric unlock</p>
                            <p class="text-xs text-gray-500 mt-0.5">Use Touch ID or Face ID to unlock your vault</p>
                        </div>
                        <button @click="toggleBio()"
                            :class="biometric ? 'bg-blue-600' : 'bg-gray-200 dark:bg-gray-700'"
                            class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors duration-200">
                            <span :class="biometric ? 'translate-x-5' : 'translate-x-0.5'"
                                class="inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform duration-200"></span>
                        </button>
                    </div>
                </div>
            </div>
        </div>

        {{-- ── Right column (1/3) ─────────────────────────────────── --}}
        <div class="space-y-5">

            {{-- Account --}}
            <div class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl p-5">
                <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">Account</h3>

                <div class="flex items-center gap-3 mb-4">
                    <div class="w-10 h-10 rounded-full bg-blue-600 flex items-center justify-center text-white font-bold text-sm shrink-0">
                        {{ strtoupper(substr(auth()->user()->name, 0, 2)) }}
                    </div>
                    <div class="min-w-0">
                        <p class="text-sm font-semibold text-gray-900 dark:text-white truncate">{{ auth()->user()->name }}</p>
                        <p class="text-xs text-gray-500 truncate">{{ auth()->user()->email }}</p>
                    </div>
                </div>

                <div class="space-y-0 divide-y divide-gray-100 dark:divide-gray-800 border-t border-gray-100 dark:border-gray-800">
                    <div class="flex items-center justify-between py-2.5">
                        <span class="text-xs text-gray-500">Plan</span>
                        <span class="text-xs font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-800 px-2 py-0.5 rounded-full">Free</span>
                    </div>
                    <div class="flex items-center justify-between py-2.5">
                        <span class="text-xs text-gray-500">Status</span>
                        <span class="inline-flex items-center gap-1.5 text-xs font-medium text-green-700 dark:text-green-400">
                            <span class="w-1.5 h-1.5 rounded-full bg-green-500 inline-block"></span>
                            Active
                        </span>
                    </div>
                    <div class="pt-3">
                        <button class="w-full text-center text-xs font-medium text-blue-600 hover:text-blue-500 transition">
                            Manage Subscription →
                        </button>
                    </div>
                </div>
            </div>

            {{-- Vault Data --}}
            <div class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl p-5">
                <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">Vault Data</h3>

                <div class="flex items-center justify-between mb-4 pb-3 border-b border-gray-100 dark:border-gray-800">
                    <span class="text-xs text-gray-500">Total entries</span>
                    <span class="text-sm font-bold text-gray-900 dark:text-white">{{ $this->vaultCount }}</span>
                </div>

                <div class="space-y-2">
                    <a href="{{ route('vault.export') }}"
                        class="flex items-center gap-2.5 px-3 py-2.5 text-sm text-gray-700 dark:text-gray-300 bg-gray-50 dark:bg-gray-800 hover:bg-gray-100 dark:hover:bg-gray-700 border border-gray-200 dark:border-gray-700 rounded-xl transition-colors duration-150">
                        <svg class="w-4 h-4 text-gray-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                        </svg>
                        Export Vault
                        <span class="ml-auto text-xs text-gray-400">JSON</span>
                    </a>
                    <button
                        class="w-full flex items-center gap-2.5 px-3 py-2.5 text-sm text-gray-700 dark:text-gray-300 bg-gray-50 dark:bg-gray-800 hover:bg-gray-100 dark:hover:bg-gray-700 border border-gray-200 dark:border-gray-700 rounded-xl transition-colors duration-150"
                        title="Import coming soon">
                        <svg class="w-4 h-4 text-gray-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/>
                        </svg>
                        Import Vault
                        <span class="ml-auto text-xs text-gray-400">Soon</span>
                    </button>
                </div>
            </div>

            {{-- Preferences --}}
            <div class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl p-5">
                <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">Preferences</h3>

                <div class="space-y-0 divide-y divide-gray-100 dark:divide-gray-800">

                    {{-- Dark mode --}}
                    <div x-data class="flex items-center justify-between py-3">
                        <div class="flex items-center gap-2.5">
                            <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/>
                            </svg>
                            <span class="text-sm text-gray-700 dark:text-gray-300">Dark Mode</span>
                        </div>
                        <button @click="$store.theme.toggle()"
                            :class="$store.theme.dark ? 'bg-blue-600' : 'bg-gray-200 dark:bg-gray-700'"
                            class="relative inline-flex h-5 w-9 items-center rounded-full transition-colors duration-200">
                            <span :class="$store.theme.dark ? 'translate-x-4' : 'translate-x-0.5'"
                                class="inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform duration-200"></span>
                        </button>
                    </div>

                    {{-- Auto-fill --}}
                    <div class="flex items-center justify-between py-3">
                        <div class="flex items-center gap-2.5">
                            <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
                            </svg>
                            <span class="text-sm text-gray-700 dark:text-gray-300">Browser Auto-fill</span>
                        </div>
                        <button @click="toggleFill()"
                            :class="autofill ? 'bg-blue-600' : 'bg-gray-200 dark:bg-gray-700'"
                            class="relative inline-flex h-5 w-9 items-center rounded-full transition-colors duration-200">
                            <span :class="autofill ? 'translate-x-4' : 'translate-x-0.5'"
                                class="inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform duration-200"></span>
                        </button>
                    </div>

                    {{-- Security Audit link --}}
                    <div class="pt-3">
                        <a wire:navigate href="{{ route('audit') }}"
                            class="flex items-center gap-2 text-xs font-medium text-blue-600 hover:text-blue-500 transition">
                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>
                            </svg>
                            Run Security Audit →
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    {{-- ── Danger Zone ─────────────────────────────────────────────── --}}
    <div class="border border-red-200 dark:border-red-900/50 rounded-2xl overflow-hidden">
        <div class="px-6 py-4 bg-red-50 dark:bg-red-900/10 border-b border-red-200 dark:border-red-900/50">
            <h3 class="text-sm font-semibold text-red-700 dark:text-red-400">Danger Zone</h3>
            <p class="text-xs text-red-600/70 dark:text-red-400/60 mt-0.5">These actions are permanent and cannot be undone.</p>
        </div>
        <div class="px-6 py-5 bg-white dark:bg-gray-900">
            <div class="flex items-start justify-between gap-8">
                <div>
                    <h4 class="text-sm font-medium text-gray-900 dark:text-white">Delete Account</h4>
                    <p class="text-xs text-gray-500 mt-1 leading-relaxed">
                        Permanently delete your Heimdall account, master password, and every vault entry.
                        This operation is irreversible.
                    </p>
                </div>
                <button
                    x-data
                    @click="$store.modal.confirm(
                        'Delete your account? All vault data will be permanently erased and cannot be recovered.',
                        () => $wire.deleteAccount()
                    )"
                    class="shrink-0 px-4 py-2 text-sm font-medium text-red-600 dark:text-red-400 border border-red-300 dark:border-red-800 rounded-xl hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors duration-150"
                >
                    Terminate Vault
                </button>
            </div>
        </div>
    </div>

</div>
</div>
