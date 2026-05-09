<?php

use App\Services\EncryptionService;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Livewire\Component;

new class extends Component
{
    public string $password = '';

    public function unlock(EncryptionService $encryption): void
    {
        $this->validate(['password' => ['required', 'string']]);

        $user = auth()->user();

        if (! Hash::check($this->password, $user->password)) {
            throw ValidationException::withMessages([
                'password' => 'Incorrect master password.',
            ]);
        }

        $key = $encryption->deriveKey($this->password, $user->vault_salt);
        session([
            'vault_key'             => base64_encode($key),
            'mfa_verified'          => true,
            'passkey_authenticated' => false,
        ]);

        $this->redirect(route('dashboard'), navigate: true);
    }
};
?>

<div class="min-h-screen flex items-center justify-center bg-gray-950 animate-fadein">
    <div class="w-full max-w-sm bg-gray-900 rounded-2xl shadow-xl p-8">
        <div class="mb-6 text-center">
            <div class="w-12 h-12 rounded-xl bg-indigo-600/20 flex items-center justify-center mx-auto mb-3">
                <svg class="w-6 h-6 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                </svg>
            </div>
            <h1 class="text-xl font-bold text-white">Unlock Your Vault</h1>
            <p class="text-gray-400 text-sm mt-1">
                Signed in as <span class="text-indigo-400">{{ auth()->user()->email }}</span>.<br>
                Enter your master password to decrypt your vault.
            </p>
        </div>

        <form wire:submit="unlock" class="space-y-4">
            <div>
                <input
                    wire:model="password"
                    type="password"
                    autocomplete="current-password"
                    placeholder="Master password"
                    class="w-full bg-gray-800 border border-gray-700 text-white rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition"
                    autofocus
                >
                @error('password') <p class="text-red-400 text-xs mt-1">{{ $message }}</p> @enderror
            </div>

            <button
                type="submit"
                class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold py-2.5 rounded-xl transition-colors duration-150"
                wire:loading.attr="disabled" wire:loading.class="opacity-60"
            >
                <span wire:loading.remove>Unlock Vault</span>
                <span wire:loading>Unlocking…</span>
            </button>
        </form>

        <div class="mt-5 text-center">
            <form method="POST" action="{{ route('logout') }}">
                @csrf
                <button type="submit" class="text-xs text-gray-600 hover:text-gray-400 transition">
                    Sign out
                </button>
            </form>
        </div>
    </div>
</div>
