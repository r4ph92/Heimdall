<?php

use App\Models\User;
use App\Services\EncryptionService;
use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Facades\Auth;
use Livewire\Component;

new class extends Component
{
    public string $name = '';
    public string $email = '';
    public string $password = '';
    public string $password_confirmation = '';

    public function register(EncryptionService $encryption): void
    {
        $this->validate([
            'name'     => ['required', 'string', 'max:255'],
            'email'    => ['required', 'email', 'max:255', 'unique:users,email'],
            'password' => ['required', 'string', 'min:12', 'confirmed'],
        ]);

        // Generate a unique random salt for this user.
        // This salt is combined with the master password via PBKDF2 to derive
        // the AES encryption key — the server never stores or knows the key itself.
        $salt = $encryption->generateSalt();

        $user = User::create([
            'name'       => $this->name,
            'email'      => $this->email,
            'password'   => $this->password, // hashed automatically by the 'hashed' cast
            'vault_salt' => $salt,
        ]);

        event(new Registered($user));

        // Derive the encryption key from the master password and store it in the
        // session. It will be used to encrypt/decrypt vault entries until logout.
        $encryptionKey = $encryption->deriveKey($this->password, $salt);
        session([
            'vault_key'    => base64_encode($encryptionKey),
            'mfa_verified' => true, // new accounts have no MFA configured yet
        ]);

        Auth::login($user);

        $this->redirect(route('dashboard'), navigate: true);
    }
};
?>

<div class="min-h-screen flex items-center justify-center bg-gray-950">
    <div class="w-full max-w-md bg-gray-900 rounded-2xl shadow-xl p-8">
        <div class="mb-8 text-center">
            <h1 class="text-3xl font-bold text-white tracking-tight">Heimdall</h1>
            <p class="text-gray-400 mt-1 text-sm">Create your secure vault</p>
        </div>

        <form wire:submit="register" class="space-y-5">
            <div>
                <label class="block text-sm font-medium text-gray-300 mb-1" for="name">Name</label>
                <input
                    wire:model="name"
                    id="name"
                    type="text"
                    autocomplete="name"
                    class="w-full bg-gray-800 border border-gray-700 text-white rounded-lg px-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    placeholder="John Doe"
                >
                @error('name') <p class="text-red-400 text-xs mt-1">{{ $message }}</p> @enderror
            </div>

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
                    autocomplete="new-password"
                    class="w-full bg-gray-800 border border-gray-700 text-white rounded-lg px-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    placeholder="Minimum 12 characters"
                >
                @error('password') <p class="text-red-400 text-xs mt-1">{{ $message }}</p> @enderror
            </div>

            <div>
                <label class="block text-sm font-medium text-gray-300 mb-1" for="password_confirmation">Confirm Master Password</label>
                <input
                    wire:model="password_confirmation"
                    id="password_confirmation"
                    type="password"
                    autocomplete="new-password"
                    class="w-full bg-gray-800 border border-gray-700 text-white rounded-lg px-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    placeholder="Repeat your master password"
                >
            </div>

            <p class="text-xs text-yellow-500">
                ⚠ Your master password cannot be recovered. If you lose it, your vault is permanently inaccessible.
            </p>

            <button
                type="submit"
                class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold py-2.5 rounded-lg transition"
                wire:loading.attr="disabled"
            >
                <span wire:loading.remove>Create Vault</span>
                <span wire:loading>Creating…</span>
            </button>
        </form>

        <p class="text-center text-gray-500 text-sm mt-6">
            Already have an account?
            <a wire:navigate href="{{ route('login') }}" class="text-indigo-400 hover:underline">Sign in</a>
        </p>
    </div>
</div>