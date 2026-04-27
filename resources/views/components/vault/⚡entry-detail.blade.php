<?php

use App\Models\VaultEntry;
use App\Services\EncryptionService;
use Livewire\Component;

new class extends Component
{
    public int $entryId;
    public string $service_name = '';
    public string $username = '';
    public string $url = '';
    public string $password = '';
    public string $notes = '';

    public function mount(int $entryId, EncryptionService $encryption): void
    {
        $entry = VaultEntry::where('user_id', auth()->id())->findOrFail($entryId);
        $key = base64_decode(session('vault_key'));

        $this->entryId = $entryId;
        $this->service_name = $entry->service_name;
        $this->username = $entry->username ?? '';
        $this->url = $entry->url ?? '';
        $this->password = $encryption->decrypt($entry->encrypted_password, $entry->iv, $key);
        $this->notes = $entry->encrypted_notes && $entry->notes_iv
            ? $encryption->decrypt($entry->encrypted_notes, $entry->notes_iv, $key)
            : '';
    }

    public function save(EncryptionService $encryption): void
    {
        $this->validate([
            'service_name' => ['required', 'string', 'max:255'],
            'username'     => ['nullable', 'string', 'max:255'],
            'url'          => ['nullable', 'url', 'max:255'],
            'password'     => ['required', 'string'],
            'notes'        => ['nullable', 'string'],
        ]);

        $key = base64_decode(session('vault_key'));

        // Always generate a fresh IV on update — reusing IVs with AES-GCM leaks keystream
        $encryptedPassword = $encryption->encrypt($this->password, $key);
        $encryptedNotes    = $this->notes ? $encryption->encrypt($this->notes, $key) : null;

        VaultEntry::where('user_id', auth()->id())->findOrFail($this->entryId)->update([
            'service_name'       => $this->service_name,
            'username'           => $this->username ?: null,
            'url'                => $this->url ?: null,
            'encrypted_password' => $encryptedPassword['ciphertext'],
            'iv'                 => $encryptedPassword['iv'],
            'encrypted_notes'    => $encryptedNotes ? $encryptedNotes['ciphertext'] : null,
            'notes_iv'           => $encryptedNotes ? $encryptedNotes['iv'] : null,
        ]);

        $this->dispatch('entry-saved');
    }
};
?>

<div
    class="h-full flex items-start justify-center p-8 overflow-y-auto"
    x-data
    x-init="$el.style.opacity=0; $el.style.transform='translateY(10px)';
            requestAnimationFrame(() => {
                $el.style.transition='opacity 220ms ease, transform 220ms ease';
                $el.style.opacity=1;
                $el.style.transform='translateY(0)';
            })"
>
    <div class="w-full max-w-lg">
        <div class="flex items-center gap-3 mb-6">
            <button wire:click="$dispatch('back-to-list')" class="text-gray-500 hover:text-gray-900 dark:hover:text-white transition-colors duration-150">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/></svg>
            </button>
            <h2 class="text-xl font-semibold text-gray-900 dark:text-white">Edit Entry</h2>
        </div>

        <form wire:submit="save" class="space-y-4">
            <div>
                <label class="block text-xs text-gray-500 uppercase tracking-wider mb-1">Service Name <span class="text-red-400">*</span></label>
                <input
                    wire:model="service_name"
                    type="text"
                    placeholder="e.g. GitHub, Netflix…"
                    class="w-full bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 text-gray-900 dark:text-white rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 transition"
                    autofocus
                >
                @error('service_name') <p class="text-red-500 dark:text-red-400 text-xs mt-1">{{ $message }}</p> @enderror
            </div>

            <div>
                <label class="block text-xs text-gray-500 uppercase tracking-wider mb-1">Username / Email</label>
                <input
                    wire:model="username"
                    type="text"
                    placeholder="you@example.com"
                    class="w-full bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 text-gray-900 dark:text-white rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 transition"
                >
                @error('username') <p class="text-red-500 dark:text-red-400 text-xs mt-1">{{ $message }}</p> @enderror
            </div>

            <div>
                <label class="block text-xs text-gray-500 uppercase tracking-wider mb-1">URL</label>
                <input
                    wire:model="url"
                    type="url"
                    placeholder="https://github.com"
                    class="w-full bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 text-gray-900 dark:text-white rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 transition"
                >
                @error('url') <p class="text-red-500 dark:text-red-400 text-xs mt-1">{{ $message }}</p> @enderror
            </div>

            <div>
                <label class="block text-xs text-gray-500 uppercase tracking-wider mb-1">Password <span class="text-red-400">*</span></label>
                <x-password-input wire:model.live="password" placeholder="Enter or paste a password" />
                @error('password') <p class="text-red-500 dark:text-red-400 text-xs mt-1">{{ $message }}</p> @enderror
            </div>

            <div>
                <label class="block text-xs text-gray-500 uppercase tracking-wider mb-1">Notes</label>
                <textarea
                    wire:model="notes"
                    rows="3"
                    placeholder="Recovery codes, security questions…"
                    class="w-full bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 text-gray-900 dark:text-white rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 transition resize-none"
                ></textarea>
            </div>

            <div class="flex items-center gap-3 pt-2">
                <button
                    type="submit"
                    class="bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-6 py-2.5 rounded-xl transition-colors duration-150"
                    wire:loading.attr="disabled"
                    wire:loading.class="opacity-60"
                >
                    <span wire:loading.remove>Save Changes</span>
                    <span wire:loading>Saving…</span>
                </button>
                <button
                    type="button"
                    wire:click="$dispatch('back-to-list')"
                    class="text-gray-500 hover:text-gray-900 dark:hover:text-white text-sm transition-colors duration-150"
                >
                    Cancel
                </button>
            </div>
        </form>
    </div>
</div>
