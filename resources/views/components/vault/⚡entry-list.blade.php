<?php

use App\Models\VaultEntry;
use App\Services\EncryptionService;
use Livewire\Component;

new class extends Component
{
    public ?int $selectedEntryId = null;
    public string $search = '';
    public ?array $decrypted = null;

    public function mount(?int $selectedEntryId = null): void
    {
        $this->selectedEntryId = $selectedEntryId;
        if ($selectedEntryId) {
            $this->loadEntry($selectedEntryId);
        }
    }

    public function selectEntry(int $id, EncryptionService $encryption): void
    {
        $this->selectedEntryId = $id;
        $this->loadEntry($id, $encryption);
        $this->dispatch('view-entry', id: $id);
    }

    public function loadEntry(int $id, ?EncryptionService $encryption = null): void
    {
        $entry = VaultEntry::where('user_id', auth()->id())->findOrFail($id);
        $encryption ??= app(EncryptionService::class);
        $key = base64_decode(session('vault_key'));

        $this->decrypted = [
            'id'           => $entry->id,
            'service_name' => $entry->service_name,
            'username'     => $entry->username,
            'url'          => $entry->url,
            'password'     => $encryption->decrypt($entry->encrypted_password, $entry->iv, $key),
            'notes'        => $entry->encrypted_notes && $entry->notes_iv
                ? $encryption->decrypt($entry->encrypted_notes, $entry->notes_iv, $key)
                : null,
            'updated_at'   => $entry->updated_at->diffForHumans(),
        ];
    }

    public function deleteEntry(int $id): void
    {
        VaultEntry::where('user_id', auth()->id())->findOrFail($id)->delete();
        $this->selectedEntryId = null;
        $this->decrypted = null;
        $this->dispatch('back-to-list');
    }

    public function getEntriesProperty()
    {
        return VaultEntry::where('user_id', auth()->id())
            ->when($this->search, fn ($q) => $q
                ->where('service_name', 'like', '%'.$this->search.'%')
                ->orWhere('username', 'like', '%'.$this->search.'%'))
            ->orderBy('service_name')
            ->get();
    }
};
?>

<div class="flex h-full animate-fadein">

    {{-- Entry list column --}}
    <div class="w-80 shrink-0 border-r border-gray-200 dark:border-gray-800 flex flex-col">
        <div class="px-4 py-4 border-b border-gray-200 dark:border-gray-800 space-y-3">
            <h2 class="text-sm font-semibold text-gray-600 dark:text-gray-300 uppercase tracking-wider">Vault</h2>
            <div class="relative">
                <svg class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M17 11A6 6 0 1 1 5 11a6 6 0 0 1 12 0z"/>
                </svg>
                <input
                    wire:model.live.debounce.300ms="search"
                    type="text"
                    placeholder="Search…"
                    class="w-full bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 text-gray-900 dark:text-white text-sm rounded-lg pl-9 pr-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition"
                >
            </div>
        </div>

        <div class="flex-1 overflow-y-auto py-2 space-y-0.5 px-2">
            @forelse ($this->entries as $entry)
                <button
                    wire:click="selectEntry({{ $entry->id }})"
                    wire:key="entry-{{ $entry->id }}"
                    class="w-full text-left px-3 py-3 flex items-center gap-3 rounded-lg transition-colors duration-150 border
                        {{ $selectedEntryId === $entry->id
                            ? 'bg-indigo-600/20 border-indigo-500/30'
                            : 'hover:bg-gray-100 dark:hover:bg-gray-800 border-transparent' }}"
                >
                    @php $domain = $entry->url ? parse_url($entry->url, PHP_URL_HOST) : null; @endphp
                    <div class="w-9 h-9 rounded-lg bg-indigo-600/30 flex items-center justify-center text-indigo-300 font-bold text-sm shrink-0 overflow-hidden"
                        x-data="{ err: false }">
                        @if($domain)
                            <img x-show="!err" x-on:error="err = true"
                                src="https://icon.horse/icon/{{ $domain }}"
                                alt="{{ $entry->service_name }}"
                                class="w-full h-full object-contain p-1.5">
                            <span x-show="err">{{ strtoupper(substr($entry->service_name, 0, 1)) }}</span>
                        @else
                            {{ strtoupper(substr($entry->service_name, 0, 1)) }}
                        @endif
                    </div>
                    <div class="min-w-0">
                        <p class="text-sm font-medium text-gray-900 dark:text-white truncate">{{ $entry->service_name }}</p>
                        <p class="text-xs text-gray-500 truncate">{{ $entry->username ?? $entry->url ?? '—' }}</p>
                    </div>
                </button>
            @empty
                <div class="px-4 py-10 text-center">
                    <p class="text-gray-500 text-sm">No entries yet.</p>
                    <button wire:click="$dispatch('create-entry')" class="mt-2 text-indigo-400 text-sm hover:underline">Add your first entry</button>
                </div>
            @endforelse
        </div>
    </div>

    {{-- Detail panel --}}
    <div class="flex-1 p-8 overflow-y-auto">
        @if ($decrypted)
            <div
                x-data
                x-init="$el.style.opacity=0; $el.style.transform='translateY(8px)';
                        requestAnimationFrame(() => {
                            $el.style.transition='opacity 200ms ease, transform 200ms ease';
                            $el.style.opacity=1;
                            $el.style.transform='translateY(0)';
                        })"
                class="max-w-lg"
            >
                <div class="flex items-center justify-between mb-6">
                    <div class="flex items-center gap-4">
                        @php $detailDomain = $decrypted['url'] ? parse_url($decrypted['url'], PHP_URL_HOST) : null; @endphp
                        <div class="w-12 h-12 rounded-xl bg-indigo-600/30 flex items-center justify-center text-indigo-300 font-bold text-lg overflow-hidden"
                            x-data="{ err: false }">
                            @if($detailDomain)
                                <img x-show="!err" x-on:error="err = true"
                                    src="https://icon.horse/icon/{{ $detailDomain }}"
                                    alt="{{ $decrypted['service_name'] }}"
                                    class="w-full h-full object-contain p-2">
                                <span x-show="err" class="text-lg">{{ strtoupper(substr($decrypted['service_name'], 0, 1)) }}</span>
                            @else
                                {{ strtoupper(substr($decrypted['service_name'], 0, 1)) }}
                            @endif
                        </div>
                        <div>
                            <h2 class="text-xl font-semibold text-gray-900 dark:text-white">{{ $decrypted['service_name'] }}</h2>
                            <p class="text-xs text-gray-500">Updated {{ $decrypted['updated_at'] }}</p>
                        </div>
                    </div>
                    <div class="flex items-center gap-2">
                        <button
                            wire:click="$dispatch('edit-entry', { id: {{ $decrypted['id'] }} })"
                            class="text-gray-400 dark:text-gray-600 hover:text-indigo-400 transition-colors duration-150"
                            title="Edit entry"
                        >
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
                        </button>
                        <button
                            x-data
                            @click="$store.modal.confirm(
                                'Delete this entry? This cannot be undone.',
                                () => $wire.deleteEntry({{ $decrypted['id'] }})
                            )"
                            class="text-gray-400 dark:text-gray-600 hover:text-red-400 transition-colors duration-150"
                            title="Delete entry"
                        >
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                        </button>
                    </div>
                </div>

                <div class="space-y-3">
                    @if ($decrypted['username'])
                        {{-- data-copy holds the value; Alpine reads it from the DOM instead of
                             interpolating it into a JS string, which avoids XSS/injection risks --}}
                        <div
                            class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4 flex items-center justify-between gap-3"
                            x-data="{ copied: false }"
                            data-copy="{{ $decrypted['username'] }}"
                        >
                            <div class="min-w-0">
                                <p class="text-xs text-gray-500 uppercase tracking-wider mb-1">Username</p>
                                <p class="text-gray-900 dark:text-white text-sm truncate">{{ $decrypted['username'] }}</p>
                            </div>
                            <button
                                @click="navigator.clipboard.writeText($el.closest('[data-copy]').dataset.copy).then(() => { copied = true; setTimeout(() => copied = false, 1500) })"
                                class="text-xs text-indigo-400 hover:text-indigo-300 transition shrink-0"
                                x-text="copied ? 'Copied!' : 'Copy'"
                            ></button>
                        </div>
                    @endif

                    @if ($decrypted['url'])
                        <div class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4 flex items-center justify-between gap-3">
                            <div class="min-w-0">
                                <p class="text-xs text-gray-500 uppercase tracking-wider mb-1">URL</p>
                                <a href="{{ $decrypted['url'] }}" target="_blank" rel="noopener noreferrer" class="text-indigo-400 text-sm hover:underline truncate block">{{ $decrypted['url'] }}</a>
                            </div>
                        </div>
                    @endif

                    <div
                        class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4"
                        x-data="{ show: false, copied: false }"
                        data-copy="{{ $decrypted['password'] }}"
                    >
                        <p class="text-xs text-gray-500 uppercase tracking-wider mb-2">Password</p>
                        <div class="flex items-center justify-between gap-3">
                            <p class="text-gray-900 dark:text-white font-mono text-sm break-all flex-1">
                                <span x-show="!show">••••••••••••</span>
                                <span x-show="show" x-cloak>{{ $decrypted['password'] }}</span>
                            </p>
                            <div class="flex items-center gap-3 shrink-0">
                                <button @click="show = !show" class="text-xs text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition" x-text="show ? 'Hide' : 'Show'"></button>
                                <button
                                    @click="navigator.clipboard.writeText($el.closest('[data-copy]').dataset.copy).then(() => { copied = true; setTimeout(() => copied = false, 1500) })"
                                    class="text-xs text-indigo-400 hover:text-indigo-300 transition"
                                    x-text="copied ? 'Copied!' : 'Copy'"
                                ></button>
                            </div>
                        </div>
                    </div>

                    @if ($decrypted['notes'])
                        <div class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4">
                            <p class="text-xs text-gray-500 uppercase tracking-wider mb-1">Notes</p>
                            <p class="text-gray-700 dark:text-gray-300 text-sm whitespace-pre-wrap">{{ $decrypted['notes'] }}</p>
                        </div>
                    @endif
                </div>

                <div class="mt-6">
                    <button wire:click="$dispatch('create-entry')" class="text-sm text-indigo-400 hover:text-indigo-300 transition">
                        + Add another entry
                    </button>
                </div>
            </div>
        @else
            <div class="h-full flex items-center justify-center animate-fadein">
                <div class="text-center">
                    <div class="w-16 h-16 rounded-2xl bg-gray-100 dark:bg-gray-800 flex items-center justify-center mx-auto mb-4">
                        <svg class="w-8 h-8 text-gray-400 dark:text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                    </div>
                    <p class="text-gray-500 text-sm">Select an entry to view details</p>
                    <p class="text-gray-400 dark:text-gray-600 text-xs mt-1">or create a new one</p>
                </div>
            </div>
        @endif
    </div>

</div>
