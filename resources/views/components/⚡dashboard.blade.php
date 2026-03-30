<?php

use Livewire\Attributes\On;
use Livewire\Component;

new class extends Component
{
    // Which panel is shown in the main area: 'list' | 'detail' | 'create'
    public string $activeView = 'list';
    public ?int $selectedEntryId = null;

    #[On('view-entry')]
    public function viewEntry(int $id): void
    {
        $this->selectedEntryId = $id;
        $this->activeView = 'detail';
    }

    #[On('create-entry')]
    public function showCreate(): void
    {
        $this->selectedEntryId = null;
        $this->activeView = 'create';
    }

    #[On('back-to-list')]
    public function backToList(): void
    {
        $this->selectedEntryId = null;
        $this->activeView = 'list';
    }

    #[On('entry-saved')]
    public function onEntrySaved(): void
    {
        $this->activeView = 'list';
        $this->selectedEntryId = null;
    }
};
?>

<div class="flex h-screen bg-gray-950 text-white overflow-hidden animate-fadein">

    {{-- Sidebar --}}
    <aside class="w-64 shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col">
        {{-- Logo --}}
        <div class="px-6 py-5 border-b border-gray-800">
            <h1 class="text-xl font-bold tracking-tight text-white">⚡ Heimdall</h1>
            <p class="text-xs text-gray-500 mt-0.5">{{ auth()->user()->name }}</p>
        </div>

        {{-- Nav --}}
        <nav class="flex-1 px-3 py-4 space-y-1">
            <button
                wire:click="$dispatch('back-to-list')"
                class="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors duration-150
                    {{ in_array($activeView, ['list', 'detail']) ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:bg-gray-800 hover:text-white' }}"
            >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>
                My Vault
            </button>

            <button
                wire:click="$dispatch('create-entry')"
                class="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors duration-150
                    {{ $activeView === 'create' ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:bg-gray-800 hover:text-white' }}"
            >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
                New Entry
            </button>

            <a
                wire:navigate href="{{ route('settings') }}"
                class="flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-gray-400 hover:bg-gray-800 hover:text-white transition-colors duration-150"
            >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><circle cx="12" cy="12" r="3"/></svg>
                Settings
            </a>
        </nav>

        {{-- Logout --}}
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

    {{-- Main panel --}}
    <main class="flex-1 overflow-y-auto">
        @if ($activeView === 'list' || $activeView === 'detail')
            <livewire:vault.entry-list :selectedEntryId="$selectedEntryId" :key="'list-'.$selectedEntryId" />
        @elseif ($activeView === 'create')
            <livewire:vault.create-entry :key="'create'" />
        @endif
    </main>

</div>