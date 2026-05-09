<?php

use Livewire\Attributes\On;
use Livewire\Component;

new class extends Component
{
    // Which panel is shown in the main area: 'list' | 'detail' | 'create' | 'edit' | 'tools'
    public string $activeView = 'list';
    public ?int $selectedEntryId = null;

    public function mount(): void
    {
        $view = request()->query('view');
        if (in_array($view, ['create', 'tools'])) {
            $this->activeView = $view;
        }
    }

    #[On('view-entry')]
    public function viewEntry(int $id): void
    {
        $this->selectedEntryId = $id;
        $this->activeView = 'detail';
    }

    #[On('edit-entry')]
    public function editEntry(int $id): void
    {
        $this->selectedEntryId = $id;
        $this->activeView = 'edit';
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

    #[On('show-tools')]
    public function showTools(): void
    {
        $this->selectedEntryId = null;
        $this->activeView = 'tools';
    }
};
?>

<div class="flex h-screen bg-gray-100 dark:bg-gray-950 text-gray-900 dark:text-white overflow-hidden animate-fadein"
    x-data="{
        _timer: null,
        _reset() {
            const mins = localStorage.getItem('h_autolock') ?? '15';
            if (mins === 'never') { clearTimeout(this._timer); return; }
            clearTimeout(this._timer);
            this._timer = setTimeout(() => this._expire(), parseInt(mins) * 60 * 1000);
        },
        _expire() {
            const action = localStorage.getItem('h_timeout') ?? 'lock';
            const token  = document.querySelector('meta[name=csrf-token]')?.content ?? '';
            const url    = action === 'logout' ? '/logout' : '/vault/lock';
            fetch(url, { method: 'POST', headers: { 'X-CSRF-TOKEN': token } })
                .finally(() => { window.location.href = action === 'logout' ? '/login' : '/vault/unlock'; });
        }
    }"
    x-init="
        _reset();
        ['mousemove','keydown','click','touchstart'].forEach(ev =>
            window.addEventListener(ev, () => _reset(), { passive: true })
        );
    ">

    <x-app-sidebar :active="$activeView" />

    {{-- Main panel --}}
    <main class="flex-1 overflow-y-auto pt-14 md:pt-0 pb-16 md:pb-0">
        @if ($activeView === 'list' || $activeView === 'detail')
            <livewire:vault.entry-list :selectedEntryId="$selectedEntryId" :key="'list-'.$selectedEntryId" />
        @elseif ($activeView === 'create')
            <livewire:vault.create-entry :key="'create'" />
        @elseif ($activeView === 'edit')
            <livewire:vault.entry-detail :entryId="$selectedEntryId" :key="'edit-'.$selectedEntryId" />
        @elseif ($activeView === 'tools')
            <livewire:vault.tools :key="'tools'" />
        @endif
    </main>

</div>
