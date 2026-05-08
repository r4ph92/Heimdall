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

<div class="flex h-screen bg-gray-100 dark:bg-gray-950 text-gray-900 dark:text-white overflow-hidden animate-fadein">

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
