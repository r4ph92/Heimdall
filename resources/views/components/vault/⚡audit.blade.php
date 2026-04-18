<?php

use App\Models\VaultEntry;
use App\Services\EncryptionService;
use Illuminate\Validation\ValidationException;
use Livewire\Component;

new class extends Component
{
    public string $search = '';
    public string $filter = 'all'; // all | issues | weak | reused

    public ?int   $editingEntryId  = null;
    public string $editNewPassword = '';
    public bool   $editSaved       = false;

    // Computed stats — populated on mount, refreshed after each password save
    public int   $securityScore = 100;
    public int   $weakCount     = 0;
    public int   $reusedCount   = 0;
    public int   $oldCount      = 0;
    public array $auditResults  = [];

    public function mount(EncryptionService $encryption): void
    {
        $this->runAudit($encryption);
    }

    public function runAudit(EncryptionService $encryption): void
    {
        $user    = auth()->user();
        $key     = base64_decode(session('vault_key'));
        $entries = $user->vaultEntries()->orderBy('service_name')->get();

        if ($entries->isEmpty()) {
            $this->securityScore = 100;
            $this->auditResults  = [];
            $this->weakCount     = $this->reusedCount = $this->oldCount = 0;
            return;
        }

        // Decrypt passwords for analysis only (never stored in Livewire state)
        $plaintexts = [];
        foreach ($entries as $entry) {
            $plaintexts[$entry->id] = $encryption->decrypt($entry->encrypted_password, $entry->iv, $key);
        }

        // Reuse detection via SHA-256 fingerprint (safe to store fingerprints, not plaintexts)
        $fingerprints  = array_map(fn ($p) => hash('sha256', $p), $plaintexts);
        $fingerprintCounts = array_count_values($fingerprints);

        $results = [];
        $weak = $reused = $old = 0;

        foreach ($entries as $entry) {
            $pw       = $plaintexts[$entry->id];
            $entropy  = $this->entropy($pw);
            $isWeak   = $entropy < 50;
            $isReused = $fingerprintCounts[$fingerprints[$entry->id]] > 1;
            $daysOld  = (int) $entry->updated_at->diffInDays(now());
            $isOld    = $daysOld > 90;

            if ($isWeak)   $weak++;
            if ($isReused) $reused++;
            if ($isOld)    $old++;

            $issues = [];
            if ($isWeak)   $issues[] = ['type' => 'weak',   'label' => 'Weak password'];
            if ($isReused) $issues[] = ['type' => 'reused', 'label' => 'Reused'];
            if ($isOld)    $issues[] = ['type' => 'old',    'label' => ceil($daysOld / 30) . 'm old'];

            $results[] = [
                'id'           => $entry->id,
                'service_name' => $entry->service_name,
                'username'     => $entry->username ?? '—',
                'url'          => $entry->url,
                'entropy'      => $entropy,
                'strength'     => $this->strengthLabel($entropy),
                'strength_color' => $this->strengthColor($entropy),
                'updated_at'   => $entry->updated_at->diffForHumans(),
                'days_old'     => $daysOld,
                'is_weak'      => $isWeak,
                'is_reused'    => $isReused,
                'is_old'       => $isOld,
                'has_issues'   => $isWeak || $isReused || $isOld,
                'issues'       => $issues,
                'domain'       => $entry->url ? parse_url($entry->url, PHP_URL_HOST) : null,
                'needs_mfa'    => false, // service-level MFA not tracked
            ];
        }

        $total    = count($results);
        $noMfa    = ! auth()->user()->hasMfaEnabled();
        $score    = 100
            - ($weak   / $total) * 30
            - ($reused / $total) * 25
            - ($old    / $total) * 15
            - ($noMfa  ? 15 : 0);

        $this->weakCount     = $weak;
        $this->reusedCount   = $reused;
        $this->oldCount      = $old;
        $this->securityScore = (int) max(0, min(100, round($score)));
        $this->auditResults  = $results;
        $this->editSaved     = false;
    }

    public function getFilteredResultsProperty(): array
    {
        return array_values(array_filter($this->auditResults, function ($r) {
            if ($this->filter === 'issues' && ! $r['has_issues']) return false;
            if ($this->filter === 'weak'   && ! $r['is_weak'])    return false;
            if ($this->filter === 'reused' && ! $r['is_reused'])  return false;

            if ($this->search) {
                $q = mb_strtolower($this->search);
                return str_contains(mb_strtolower($r['service_name']), $q)
                    || str_contains(mb_strtolower($r['username']), $q);
            }
            return true;
        }));
    }

    public function getCircleParamsProperty(): array
    {
        $r = 52;
        $c = 2 * M_PI * $r;
        $color = match (true) {
            $this->securityScore >= 80 => '#22c55e',
            $this->securityScore >= 60 => '#eab308',
            $this->securityScore >= 40 => '#f97316',
            default                    => '#ef4444',
        };
        return [
            'c'      => $c,
            'dash'   => ($this->securityScore / 100) * $c,
            'color'  => $color,
        ];
    }

    public function editEntry(int $id): void
    {
        $this->editingEntryId  = $id;
        $this->editNewPassword = '';
        $this->editSaved       = false;
    }

    public function cancelEdit(): void
    {
        $this->editingEntryId  = null;
        $this->editNewPassword = '';
    }

    public function savePassword(EncryptionService $encryption): void
    {
        $this->validate(['editNewPassword' => 'required|string|min:1']);

        $entry = VaultEntry::where('user_id', auth()->id())->findOrFail($this->editingEntryId);
        $key   = base64_decode(session('vault_key'));
        $enc   = $encryption->encrypt($this->editNewPassword, $key);

        $entry->update([
            'encrypted_password' => $enc['ciphertext'],
            'iv'                 => $enc['iv'],
        ]);

        $this->editingEntryId  = null;
        $this->editNewPassword = '';
        $this->editSaved       = true;

        $this->runAudit($encryption);
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private function entropy(string $pw): int
    {
        if (! $pw) return 0;
        $cs = 26;
        if (preg_match('/[A-Z]/', $pw))        $cs += 26;
        if (preg_match('/[0-9]/', $pw))        $cs += 10;
        if (preg_match('/[^a-zA-Z0-9]/', $pw)) $cs += 32;
        return (int) floor(strlen($pw) * log($cs, 2));
    }

    private function strengthLabel(int $e): string
    {
        return match (true) {
            $e >= 100 => 'Excellent',
            $e >= 80  => 'Very Strong',
            $e >= 60  => 'Strong',
            $e >= 40  => 'Fair',
            default   => 'Weak',
        };
    }

    private function strengthColor(int $e): string
    {
        return match (true) {
            $e >= 80 => 'text-green-600 dark:text-green-400',
            $e >= 60 => 'text-blue-600 dark:text-blue-400',
            $e >= 40 => 'text-amber-600 dark:text-amber-400',
            default  => 'text-red-600 dark:text-red-400',
        };
    }
};
?>

<div class="flex h-screen bg-gray-100 dark:bg-gray-950 text-gray-900 dark:text-white overflow-hidden animate-fadein">

    {{-- Sidebar --}}
    <aside class="w-64 shrink-0 bg-white dark:bg-gray-900 border-r border-gray-200 dark:border-gray-800 flex flex-col">
        <div class="px-6 py-5 border-b border-gray-200 dark:border-gray-800">
            <h1 class="text-xl font-bold tracking-tight text-gray-900 dark:text-white">⚡ Heimdall</h1>
            <p class="text-xs text-gray-500 mt-0.5">{{ auth()->user()->name }}</p>
        </div>

        <nav class="flex-1 px-3 py-4 space-y-1">
            <a wire:navigate href="{{ route('dashboard') }}"
                class="flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-white transition-colors duration-150">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>
                My Vault
            </a>
            <a wire:navigate href="{{ route('audit') }}"
                class="flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium bg-blue-600 text-white transition-colors duration-150">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/></svg>
                Security Audit
            </a>
            <a wire:navigate href="{{ route('settings') }}"
                class="flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-white transition-colors duration-150">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><circle cx="12" cy="12" r="3"/></svg>
                Settings
            </a>
        </nav>

        <div class="px-3 py-4 border-t border-gray-200 dark:border-gray-800 space-y-1">
            <button x-data @click="$store.theme.toggle()"
                class="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-white transition-colors duration-150">
                <template x-if="$store.theme.dark">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707M17.657 17.657l-.707-.707M6.343 6.343l-.707-.707M12 7a5 5 0 100 10A5 5 0 0012 7z"/></svg>
                </template>
                <template x-if="!$store.theme.dark">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
                </template>
                <span x-text="$store.theme.dark ? 'Light mode' : 'Dark mode'"></span>
            </button>
            <form method="POST" action="{{ route('logout') }}">
                @csrf
                <button type="submit" class="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-gray-600 dark:text-gray-400 hover:bg-red-50 dark:hover:bg-red-900/40 hover:text-red-500 dark:hover:text-red-400 transition-colors duration-150">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/></svg>
                    Lock & Logout
                </button>
            </form>
        </div>
    </aside>

    {{-- Main content --}}
    <main class="flex-1 flex flex-col overflow-hidden">

        {{-- Top bar --}}
        <div class="shrink-0 px-8 py-5 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800 flex items-center justify-between gap-6">
            <div>
                <h2 class="text-xl font-bold text-gray-900 dark:text-white">Security Audit</h2>
                <p class="text-xs text-gray-500 mt-0.5">{{ count($this->auditResults) }} entries analysed</p>
            </div>
            <div class="flex items-center gap-3">
                {{-- Search --}}
                <div class="relative">
                    <svg class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M17 11A6 6 0 1 1 5 11a6 6 0 0 1 12 0z"/>
                    </svg>
                    <input wire:model.live.debounce.300ms="search" type="text" placeholder="Search entries…"
                        class="bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-gray-900 dark:text-white text-sm rounded-xl pl-9 pr-4 py-2 w-56 focus:outline-none focus:ring-2 focus:ring-blue-500 transition">
                </div>
                {{-- Refresh --}}
                <button wire:click="runAudit" wire:loading.class="opacity-50 cursor-not-allowed"
                    class="flex items-center gap-1.5 px-3 py-2 text-sm font-medium text-gray-600 dark:text-gray-400 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                    <svg class="w-4 h-4" wire:loading.class="animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                    </svg>
                    Refresh
                </button>
            </div>
        </div>

        {{-- Scrollable body --}}
        <div class="flex-1 overflow-y-auto p-8">
        <div class="max-w-6xl mx-auto space-y-6">

            @if($editSaved)
                <div class="flex items-center gap-2 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800/40 text-green-700 dark:text-green-400 text-sm rounded-xl px-4 py-3">
                    <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
                    Password updated successfully — audit refreshed.
                </div>
            @endif

            {{-- ── Summary cards ──────────────────────────────────────── --}}
            <div class="grid grid-cols-4 gap-4">

                {{-- Security Score --}}
                @php
                    $cp = $this->circleParams;
                    $scoreLabel = match(true) {
                        $securityScore >= 80 => ['Excellent', 'text-green-600 dark:text-green-400', 'bg-green-50 dark:bg-green-900/20'],
                        $securityScore >= 60 => ['Good', 'text-amber-600 dark:text-amber-400', 'bg-amber-50 dark:bg-amber-900/20'],
                        $securityScore >= 40 => ['Fair', 'text-orange-600 dark:text-orange-400', 'bg-orange-50 dark:bg-orange-900/20'],
                        default              => ['At Risk', 'text-red-600 dark:text-red-400', 'bg-red-50 dark:bg-red-900/20'],
                    };
                @endphp
                <div class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl p-5 flex flex-col items-center text-center">
                    <p class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Security Score</p>
                    <div class="relative w-28 h-28">
                        <svg viewBox="0 0 120 120" class="w-full h-full -rotate-90">
                            <circle cx="60" cy="60" r="52" fill="none" stroke="currentColor"
                                class="text-gray-100 dark:text-gray-800" stroke-width="8"/>
                            <circle cx="60" cy="60" r="52" fill="none"
                                stroke="{{ $cp['color'] }}" stroke-width="8" stroke-linecap="round"
                                stroke-dasharray="{{ number_format($cp['dash'], 2) }} {{ number_format($cp['c'], 2) }}"/>
                        </svg>
                        <div class="absolute inset-0 flex flex-col items-center justify-center">
                            <span class="text-2xl font-bold text-gray-900 dark:text-white leading-none">{{ $securityScore }}</span>
                            <span class="text-xs text-gray-400 leading-none mt-0.5">/100</span>
                        </div>
                    </div>
                    <span class="mt-3 text-sm font-semibold {{ $scoreLabel[1] }}">{{ $scoreLabel[0] }}</span>
                </div>

                {{-- Weak Passwords --}}
                <div class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl p-5">
                    <div class="flex items-center justify-between mb-3">
                        <p class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Weak</p>
                        <div class="w-8 h-8 rounded-lg {{ $weakCount > 0 ? 'bg-red-50 dark:bg-red-900/20' : 'bg-green-50 dark:bg-green-900/20' }} flex items-center justify-center">
                            <svg class="w-4 h-4 {{ $weakCount > 0 ? 'text-red-500' : 'text-green-500' }}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="{{ $weakCount > 0 ? 'M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z' : 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' }}"/>
                            </svg>
                        </div>
                    </div>
                    <p class="text-3xl font-bold text-gray-900 dark:text-white">{{ $weakCount }}</p>
                    <p class="text-xs text-gray-500 mt-1">{{ $weakCount === 1 ? 'password' : 'passwords' }}</p>
                    @if($weakCount > 0)
                        <button wire:click="$set('filter', 'weak')" class="mt-3 text-xs font-medium text-red-600 hover:text-red-500 transition">View all →</button>
                    @else
                        <p class="mt-3 text-xs font-medium text-green-600 dark:text-green-400">All good</p>
                    @endif
                </div>

                {{-- Reused Passwords --}}
                <div class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl p-5">
                    <div class="flex items-center justify-between mb-3">
                        <p class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Reused</p>
                        <div class="w-8 h-8 rounded-lg {{ $reusedCount > 0 ? 'bg-amber-50 dark:bg-amber-900/20' : 'bg-green-50 dark:bg-green-900/20' }} flex items-center justify-center">
                            <svg class="w-4 h-4 {{ $reusedCount > 0 ? 'text-amber-500' : 'text-green-500' }}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="{{ $reusedCount > 0 ? 'M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4' : 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' }}"/>
                            </svg>
                        </div>
                    </div>
                    <p class="text-3xl font-bold text-gray-900 dark:text-white">{{ $reusedCount }}</p>
                    <p class="text-xs text-gray-500 mt-1">{{ $reusedCount === 1 ? 'password' : 'passwords' }}</p>
                    @if($reusedCount > 0)
                        <button wire:click="$set('filter', 'reused')" class="mt-3 text-xs font-medium text-amber-600 hover:text-amber-500 transition">View all →</button>
                    @else
                        <p class="mt-3 text-xs font-medium text-green-600 dark:text-green-400">All unique</p>
                    @endif
                </div>

                {{-- MFA Protection --}}
                @php $hasMfa = auth()->user()->hasMfaEnabled(); @endphp
                <div class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl p-5">
                    <div class="flex items-center justify-between mb-3">
                        <p class="text-xs font-semibold text-gray-400 uppercase tracking-wider">MFA</p>
                        <div class="w-8 h-8 rounded-lg {{ $hasMfa ? 'bg-blue-50 dark:bg-blue-900/20' : 'bg-red-50 dark:bg-red-900/20' }} flex items-center justify-center">
                            <svg class="w-4 h-4 {{ $hasMfa ? 'text-blue-600' : 'text-red-500' }}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                            </svg>
                        </div>
                    </div>
                    <p class="text-lg font-bold {{ $hasMfa ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400' }}">
                        {{ $hasMfa ? 'Protected' : 'Exposed' }}
                    </p>
                    <p class="text-xs text-gray-500 mt-1">
                        {{ $hasMfa ? auth()->user()->two_factor_type === 'totp' ? 'Via authenticator app' : 'Via email OTP' : 'No second factor set' }}
                    </p>
                    @if(! $hasMfa)
                        <a wire:navigate href="{{ route('settings') }}" class="mt-3 text-xs font-medium text-red-600 hover:text-red-500 transition block">Enable now →</a>
                    @else
                        <p class="mt-3 text-xs font-medium text-blue-600 dark:text-blue-400">Active</p>
                    @endif
                </div>
            </div>

            {{-- ── Vulnerability Report ────────────────────────────────── --}}
            <div class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl overflow-hidden">

                {{-- Table header + filter tabs --}}
                <div class="px-5 py-4 border-b border-gray-100 dark:border-gray-800 flex items-center justify-between gap-4">
                    <h3 class="font-semibold text-gray-900 dark:text-white">Vulnerability Report</h3>
                    <div class="flex items-center gap-1 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl p-1">
                        @foreach(['all' => 'All', 'issues' => 'Issues', 'weak' => 'Weak', 'reused' => 'Reused'] as $key => $label)
                            <button
                                wire:click="$set('filter', '{{ $key }}')"
                                class="px-3 py-1 text-xs font-medium rounded-lg transition-colors duration-150
                                    {{ $filter === $key ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-500 hover:text-gray-700 dark:hover:text-gray-300' }}"
                            >{{ $label }}</button>
                        @endforeach
                    </div>
                </div>

                {{-- Entries --}}
                @forelse($this->filteredResults as $entry)
                    <div class="border-b border-gray-100 dark:border-gray-800 last:border-0">

                        {{-- Row --}}
                        <div class="px-5 py-4 flex items-center gap-4">

                            {{-- Favicon / Letter --}}
                            <div class="w-9 h-9 rounded-lg bg-blue-600/10 flex items-center justify-center text-blue-600 font-bold text-sm shrink-0 overflow-hidden"
                                x-data="{ err: false }">
                                @if($entry['domain'])
                                    <img x-show="!err" x-on:error="err = true"
                                        src="https://icon.horse/icon/{{ $entry['domain'] }}"
                                        class="w-full h-full object-contain p-1">
                                    <span x-show="err">{{ strtoupper(substr($entry['service_name'], 0, 1)) }}</span>
                                @else
                                    {{ strtoupper(substr($entry['service_name'], 0, 1)) }}
                                @endif
                            </div>

                            {{-- Service + username --}}
                            <div class="w-40 shrink-0 min-w-0">
                                <p class="text-sm font-semibold text-gray-900 dark:text-white truncate">{{ $entry['service_name'] }}</p>
                                <p class="text-xs text-gray-500 truncate">{{ $entry['username'] }}</p>
                            </div>

                            {{-- Issue badges --}}
                            <div class="flex-1 flex flex-wrap gap-1.5">
                                @if(empty($entry['issues']))
                                    <span class="inline-flex items-center gap-1 text-xs font-medium text-green-700 dark:text-green-400 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800/40 px-2.5 py-0.5 rounded-full">
                                        <span class="w-1.5 h-1.5 rounded-full bg-green-500 inline-block"></span>
                                        Secure
                                    </span>
                                @else
                                    @foreach($entry['issues'] as $issue)
                                        <span class="text-xs font-medium px-2.5 py-0.5 rounded-full border
                                            {{ $issue['type'] === 'weak'   ? 'text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800/40' : '' }}
                                            {{ $issue['type'] === 'reused' ? 'text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/20 border-amber-200 dark:border-amber-800/40' : '' }}
                                            {{ $issue['type'] === 'old'    ? 'text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-800 border-gray-200 dark:border-gray-700' : '' }}
                                        ">{{ $issue['label'] }}</span>
                                    @endforeach
                                @endif
                            </div>

                            {{-- Strength + age --}}
                            <div class="hidden lg:flex items-center gap-4 shrink-0">
                                <div class="text-right">
                                    <p class="text-xs font-medium {{ $entry['strength_color'] }}">{{ $entry['strength'] }}</p>
                                    <p class="text-xs text-gray-400 mt-0.5">{{ $entry['entropy'] }} bits</p>
                                </div>
                                <div class="text-right">
                                    <p class="text-xs text-gray-500">{{ $entry['updated_at'] }}</p>
                                    <p class="text-xs text-gray-400 mt-0.5">last updated</p>
                                </div>
                            </div>

                            {{-- Action --}}
                            <div class="shrink-0 flex items-center gap-2">
                                @if($entry['has_issues'])
                                    <button wire:click="editEntry({{ $entry['id'] }})"
                                        class="px-3 py-1.5 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors duration-150">
                                        Change Password
                                    </button>
                                @else
                                    <span class="text-xs text-gray-400">—</span>
                                @endif
                            </div>
                        </div>

                        {{-- Inline edit form --}}
                        @if($editingEntryId === $entry['id'])
                            <div class="px-5 pb-5 bg-blue-50/40 dark:bg-blue-900/10 border-t border-blue-100 dark:border-blue-900/30">
                                <p class="text-xs font-semibold text-blue-700 dark:text-blue-400 pt-4 mb-3">
                                    New password for <span class="font-bold">{{ $entry['service_name'] }}</span>
                                </p>
                                <div class="flex items-start gap-3">
                                    <div class="flex-1">
                                        <x-password-input wire:model.live="editNewPassword" placeholder="Enter a strong new password" />
                                        @error('editNewPassword') <p class="text-red-500 text-xs mt-1">{{ $message }}</p> @enderror
                                    </div>
                                    <div class="flex gap-2 pt-0.5">
                                        <button wire:click="savePassword"
                                            class="px-4 py-2.5 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-xl transition-colors duration-150"
                                            wire:loading.attr="disabled" wire:loading.class="opacity-60"
                                            wire:target="savePassword">
                                            <span wire:loading.remove wire:target="savePassword">Save</span>
                                            <span wire:loading wire:target="savePassword">Saving…</span>
                                        </button>
                                        <button wire:click="cancelEdit"
                                            class="px-4 py-2.5 text-sm font-medium text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition">
                                            Cancel
                                        </button>
                                    </div>
                                </div>
                            </div>
                        @endif
                    </div>
                @empty
                    <div class="px-5 py-16 text-center">
                        @if($search || $filter !== 'all')
                            <p class="text-gray-500 text-sm">No entries match your current filter.</p>
                            <button wire:click="$set('filter', 'all'); $set('search', '')" class="mt-2 text-blue-600 text-sm hover:underline">Clear filters</button>
                        @else
                            <div class="w-14 h-14 rounded-2xl bg-green-50 dark:bg-green-900/20 flex items-center justify-center mx-auto mb-4">
                                <svg class="w-7 h-7 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                            </div>
                            <p class="text-gray-700 dark:text-gray-300 text-sm font-medium">Your vault looks great</p>
                            <p class="text-gray-500 text-xs mt-1">No vulnerabilities detected. Keep it up.</p>
                        @endif
                    </div>
                @endforelse
            </div>

            {{-- ── Insight panel ───────────────────────────────────────── --}}
            @php $totalIssues = $weakCount + $reusedCount + $oldCount; @endphp
            @if($totalIssues > 0)
                <div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800/50 rounded-2xl p-5 flex items-center justify-between gap-6">
                    <div class="flex items-start gap-3">
                        <div class="w-9 h-9 rounded-xl bg-blue-600/10 flex items-center justify-center shrink-0 mt-0.5">
                            <svg class="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m1.636-6.364l.707.707M12 21v-1M5.636 5.636l.707.707m12.728 0l-.707.707M12 17a5 5 0 100-10 5 5 0 000 10z"/>
                            </svg>
                        </div>
                        <div>
                            <p class="text-sm font-semibold text-blue-900 dark:text-blue-200">
                                {{ $totalIssues }} {{ $totalIssues === 1 ? 'issue' : 'issues' }} found across your vault
                            </p>
                            <p class="text-xs text-blue-700/70 dark:text-blue-400/80 mt-0.5 leading-relaxed">
                                @if($weakCount > 0) {{ $weakCount }} weak {{ $weakCount === 1 ? 'password' : 'passwords' }}. @endif
                                @if($reusedCount > 0) {{ $reusedCount }} reused {{ $reusedCount === 1 ? 'password' : 'passwords' }}. @endif
                                @if($oldCount > 0) {{ $oldCount }} not rotated in 90+ days. @endif
                                Fixing these significantly reduces your attack surface.
                            </p>
                        </div>
                    </div>
                    <button wire:click="$set('filter', 'issues')"
                        class="shrink-0 px-4 py-2 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-xl transition-colors duration-150">
                        Review Issues
                    </button>
                </div>
            @else
                <div class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800/50 rounded-2xl p-5 flex items-center gap-3">
                    <div class="w-9 h-9 rounded-xl bg-green-500/10 flex items-center justify-center shrink-0">
                        <svg class="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                    </div>
                    <p class="text-sm font-semibold text-green-800 dark:text-green-300">
                        Your vault is healthy — no issues detected.
                    </p>
                </div>
            @endif

        </div>
        </div>
    </main>
</div>
