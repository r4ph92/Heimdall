<?php
use Livewire\Component;
new class extends Component {};
?>

<div class="h-full p-8 overflow-y-auto animate-fadein">
<div class="max-w-4xl mx-auto space-y-6">

    <h2 class="text-2xl font-bold text-gray-900 dark:text-white">Password Tools</h2>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">

        {{-- ── Generator ──────────────────────────────────────────────── --}}
        <div
            class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl p-6"
            x-data="{
                password: '',
                show: false,
                copied: false,
                length: 20,
                useUpper: true,
                useNumbers: true,
                useSymbols: true,

                calcEntropy(pwd) {
                    if (!pwd || pwd.length === 0) return 0;
                    let charset = 26;
                    if (/[A-Z]/.test(pwd)) charset += 26;
                    if (/[0-9]/.test(pwd)) charset += 10;
                    if (/[^a-zA-Z0-9]/.test(pwd)) charset += 32;
                    return Math.floor(pwd.length * Math.log2(charset));
                },

                get entropy() { return this.calcEntropy(this.password); },

                get strength() {
                    const e = this.entropy;
                    if (e === 0)   return null;
                    if (e < 36)    return { label: 'Weak',        color: 'bg-red-500',     text: 'text-red-400',     pct: '15%' };
                    if (e < 60)    return { label: 'Fair',        color: 'bg-orange-500',  text: 'text-orange-400',  pct: '35%' };
                    if (e < 80)    return { label: 'Good',        color: 'bg-yellow-400',  text: 'text-yellow-400',  pct: '55%' };
                    if (e < 100)   return { label: 'Strong',      color: 'bg-green-500',   text: 'text-green-400',   pct: '78%' };
                    if (e < 128)   return { label: 'Very strong', color: 'bg-emerald-500', text: 'text-emerald-400', pct: '90%' };
                    return               { label: 'Excellent',   color: 'bg-indigo-500',  text: 'text-indigo-400',  pct: '100%' };
                },

                generate() {
                    let chars = 'abcdefghijklmnopqrstuvwxyz';
                    if (this.useUpper)   chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
                    if (this.useNumbers) chars += '0123456789';
                    if (this.useSymbols) chars += '!@#$%^&*()-_=+[]{}|;,.<>?';
                    const arr = new Uint32Array(this.length);
                    crypto.getRandomValues(arr);
                    this.password = Array.from(arr).map(n => chars[n % chars.length]).join('');
                    this.copied = false;
                },

                copy() {
                    if (!this.password) return;
                    navigator.clipboard.writeText(this.password).then(() => {
                        this.copied = true;
                        setTimeout(() => this.copied = false, 1500);
                    });
                }
            }"
            x-init="generate()"
        >
            <h3 class="font-semibold text-gray-900 dark:text-white mb-4">Generator</h3>

            {{-- Password display --}}
            <div class="relative bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-xl px-4 py-3 mb-4 group">
                <p class="text-sm font-mono text-gray-900 dark:text-white break-all pr-16 min-h-[1.25rem]"
                    x-text="show ? password : password.replace(/./g, '•')"></p>
                <div class="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-2">
                    <button type="button" @click="show = !show"
                        class="text-xs text-gray-500 hover:text-gray-900 dark:hover:text-white transition"
                        x-text="show ? 'Hide' : 'Show'">
                    </button>
                    <div class="w-px h-3 bg-gray-300 dark:bg-gray-700"></div>
                    <button type="button" @click="copy()"
                        class="text-xs transition"
                        :class="copied ? 'text-green-400' : 'text-indigo-400 hover:text-indigo-300'"
                        x-text="copied ? 'Copied!' : 'Copy'">
                    </button>
                </div>
            </div>

            {{-- Entropy bar --}}
            <template x-if="entropy > 0">
                <div class="mb-5 space-y-1">
                    <div class="h-1.5 w-full bg-gray-200 dark:bg-gray-800 rounded-full overflow-hidden">
                        <div class="h-full rounded-full transition-all duration-500"
                            :class="strength?.color"
                            :style="'width: ' + (strength?.pct ?? '0%')">
                        </div>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-xs font-medium transition-colors duration-300"
                            :class="strength?.text" x-text="strength?.label"></span>
                        <span class="text-xs text-gray-500 dark:text-gray-600 font-mono" x-text="entropy + ' bits'"></span>
                    </div>
                </div>
            </template>

            {{-- Options --}}
            <div class="space-y-4">
                <div>
                    <div class="flex justify-between mb-1.5">
                        <span class="text-xs text-gray-600 dark:text-gray-400">Length</span>
                        <span class="text-xs font-mono text-gray-900 dark:text-white" x-text="length"></span>
                    </div>
                    <input type="range" x-model="length" min="8" max="64"
                        @input="generate()"
                        class="w-full accent-indigo-500 h-1.5 rounded-full bg-gray-300 dark:bg-gray-700 appearance-none cursor-pointer">
                </div>

                <div class="flex gap-4">
                    <label class="flex items-center gap-2 cursor-pointer">
                        <input type="checkbox" x-model="useUpper" @change="generate()" class="accent-indigo-500 rounded">
                        <span class="text-xs text-gray-600 dark:text-gray-400">A–Z</span>
                    </label>
                    <label class="flex items-center gap-2 cursor-pointer">
                        <input type="checkbox" x-model="useNumbers" @change="generate()" class="accent-indigo-500 rounded">
                        <span class="text-xs text-gray-600 dark:text-gray-400">0–9</span>
                    </label>
                    <label class="flex items-center gap-2 cursor-pointer">
                        <input type="checkbox" x-model="useSymbols" @change="generate()" class="accent-indigo-500 rounded">
                        <span class="text-xs text-gray-600 dark:text-gray-400">!@#…</span>
                    </label>
                </div>

                <button type="button" @click="generate()"
                    class="w-full bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-semibold py-2.5 rounded-xl transition-colors duration-150 flex items-center justify-center gap-2">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                            d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                    </svg>
                    Regenerate
                </button>
            </div>
        </div>

        {{-- ── Entropy Checker ─────────────────────────────────────────── --}}
        <div
            class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl p-6"
            x-data="{
                password: '',
                show: false,

                calcEntropy(pwd) {
                    if (!pwd || pwd.length === 0) return 0;
                    let charset = 26;
                    if (/[A-Z]/.test(pwd)) charset += 26;
                    if (/[0-9]/.test(pwd)) charset += 10;
                    if (/[^a-zA-Z0-9]/.test(pwd)) charset += 32;
                    return Math.floor(pwd.length * Math.log2(charset));
                },

                get entropy() { return this.calcEntropy(this.password); },

                get charsetSize() {
                    let n = 0;
                    if (/[a-z]/.test(this.password)) n += 26;
                    if (/[A-Z]/.test(this.password)) n += 26;
                    if (/[0-9]/.test(this.password)) n += 10;
                    if (/[^a-zA-Z0-9]/.test(this.password)) n += 32;
                    return n;
                },

                get strength() {
                    const e = this.entropy;
                    if (e === 0)   return null;
                    if (e < 36)    return { label: 'Weak',        color: 'bg-red-500',     text: 'text-red-400',     pct: '15%' };
                    if (e < 60)    return { label: 'Fair',        color: 'bg-orange-500',  text: 'text-orange-400',  pct: '35%' };
                    if (e < 80)    return { label: 'Good',        color: 'bg-yellow-400',  text: 'text-yellow-400',  pct: '55%' };
                    if (e < 100)   return { label: 'Strong',      color: 'bg-green-500',   text: 'text-green-400',   pct: '78%' };
                    if (e < 128)   return { label: 'Very strong', color: 'bg-emerald-500', text: 'text-emerald-400', pct: '90%' };
                    return               { label: 'Excellent',   color: 'bg-indigo-500',  text: 'text-indigo-400',  pct: '100%' };
                },

                crackTime(entropy) {
                    if (entropy === 0) return null;
                    // Assumes offline brute-force at 10 billion guesses/sec (GPU against fast hash)
                    // Divide by 2 for average case (expected halfway through keyspace)
                    const seconds = Math.pow(2, entropy) / 1e10 / 2;
                    if (seconds < 1)                   return 'less than a second';
                    if (seconds < 60)                  return Math.round(seconds) + ' seconds';
                    if (seconds < 3600)                return Math.round(seconds / 60) + ' minutes';
                    if (seconds < 86400)               return Math.round(seconds / 3600) + ' hours';
                    if (seconds < 86400 * 365)         return Math.round(seconds / 86400) + ' days';
                    if (seconds < 86400 * 365 * 1e3)   return Math.round(seconds / (86400 * 365)) + ' years';
                    if (seconds < 86400 * 365 * 1e6)   return (seconds / (86400 * 365 * 1e3)).toFixed(1) + ' thousand years';
                    if (seconds < 86400 * 365 * 1e9)   return (seconds / (86400 * 365 * 1e6)).toFixed(1) + ' million years';
                    if (seconds < 86400 * 365 * 1e12)  return (seconds / (86400 * 365 * 1e9)).toFixed(1) + ' billion years';
                    return 'longer than the universe has existed';
                },

                charTypes() {
                    const types = [];
                    if (/[a-z]/.test(this.password)) types.push({ label: 'Lowercase', count: 26 });
                    if (/[A-Z]/.test(this.password)) types.push({ label: 'Uppercase', count: 26 });
                    if (/[0-9]/.test(this.password)) types.push({ label: 'Numbers',   count: 10 });
                    if (/[^a-zA-Z0-9]/.test(this.password)) types.push({ label: 'Symbols', count: 32 });
                    return types;
                }
            }"
        >
            <h3 class="font-semibold text-gray-900 dark:text-white mb-4">Entropy Checker</h3>

            {{-- Input --}}
            <div class="relative mb-4">
                <input
                    :type="show ? 'text' : 'password'"
                    x-model="password"
                    placeholder="Paste or type any password…"
                    class="w-full bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 text-gray-900 dark:text-white rounded-xl px-4 py-3 pr-16 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500 transition"
                >
                <button type="button" @click="show = !show"
                    x-text="show ? 'Hide' : 'Show'"
                    class="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-gray-500 hover:text-gray-900 dark:hover:text-white transition">
                </button>
            </div>

            {{-- Results --}}
            <template x-if="password.length > 0">
                <div class="space-y-4"
                    x-transition:enter="transition ease-out duration-200"
                    x-transition:enter-start="opacity-0 translate-y-1"
                    x-transition:enter-end="opacity-100 translate-y-0">

                    {{-- Entropy bar --}}
                    <div class="space-y-1">
                        <div class="h-1.5 w-full bg-gray-200 dark:bg-gray-800 rounded-full overflow-hidden">
                            <div class="h-full rounded-full transition-all duration-500"
                                :class="strength?.color"
                                :style="'width: ' + (strength?.pct ?? '0%')">
                            </div>
                        </div>
                        <div class="flex justify-between">
                            <span class="text-xs font-medium transition-colors duration-300"
                                :class="strength?.text" x-text="strength?.label"></span>
                            <span class="text-xs text-gray-500 dark:text-gray-600 font-mono" x-text="entropy + ' bits'"></span>
                        </div>
                    </div>

                    {{-- Stats grid --}}
                    <div class="grid grid-cols-2 gap-2">
                        <div class="bg-gray-100 dark:bg-gray-800 rounded-xl p-3">
                            <p class="text-xs text-gray-500 mb-0.5">Length</p>
                            <p class="text-lg font-bold text-gray-900 dark:text-white font-mono" x-text="password.length"></p>
                        </div>
                        <div class="bg-gray-100 dark:bg-gray-800 rounded-xl p-3">
                            <p class="text-xs text-gray-500 mb-0.5">Charset size</p>
                            <p class="text-lg font-bold text-gray-900 dark:text-white font-mono" x-text="charsetSize"></p>
                        </div>
                        <div class="bg-gray-100 dark:bg-gray-800 rounded-xl p-3">
                            <p class="text-xs text-gray-500 mb-0.5">Entropy</p>
                            <p class="text-lg font-bold text-gray-900 dark:text-white font-mono" x-text="entropy + ' bits'"></p>
                        </div>
                        <div class="bg-gray-100 dark:bg-gray-800 rounded-xl p-3">
                            <p class="text-xs text-gray-500 mb-0.5">Character types</p>
                            <p class="text-lg font-bold text-gray-900 dark:text-white font-mono" x-text="charTypes().length"></p>
                        </div>
                    </div>

                    {{-- Character type badges --}}
                    <div class="flex flex-wrap gap-1.5">
                        <template x-for="type in charTypes()" :key="type.label">
                            <span class="text-xs bg-indigo-600/20 text-indigo-600 dark:text-indigo-300 border border-indigo-500/20 rounded-lg px-2.5 py-1"
                                x-text="type.label + ' (+' + type.count + ')'">
                            </span>
                        </template>
                    </div>

                    {{-- Crack time --}}
                    <div class="bg-gray-100 dark:bg-gray-800 rounded-xl p-4">
                        <p class="text-xs text-gray-500 uppercase tracking-wider mb-1">Estimated crack time</p>
                        <p class="text-sm font-semibold" :class="strength?.text" x-text="crackTime(entropy)"></p>
                        <p class="text-xs text-gray-500 dark:text-gray-600 mt-1">Assuming 10 billion guesses/sec (GPU offline attack)</p>
                    </div>
                </div>
            </template>

            <template x-if="password.length === 0">
                <div class="py-8 text-center text-gray-400 dark:text-gray-600 text-sm">
                    Type or paste a password to analyse it
                </div>
            </template>
        </div>

    </div>
</div>
</div>
