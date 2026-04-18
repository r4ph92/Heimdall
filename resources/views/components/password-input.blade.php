@props(['placeholder' => 'Enter or paste a password'])

<div
    x-data="{
        show: false,
        entropy: 0,
        showGen: false,
        genLength: 20,
        genUpper: true,
        genNumbers: true,
        genSymbols: true,

        calcEntropy(pwd) {
            if (!pwd || pwd.length === 0) return 0;
            let charset = 26; // always includes lowercase
            if (/[A-Z]/.test(pwd)) charset += 26;
            if (/[0-9]/.test(pwd)) charset += 10;
            if (/[^a-zA-Z0-9]/.test(pwd)) charset += 32;
            return Math.floor(pwd.length * Math.log2(charset));
        },

        get strength() {
            if (this.entropy === 0)   return null;
            if (this.entropy < 36)    return { label: 'Weak',      color: 'bg-red-500',    text: 'text-red-400',    pct: '15%' };
            if (this.entropy < 60)    return { label: 'Fair',      color: 'bg-orange-500', text: 'text-orange-400', pct: '35%' };
            if (this.entropy < 80)    return { label: 'Good',      color: 'bg-yellow-400', text: 'text-yellow-400', pct: '55%' };
            if (this.entropy < 100)   return { label: 'Strong',    color: 'bg-green-500',  text: 'text-green-400',  pct: '78%' };
            if (this.entropy < 128)   return { label: 'Very strong', color: 'bg-emerald-500', text: 'text-emerald-400', pct: '90%' };
            return                           { label: 'Excellent', color: 'bg-indigo-500', text: 'text-indigo-400', pct: '100%' };
        },

        generate() {
            let chars = 'abcdefghijklmnopqrstuvwxyz';
            if (this.genUpper)   chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            if (this.genNumbers) chars += '0123456789';
            if (this.genSymbols) chars += '!@#$%^&*()-_=+[]{}|;,.<>?';

            // Use crypto.getRandomValues for cryptographically secure randomness
            const array = new Uint32Array(this.genLength);
            crypto.getRandomValues(array);
            const pwd = Array.from(array).map(n => chars[n % chars.length]).join('');

            // Set the input value and fire a native input event so wire:model.live picks it up
            this.$refs.input.value = pwd;
            this.$refs.input.dispatchEvent(new Event('input', { bubbles: true }));
            this.entropy = this.calcEntropy(pwd);
            this.show = true;
        }
    }"
>
    {{-- Input row --}}
    <div class="relative">
        <input
            x-ref="input"
            :type="show ? 'text' : 'password'"
            placeholder="{{ $placeholder }}"
            x-on:input="entropy = calcEntropy($el.value)"
            {{ $attributes->merge(['class' => 'w-full bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 text-gray-900 dark:text-white rounded-xl px-4 py-3 pr-24 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500 transition']) }}
        >
        <div class="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-2">
            <button type="button" @click="show = !show"
                class="text-xs text-gray-500 hover:text-gray-900 dark:hover:text-white transition"
                x-text="show ? 'Hide' : 'Show'">
            </button>
            <div class="w-px h-3 bg-gray-300 dark:bg-gray-700"></div>
            <button type="button" @click="showGen = !showGen"
                class="text-xs text-indigo-400 hover:text-indigo-300 transition"
                title="Generate password">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                </svg>
            </button>
        </div>
    </div>

    {{-- Generator panel --}}
    <div
        x-show="showGen" x-cloak
        x-transition:enter="transition ease-out duration-150"
        x-transition:enter-start="opacity-0 -translate-y-1"
        x-transition:enter-end="opacity-100 translate-y-0"
        x-transition:leave="transition ease-in duration-100"
        x-transition:leave-start="opacity-100 translate-y-0"
        x-transition:leave-end="opacity-0 -translate-y-1"
        class="mt-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-xl p-4 space-y-3"
    >
        {{-- Length slider --}}
        <div>
            <div class="flex items-center justify-between mb-1.5">
                <span class="text-xs text-gray-600 dark:text-gray-400">Length</span>
                <span class="text-xs font-mono text-gray-900 dark:text-white" x-text="genLength"></span>
            </div>
            <input type="range" x-model="genLength" min="8" max="64"
                class="w-full accent-indigo-500 h-1.5 rounded-full bg-gray-300 dark:bg-gray-700 appearance-none cursor-pointer">
        </div>

        {{-- Toggles --}}
        <div class="flex gap-2 flex-wrap">
            <label class="flex items-center gap-1.5 cursor-pointer">
                <input type="checkbox" x-model="genUpper" class="accent-indigo-500 rounded">
                <span class="text-xs text-gray-600 dark:text-gray-400">A–Z</span>
            </label>
            <label class="flex items-center gap-1.5 cursor-pointer">
                <input type="checkbox" x-model="genNumbers" class="accent-indigo-500 rounded">
                <span class="text-xs text-gray-600 dark:text-gray-400">0–9</span>
            </label>
            <label class="flex items-center gap-1.5 cursor-pointer">
                <input type="checkbox" x-model="genSymbols" class="accent-indigo-500 rounded">
                <span class="text-xs text-gray-600 dark:text-gray-400">!@#…</span>
            </label>
        </div>

        <button type="button" @click="generate()"
            class="w-full bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold py-2 rounded-lg transition-colors duration-150">
            Generate
        </button>
    </div>

    {{-- Entropy meter --}}
    <div x-show="entropy > 0" x-cloak class="mt-2 space-y-1">
        <div class="h-1 w-full bg-gray-200 dark:bg-gray-800 rounded-full overflow-hidden">
            <div
                class="h-full rounded-full transition-all duration-500"
                :class="strength?.color"
                :style="'width: ' + (strength?.pct ?? '0%')"
            ></div>
        </div>
        <div class="flex items-center justify-between">
            <span class="text-xs font-medium transition-colors duration-300" :class="strength?.text" x-text="strength?.label"></span>
            <span class="text-xs text-gray-500 dark:text-gray-600 font-mono" x-text="entropy + ' bits'"></span>
        </div>
    </div>

</div>
