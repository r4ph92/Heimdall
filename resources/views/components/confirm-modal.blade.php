<div
    x-cloak
    x-data
    x-show="$store.modal.open"
    x-transition:enter="transition ease-out duration-200"
    x-transition:enter-start="opacity-0"
    x-transition:enter-end="opacity-100"
    x-transition:leave="transition ease-in duration-150"
    x-transition:leave-start="opacity-100"
    x-transition:leave-end="opacity-0"
    @keydown.escape.window="$store.modal.cancel()"
    class="fixed inset-0 z-50 flex items-center justify-center p-4"
>
    {{-- Backdrop --}}
    <div
        class="absolute inset-0 bg-black/60 backdrop-blur-sm"
        @click="$store.modal.cancel()"
    ></div>

    {{-- Dialog --}}
    <div
        x-show="$store.modal.open"
        x-transition:enter="transition ease-out duration-200"
        x-transition:enter-start="opacity-0 scale-95 translate-y-2"
        x-transition:enter-end="opacity-100 scale-100 translate-y-0"
        x-transition:leave="transition ease-in duration-150"
        x-transition:leave-start="opacity-100 scale-100 translate-y-0"
        x-transition:leave-end="opacity-0 scale-95 translate-y-2"
        class="relative z-10 w-full max-w-sm bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl shadow-2xl p-6"
    >
        <div class="flex items-start gap-4 mb-5">
            <div
                :class="$store.modal.isDanger ? 'bg-red-100 dark:bg-red-900/30 text-red-500 dark:text-red-400' : 'bg-indigo-100 dark:bg-indigo-900/30 text-indigo-500 dark:text-indigo-400'"
                class="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
            >
                <template x-if="$store.modal.isDanger">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                            d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                    </svg>
                </template>
                <template x-if="!$store.modal.isDanger">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                            d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                </template>
            </div>
            <p class="text-sm text-gray-700 dark:text-gray-300 leading-relaxed pt-1.5" x-text="$store.modal.message"></p>
        </div>

        <div class="flex gap-3 justify-end">
            <button
                @click="$store.modal.cancel()"
                class="px-4 py-2 text-sm font-medium text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-xl transition-colors duration-150"
            >Cancel</button>
            <button
                @click="$store.modal.accept()"
                :class="$store.modal.isDanger
                    ? 'bg-red-600 hover:bg-red-500'
                    : 'bg-indigo-600 hover:bg-indigo-500'"
                class="px-4 py-2 text-sm font-medium text-white rounded-xl transition-colors duration-150"
                x-text="$store.modal.confirmLabel"
            ></button>
        </div>
    </div>
</div>
