<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" type="image/png" href="/favicon.png">
    <title>{{ $share->entry_name }} — Heimdall Share</title>
    @vite(['resources/css/app.css', 'resources/js/app.js'])
</head>
<body class="bg-gray-950 min-h-screen flex items-center justify-center p-4 antialiased">

<div
    x-data="shareDecrypt('{{ $share->token }}', '{{ $share->isExpired() ? 'expired' : '' }}')"
    x-init="init()"
    class="w-full max-w-md"
>
    {{-- Header --}}
    <div class="text-center mb-8">
        <p class="text-indigo-400 font-semibold text-sm tracking-wider uppercase">⚡ Heimdall</p>
        <h1 class="text-2xl font-bold text-white mt-1">{{ $share->entry_name }}</h1>
        <p class="text-gray-500 text-xs mt-1">
            Shared entry · Expires {{ $share->expires_at->diffForHumans() }}
        </p>
    </div>

    {{-- Expired --}}
    <div x-show="state === 'expired'" class="bg-red-900/20 border border-red-800/50 rounded-2xl p-6 text-center">
        <p class="text-red-400 font-semibold">This link has expired.</p>
        <p class="text-gray-500 text-sm mt-1">Ask the sender to generate a new share link.</p>
    </div>

    {{-- No key in URL — let user paste it manually --}}
    <div x-show="state === 'nokey'" class="bg-gray-900 border border-gray-800 rounded-2xl p-6">
        <p class="text-yellow-400 font-semibold mb-1">Decryption key missing</p>
        <p class="text-gray-400 text-sm mb-4">
            The key was stripped from the URL (common with messaging apps).
            Ask the sender for the key and paste it below.
        </p>
        <input
            x-model="manualKey"
            type="text"
            placeholder="Paste key here…"
            @keydown.enter="decryptWithKey(manualKey)"
            class="w-full bg-gray-800 border border-gray-700 text-white text-xs font-mono rounded-xl px-3 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-500 mb-3"
        >
        <button
            @click="decryptWithKey(manualKey)"
            :disabled="!manualKey.trim()"
            class="w-full bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white text-sm font-semibold py-2.5 rounded-xl transition"
        >
            Decrypt
        </button>
    </div>

    {{-- Decrypting --}}
    <div x-show="state === 'loading'" class="text-center py-12">
        <div class="w-10 h-10 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin mx-auto mb-3"></div>
        <p class="text-gray-400 text-sm">Decrypting…</p>
    </div>

    {{-- Error --}}
    <div x-show="state === 'error'" class="bg-red-900/20 border border-red-800/50 rounded-2xl p-6 text-center">
        <p class="text-red-400 font-semibold">Decryption failed.</p>
        <p class="text-gray-500 text-sm mt-1" x-text="errorMsg"></p>
        <button @click="state = 'nokey'" class="mt-4 text-xs text-indigo-400 hover:text-indigo-300 transition">
            Try a different key →
        </button>
    </div>

    {{-- Decrypted entry --}}
    <div x-show="state === 'done'" class="space-y-3 animate-fadein">

        <template x-if="entry.username">
            <div class="bg-gray-900 border border-gray-800 rounded-xl p-4 flex items-center justify-between gap-3"
                x-data="{ copied: false }">
                <div class="min-w-0">
                    <p class="text-xs text-gray-500 uppercase tracking-wider mb-1">Username</p>
                    <p class="text-white text-sm truncate" x-text="entry.username"></p>
                </div>
                <button
                    @click="navigator.clipboard.writeText(entry.username).then(() => { copied = true; setTimeout(() => copied = false, 1500) })"
                    class="text-xs text-indigo-400 hover:text-indigo-300 transition shrink-0"
                    x-text="copied ? 'Copied!' : 'Copy'"
                ></button>
            </div>
        </template>

        <template x-if="entry.url">
            <div class="bg-gray-900 border border-gray-800 rounded-xl p-4">
                <p class="text-xs text-gray-500 uppercase tracking-wider mb-1">URL</p>
                <a :href="entry.url" target="_blank" rel="noopener noreferrer"
                    class="text-indigo-400 text-sm hover:underline truncate block" x-text="entry.url"></a>
            </div>
        </template>

        <div class="bg-gray-900 border border-gray-800 rounded-xl p-4"
            x-data="{ show: false, copied: false }">
            <p class="text-xs text-gray-500 uppercase tracking-wider mb-2">Password</p>
            <div class="flex items-center justify-between gap-3">
                <p class="text-white font-mono text-sm break-all flex-1">
                    <span x-show="!show">••••••••••••</span>
                    <span x-show="show" x-text="entry.password"></span>
                </p>
                <div class="flex items-center gap-3 shrink-0">
                    <button @click="show = !show" class="text-xs text-gray-500 hover:text-white transition"
                        x-text="show ? 'Hide' : 'Show'"></button>
                    <button
                        @click="navigator.clipboard.writeText(entry.password).then(() => { copied = true; setTimeout(() => copied = false, 1500) })"
                        class="text-xs text-indigo-400 hover:text-indigo-300 transition"
                        x-text="copied ? 'Copied!' : 'Copy'"
                    ></button>
                </div>
            </div>
        </div>

        <template x-if="entry.notes">
            <div class="bg-gray-900 border border-gray-800 rounded-xl p-4">
                <p class="text-xs text-gray-500 uppercase tracking-wider mb-1">Notes</p>
                <p class="text-gray-300 text-sm whitespace-pre-wrap" x-text="entry.notes"></p>
            </div>
        </template>

        <p class="text-center text-xs text-gray-600 pt-2">
            This link is end-to-end encrypted. The server never saw this password.
        </p>
    </div>
</div>

<script>
function shareDecrypt(token, expiredFlag) {
    return {
        state:     expiredFlag === 'expired' ? 'expired' : 'loading',
        entry:     {},
        errorMsg:  '',
        manualKey: '',

        async init() {
            if (this.state === 'expired') return;

            const fragment = window.location.hash.slice(1);
            if (!fragment) { this.state = 'nokey'; return; }

            await this.decryptWithKey(fragment);
        },

        async decryptWithKey(keyB64u) {
            if (!keyB64u || !keyB64u.trim()) return;
            this.state = 'loading';
            try {
                // Restore standard base64 from base64url, add padding if needed
                let b64 = keyB64u.trim().replace(/-/g, '+').replace(/_/g, '/');
                while (b64.length % 4) b64 += '=';

                const keyBytes  = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
                const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);

                const resp = await fetch(`/api/share/${token}`);
                if (!resp.ok) {
                    const data = await resp.json().catch(() => ({}));
                    this.errorMsg = data.error ?? 'Failed to load share data.';
                    this.state = 'error';
                    return;
                }

                const { encrypted_blob, iv } = await resp.json();

                const b64decode = s => {
                    let padded = s.replace(/-/g, '+').replace(/_/g, '/');
                    while (padded.length % 4) padded += '=';
                    return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
                };

                const ciphertext = b64decode(encrypted_blob);
                const ivBytes    = b64decode(iv);

                const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, cryptoKey, ciphertext);
                this.entry = JSON.parse(new TextDecoder().decode(plaintext));
                this.state = 'done';
            } catch (e) {
                this.errorMsg = 'Decryption failed — the key may be wrong or the link corrupted.';
                this.state = 'error';
            }
        }
    };
}
</script>

</body>
</html>
