<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/png" href="/favicon.png">
    <title>Verify Email — Heimdall</title>
    <script>
        if (localStorage.getItem('theme') !== 'light') {
            document.documentElement.classList.add('dark');
        }
    </script>
    @vite(['resources/css/app.css', 'resources/js/app.js'])
</head>
<body class="min-h-screen flex items-center justify-center bg-gray-950">

<div class="w-full max-w-md bg-gray-900 rounded-2xl shadow-xl p-8 mx-4">

    {{-- Icon --}}
    <div class="flex justify-center mb-6">
        <div class="w-16 h-16 rounded-2xl bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center">
            <svg class="w-8 h-8 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
            </svg>
        </div>
    </div>

    <div class="text-center mb-8">
        <h1 class="text-2xl font-bold text-white">Check your inbox</h1>
        <p class="text-gray-400 text-sm mt-2 leading-relaxed">
            We sent a verification link to
            <span class="text-white font-medium">{{ auth()->user()->email }}</span>.
            Click it to activate your vault.
        </p>
    </div>

    @if (session('resent'))
        <div class="mb-4 flex items-center gap-2 bg-green-500/10 border border-green-500/30 text-green-400 text-sm rounded-xl px-4 py-3">
            <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
            </svg>
            A new verification link has been sent.
        </div>
    @endif

    @if (session('email_error'))
        <div class="mb-4 flex items-center gap-2 bg-red-500/10 border border-red-500/30 text-red-400 text-sm rounded-xl px-4 py-3">
            <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
            {{ session('email_error') }}
        </div>
    @endif

    <form method="POST" action="{{ route('verification.send') }}">
        @csrf
        <button type="submit"
            class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold py-2.5 rounded-xl transition text-sm">
            Resend verification email
        </button>
    </form>

    <form method="POST" action="{{ route('logout') }}" class="mt-3">
        @csrf
        <button type="submit"
            class="w-full text-gray-500 hover:text-gray-300 text-sm py-2 transition">
            Sign out
        </button>
    </form>

</div>

</body>
</html>
