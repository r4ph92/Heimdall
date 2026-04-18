<?php

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

Route::get('/', fn () => redirect()->route('login'));

// Auth routes (guests only)
Route::middleware('guest')->group(function () {
    Route::get('/login', fn () => view('auth.login'))->name('login');
    Route::get('/register', fn () => view('auth.register'))->name('register');
});

// MFA challenge — auth + vault key required, but NOT mfa_verified (that's what this page does)
Route::middleware(['auth', \App\Http\Middleware\EnsureVaultKeyInSession::class])
    ->get('/mfa/challenge', fn () => view('mfa.challenge'))
    ->name('mfa.challenge');

// Fully authenticated routes — auth + vault key + MFA verified
Route::middleware([
    'auth',
    \App\Http\Middleware\EnsureVaultKeyInSession::class,
    \App\Http\Middleware\EnsureMfaVerified::class,
])->group(function () {
    Route::get('/dashboard', fn () => view('dashboard'))->name('dashboard');
    Route::get('/settings', fn () => view('settings'))->name('settings');
    Route::get('/audit', fn () => view('audit'))->name('audit');

    // Vault export — decrypts all entries server-side and streams a JSON download
    Route::get('/vault/export', function () {
        $user       = auth()->user();
        $key        = base64_decode(session('vault_key'));
        $encryption = app(\App\Services\EncryptionService::class);

        $entries = $user->vaultEntries()->orderBy('service_name')->get()->map(
            fn ($e) => [
                'service_name' => $e->service_name,
                'username'     => $e->username,
                'url'          => $e->url,
                'password'     => $encryption->decrypt($e->encrypted_password, $e->iv, $key),
                'notes'        => $e->encrypted_notes
                    ? $encryption->decrypt($e->encrypted_notes, $e->notes_iv, $key)
                    : null,
                'updated_at'   => $e->updated_at->toDateTimeString(),
            ]
        );

        $json = json_encode([
            'exported_at' => now()->toISOString(),
            'vault'       => $entries,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

        return response($json, 200, [
            'Content-Type'        => 'application/json',
            'Content-Disposition' => 'attachment; filename="heimdall-vault-' . now()->format('Y-m-d') . '.json"',
        ]);
    })->name('vault.export');

    Route::post('/logout', function () {
        session()->forget(['vault_key', 'mfa_verified']);
        Auth::logout();
        request()->session()->invalidate();
        request()->session()->regenerateToken();
        return redirect()->route('login');
    })->name('logout');
});
