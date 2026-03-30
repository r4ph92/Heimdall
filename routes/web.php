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

    Route::post('/logout', function () {
        session()->forget(['vault_key', 'mfa_verified']);
        Auth::logout();
        request()->session()->invalidate();
        request()->session()->regenerateToken();
        return redirect()->route('login');
    })->name('logout');
});
