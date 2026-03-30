<?php

use App\Mail\MfaOtpMail;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Mail;
use Illuminate\Validation\ValidationException;
use Livewire\Component;
use PragmaRX\Google2FA\Google2FA;

new class extends Component
{
    public string $code = '';
    public bool $otpSent = false;

    public function mount(): void
    {
        // If user uses email MFA, send the OTP automatically on page load
        if (auth()->user()->two_factor_type === 'email') {
            $this->sendEmailOtp();
        }
    }

    public function sendEmailOtp(): void
    {
        $user = auth()->user();
        $otp  = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);

        // Store hashed OTP in cache for 10 minutes, keyed by user ID
        Cache::put("mfa_otp_{$user->id}", bcrypt($otp), now()->addMinutes(10));

        Mail::to($user->email)->send(new MfaOtpMail($otp));

        $this->otpSent = true;
    }

    public function verify(): void
    {
        $this->validate(['code' => ['required', 'string']]);

        $user = auth()->user();

        $verified = match ($user->two_factor_type) {
            'email' => $this->verifyEmailOtp($user),
            'totp'  => $this->verifyTotp($user),
            default => false,
        };

        if (! $verified) {
            throw ValidationException::withMessages([
                'code' => 'Invalid code. Please try again.',
            ]);
        }

        session(['mfa_verified' => true]);
        $this->redirect(route('dashboard'), navigate: true);
    }

    private function verifyEmailOtp($user): bool
    {
        $hashed = Cache::get("mfa_otp_{$user->id}");
        if (! $hashed || ! password_verify($this->code, $hashed)) {
            return false;
        }
        Cache::forget("mfa_otp_{$user->id}");
        return true;
    }

    private function verifyTotp($user): bool
    {
        $google2fa = new Google2FA();
        return $google2fa->verifyKey($user->two_factor_secret, $this->code);
    }

    public function useRecoveryCode(): void
    {
        $this->validate(['code' => ['required', 'string']]);

        $user  = auth()->user();
        $codes = json_decode(decrypt($user->two_factor_recovery_codes), true);

        foreach ($codes as $index => $hashed) {
            if (password_verify($this->code, $hashed)) {
                // Burn the used recovery code — each one is single-use
                unset($codes[$index]);
                $user->update(['two_factor_recovery_codes' => encrypt(json_encode(array_values($codes)))]);

                session(['mfa_verified' => true]);
                $this->redirect(route('dashboard'), navigate: true);
                return;
            }
        }

        throw ValidationException::withMessages([
            'code' => 'Invalid recovery code.',
        ]);
    }
};
?>

<div class="min-h-screen flex items-center justify-center bg-gray-950 animate-fadein">
    <div class="w-full max-w-sm bg-gray-900 rounded-2xl shadow-xl p-8">
        <div class="mb-6 text-center">
            <div class="w-12 h-12 rounded-xl bg-indigo-600/20 flex items-center justify-center mx-auto mb-3">
                <svg class="w-6 h-6 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
            </div>
            <h1 class="text-xl font-bold text-white">Two-Factor Authentication</h1>
            <p class="text-gray-400 text-sm mt-1">
                @if(auth()->user()->two_factor_type === 'email')
                    {{ $otpSent ? 'Check your email for a 6-digit code.' : 'Sending code to your email…' }}
                @else
                    Enter the code from your authenticator app.
                @endif
            </p>
        </div>

        <form wire:submit="verify" class="space-y-4" x-data>
            <div>
                <input
                    wire:model="code"
                    type="text"
                    inputmode="numeric"
                    autocomplete="one-time-code"
                    maxlength="6"
                    placeholder="000000"
                    class="w-full bg-gray-800 border border-gray-700 text-white text-center text-2xl tracking-[0.5em] rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition"
                    autofocus
                >
                @error('code') <p class="text-red-400 text-xs mt-1 text-center">{{ $message }}</p> @enderror
            </div>

            <button
                type="submit"
                class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold py-2.5 rounded-xl transition-colors duration-150"
                wire:loading.attr="disabled" wire:loading.class="opacity-60"
            >
                <span wire:loading.remove>Verify</span>
                <span wire:loading>Verifying…</span>
            </button>

            @if(auth()->user()->two_factor_type === 'email')
                <button
                    type="button"
                    wire:click="sendEmailOtp"
                    class="w-full text-sm text-gray-500 hover:text-gray-300 transition"
                    wire:loading.attr="disabled"
                >
                    Resend code
                </button>
            @endif
        </form>

        <div class="mt-6 pt-4 border-t border-gray-800 text-center" x-data="{ showRecovery: false }">
            <button @click="showRecovery = !showRecovery" class="text-xs text-gray-600 hover:text-gray-400 transition">
                Use a recovery code instead
            </button>
            <form x-show="showRecovery" x-cloak wire:submit="useRecoveryCode" class="mt-3 space-y-2"
                x-transition:enter="transition ease-out duration-150" x-transition:enter-start="opacity-0 -translate-y-1" x-transition:enter-end="opacity-100 translate-y-0">
                <input
                    wire:model="code"
                    type="text"
                    placeholder="Recovery code"
                    class="w-full bg-gray-800 border border-gray-700 text-white text-sm rounded-xl px-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition"
                >
                <button type="submit" class="w-full text-sm text-gray-400 hover:text-white transition">Submit recovery code</button>
            </form>
        </div>
    </div>
</div>