<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            // Which MFA method is active: null = disabled, 'email' = OTP to email, 'totp' = authenticator app
            $table->string('two_factor_type')->nullable()->after('vault_salt');
            // TOTP secret (base32 encoded), only set when type = 'totp'
            $table->text('two_factor_secret')->nullable()->after('two_factor_type');
            // Timestamp when TOTP was confirmed (scanned QR + entered first code)
            $table->timestamp('two_factor_confirmed_at')->nullable()->after('two_factor_secret');
            // JSON array of one-time recovery codes (hashed)
            $table->text('two_factor_recovery_codes')->nullable()->after('two_factor_confirmed_at');
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn([
                'two_factor_type',
                'two_factor_secret',
                'two_factor_confirmed_at',
                'two_factor_recovery_codes',
            ]);
        });
    }
};
