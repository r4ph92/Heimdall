<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            // Plaintext token for fast lookup — acceptable for a local school project.
            // Production would store a hashed token and use a short prefix index for lookup.
            $table->string('extension_token', 64)->nullable()->unique()->after('remember_token');
            $table->timestamp('extension_token_expires_at')->nullable()->after('extension_token');
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn(['extension_token', 'extension_token_expires_at']);
        });
    }
};
