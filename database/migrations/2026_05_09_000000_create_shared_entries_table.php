<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('shared_entries', function (Blueprint $table) {
            $table->id();
            $table->foreignId('created_by')->constrained('users')->cascadeOnDelete();
            // Random token used in the public URL (/share/{token})
            $table->string('token', 64)->unique();
            // AES-256-GCM ciphertext — server never sees the plaintext or the key
            $table->text('encrypted_blob');
            // 12-byte IV used for AES-GCM, base64url encoded
            $table->string('iv', 32);
            // Plaintext service name shown on the share page before decryption
            $table->string('entry_name')->default('Shared Entry');
            $table->timestamp('expires_at');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('shared_entries');
    }
};
