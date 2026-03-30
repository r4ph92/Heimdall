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
        Schema::create('vault_entries', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('service_name');
            $table->string('username')->nullable();
            $table->string('url')->nullable();
            $table->text('encrypted_password'); // AES-256-GCM ciphertext (base64 encoded)
            $table->text('encrypted_notes')->nullable(); // notes are also encrypted at rest
            $table->string('iv'); // initialization vector for AES-GCM, unique per entry
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('vault_entries');
    }
};
