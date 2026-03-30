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
        Schema::create('webauthn_credentials', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            // The credential ID issued by the authenticator (base64url encoded)
            $table->text('credential_id')->unique();
            // The public key used to verify assertions (base64 encoded CBOR)
            $table->text('public_key');
            // Signature counter — we track this to detect cloned authenticators
            $table->unsignedBigInteger('sign_count')->default(0);
            // Human-readable name set by the user (e.g. "MacBook Touch ID")
            $table->string('name')->default('Passkey');
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('webauthn_credentials');
    }
};
