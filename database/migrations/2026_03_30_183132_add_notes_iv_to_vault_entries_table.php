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
        Schema::table('vault_entries', function (Blueprint $table) {
            // Notes are encrypted separately from the password — each needs its own unique IV
            $table->string('notes_iv')->nullable()->after('iv');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('vault_entries', function (Blueprint $table) {
            $table->dropColumn('notes_iv');
        });
    }
};
