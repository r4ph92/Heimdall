<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class VaultEntry extends Model
{
    protected $fillable = [
        'user_id',
        'service_name',
        'username',
        'url',
        'is_favorite',
        'encrypted_password',
        'encrypted_notes',
        'iv',
        'notes_iv',
    ];

    protected function casts(): array
    {
        return ['is_favorite' => 'boolean'];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
