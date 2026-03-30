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
        'encrypted_password',
        'encrypted_notes',
        'iv',
        'notes_iv',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
