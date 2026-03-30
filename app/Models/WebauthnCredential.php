<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class WebauthnCredential extends Model
{
    protected $fillable = [
        'user_id',
        'credential_id',
        'public_key',
        'sign_count',
        'name',
        'last_used_at',
    ];

    protected function casts(): array
    {
        return [
            'last_used_at' => 'datetime',
        ];
    }
}
