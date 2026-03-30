<?php

namespace App\Models;

use Database\Factories\UserFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

#[Fillable(['name', 'email', 'password', 'vault_salt', 'two_factor_type', 'two_factor_secret', 'two_factor_confirmed_at', 'two_factor_recovery_codes'])]
#[Hidden(['password', 'remember_token', 'vault_salt', 'two_factor_secret', 'two_factor_recovery_codes'])]
class User extends Authenticatable
{
    /** @use HasFactory<UserFactory> */
    use HasFactory, Notifiable;

    protected function casts(): array
    {
        return [
            'email_verified_at'       => 'datetime',
            'two_factor_confirmed_at' => 'datetime',
            'password'                => 'hashed',
        ];
    }

    public function hasMfaEnabled(): bool
    {
        return $this->two_factor_type !== null
            && ($this->two_factor_type !== 'totp' || $this->two_factor_confirmed_at !== null);
    }

    public function vaultEntries(): HasMany
    {
        return $this->hasMany(VaultEntry::class);
    }

    public function webauthnCredentials(): HasMany
    {
        return $this->hasMany(WebauthnCredential::class);
    }
}
