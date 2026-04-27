# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Heimdall is a zero-knowledge password manager built as a school project (Cegep session 3). The teacher values security reasoning, so always explain the *why* behind security decisions.

## Stack

- **Backend:** Laravel 13, PHP 8.3, SQLite (no external DB needed)
- **Frontend:** Livewire 4 (inline anonymous components with `⚡` prefix), Alpine.js, Tailwind CSS 4, Vite
- **Security libs:** `pragmarx/google2fa` (TOTP), `bacon/bacon-qr-code` (QR), `web-auth/webauthn-lib` (passkeys — installed but not integrated)

## Commands

```bash
composer install && npm install   # Install dependencies
composer run dev                  # Start everything: Laravel server, Vite, queue listener, log tail
composer run test                 # php artisan test (clears config cache first)
php artisan migrate               # Apply migrations (SQLite auto-creates the file)
```

## Architecture

### Authentication & Middleware Chain

```
auth  →  EnsureVaultKeyInSession  →  EnsureMfaVerified  →  vault routes
```

- On login: master password verified → PBKDF2 key derived → stored in `session('vault_key')` (never persisted to DB)
- If MFA enabled: redirect to `/mfa/challenge` before granting vault access; `session('mfa_verified')` is the gate
- Lost master password = permanently inaccessible vault (by design, zero-knowledge)

### Encryption Model

`EncryptionService.php` — AES-256-GCM with random 12-byte IV per field, 16-byte auth tag appended to ciphertext. Key derived via PBKDF2-SHA256 (master_password + per-user `vault_salt`, 200 000 iterations, 32-byte output). Each encrypted field stores `{ciphertext}{tag}` and its IV separately, both base64-encoded.

### Livewire Component Convention

All Livewire components use **inline anonymous classes** inside `resources/views/components/`. File names are prefixed with `⚡` (e.g., `⚡entry-list.blade.php`). The PHP class lives inside the Blade file itself with `new class extends Component { ... }`. Events flow via `$this->dispatch('event-name')` and `#[On('event-name')]`.

### Database Schema (key tables)

| Table | Purpose |
|---|---|
| `users` | Auth + `vault_salt` + MFA config (`mfa_type`, `totp_secret`, `recovery_codes`, `mfa_enabled`) |
| `vault_entries` | `encrypted_password` + `password_iv`, `encrypted_notes` + `notes_iv`, plaintext metadata (service, username, URL) |
| `webauthn_credentials` | Passkey storage — populated by UI scaffold but backend routes/verification not yet implemented |
| `sessions` | Holds `vault_key` and `mfa_verified` flag |

## What Is Done vs. What Is Not

### Fully Implemented

- Zero-knowledge encryption (`EncryptionService`)
- Register/login with vault key derivation
- MFA: email OTP (cached 10 min, single-use), TOTP (Google Authenticator + QR), recovery codes
- Vault: create, list, delete entries; export as JSON
- Security audit: entropy scoring, weak/reused password detection, age warnings, overall score
- Password generator (cryptographically secure, configurable)
- Master password rotation (re-encrypts full vault, regenerates salt)
- Account deletion
- Dark/light theme (localStorage)

### Incomplete / Stub

| What | Where | State |
|---|---|---|
| Entry detail view | `resources/views/components/vault/⚡entry-detail.blade.php` | Done — full edit form, pre-populated with decrypted values |
| WebAuthn / Passkeys | `app/Models/WebauthnCredential.php`, settings UI | Library installed, UI scaffolded, **no backend routes or verification logic** |
| Tests | `tests/Feature/`, `tests/Unit/` | **Placeholder stubs only** — PHPUnit runs but covers nothing real |
| Console commands | `routes/console.php` | Empty |

### Not Started

- Rate limiting on login attempts
- Audit logging (who accessed which entry, when)
- Vault sharing / delegation
- Browser extension for opera or chrome
