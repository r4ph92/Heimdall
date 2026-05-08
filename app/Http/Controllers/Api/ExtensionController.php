<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class ExtensionController extends Controller
{
    /**
     * Authenticates the user and returns their vault_salt + encrypted entries.
     * The extension derives the vault key client-side and decrypts entries locally —
     * the server never sees plaintext passwords (zero-knowledge).
     */
    public function login(Request $request): JsonResponse
    {
        $request->validate([
            'email'    => 'required|email',
            'password' => 'required|string',
        ]);

        $user = User::where('email', $request->email)->first();

        if (! $user || ! Hash::check($request->password, $user->password)) {
            return response()->json(['error' => 'Invalid credentials'], 401);
        }

        $token = Str::random(64);

        $user->update([
            'extension_token'            => $token,
            'extension_token_expires_at' => now()->addDays(7),
        ]);

        return response()->json([
            'token'      => $token,
            'vault_salt' => $user->getRawOriginal('vault_salt'),
            'entries'    => $this->formatEntries($user),
        ]);
    }

    /**
     * Returns fresh encrypted entries for an already-authenticated extension session.
     */
    public function entries(Request $request): JsonResponse
    {
        return response()->json([
            'entries' => $this->formatEntries($request->extensionUser),
        ]);
    }

    /**
     * Revokes the extension token on logout.
     */
    public function logout(Request $request): JsonResponse
    {
        $request->extensionUser->update([
            'extension_token'            => null,
            'extension_token_expires_at' => null,
        ]);

        return response()->json(['ok' => true]);
    }

    private function formatEntries(User $user): array
    {
        return $user->vaultEntries()
            ->orderBy('service_name')
            ->get(['id', 'service_name', 'username', 'url', 'encrypted_password', 'iv', 'encrypted_notes', 'notes_iv'])
            ->toArray();
    }
}
