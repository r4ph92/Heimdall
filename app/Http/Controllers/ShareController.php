<?php

namespace App\Http\Controllers;

use App\Models\SharedEntry;
use Illuminate\Http\JsonResponse;

class ShareController extends Controller
{
    /**
     * Render the public share page. The page decrypts the blob entirely client-side;
     * this route only serves the HTML shell.
     */
    public function show(string $token)
    {
        $share = SharedEntry::where('token', $token)->firstOrFail();

        return view('share', ['share' => $share]);
    }

    /**
     * Return the encrypted blob and IV for a given token.
     * Called via fetch() from the share page's Alpine.js component.
     * The server only ever returns ciphertext — the decryption key lives in the URL fragment.
     */
    public function payload(string $token): JsonResponse
    {
        $share = SharedEntry::where('token', $token)->firstOrFail();

        if ($share->isExpired()) {
            return response()->json(['error' => 'This link has expired.'], 410);
        }

        return response()->json([
            'encrypted_blob' => $share->encrypted_blob,
            'iv'             => $share->iv,
            'entry_name'     => $share->entry_name,
            'expires_at'     => $share->expires_at->toDateTimeString(),
        ]);
    }
}
