<?php

namespace App\Http\Middleware;

use App\Models\User;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class ExtensionTokenAuth
{
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->bearerToken();

        if (! $token) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $user = User::where('extension_token', $token)
            ->where('extension_token_expires_at', '>', now())
            ->first();

        if (! $user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $request->extensionUser = $user;

        return $next($request);
    }
}
