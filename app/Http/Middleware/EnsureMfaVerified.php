<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureMfaVerified
{
    /**
     * Handle an incoming request.
     *
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        // If the user has MFA enabled and hasn't completed the challenge this session,
        // redirect them to the MFA challenge page instead of letting them through.
        if ($user && $user->hasMfaEnabled() && ! session()->get('mfa_verified')) {
            return redirect()->route('mfa.challenge');
        }

        return $next($request);
    }
}
