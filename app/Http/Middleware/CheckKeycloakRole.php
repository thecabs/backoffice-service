<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

/**
 * Middleware de compat : vérifie un rôle *canonique* injecté par CheckJWTFromKeycloak.
 * Préfère, quand c’est possible, l’appel à CheckJWTFromKeycloak::hasPermission($req, $module, $action).
 */
class CheckKeycloakRole
{
    public function handle(Request $request, Closure $next, string $requiredRolesCsv)
    {
        $admin = $request->attributes->get('admin_user');
        if (!$admin || empty($admin['role'])) {
            return response()->json(['error' => 'Access Denied - No canonical role'], 403);
        }

        $required = array_values(array_filter(array_map('trim', explode(',', strtolower($requiredRolesCsv)))));
        $canon    = strtolower((string) $admin['role']);

        if (in_array($canon, $required, true)) {
            return $next($request);
        }

        return response()->json([
            'error'          => 'Access Denied - Missing role',
            'required_roles' => $required,
            'user_role'      => $canon,
        ], 403);
    }
}
