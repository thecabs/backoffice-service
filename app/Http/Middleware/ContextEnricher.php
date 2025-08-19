<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class ContextEnricher
{
    public function handle(Request $request, Closure $next)
    {
        // -------- Subject (depuis CheckJWTFromKeycloak) ----------
        $admin  = (array) $request->attributes->get('admin_user', []);
        $claims = (array) $request->attributes->get('token_data', []);
        $roles  = (array) $request->attributes->get('token_roles', []);

        $subject = [
            'sub'         => (string) ($admin['external_id'] ?? $claims['sub'] ?? ''),
            'username'    => (string) ($admin['username'] ?? $claims['preferred_username'] ?? ''),
            'roles'       => array_values(array_unique(array_map('strtolower', (array) $roles))),
            'agency_id'   => $admin['agency_id'] ?? ($claims['agency_id'] ?? null),
            'email'       => $admin['email'] ?? ($claims['email'] ?? null),
            'actor_role'  => $admin['role'] ?? null, // rôle canonique BO
        ];

        // -------- Action (intention) ----------
        $method = strtoupper($request->getMethod());
        $action = match ($method) {
            'GET', 'HEAD', 'OPTIONS' => 'read',
            'POST', 'PUT', 'PATCH', 'DELETE' => 'write',
            default => 'read',
        };

        // -------- Module & Sensitivity ----------
        // Déduit du chemin: /admin/<module>/...
        $path = trim($request->path(), '/');
        $first = explode('/', $path)[1] ?? ''; // index 0 = admin, 1 = module
        $module = strtolower($first);

        // Fallback si route non prefixée admin
        if ($module === '' && str_starts_with($path, 'admin')) {
            $module = 'dashboard';
        }

        // Sensibilité par défaut (PII pour users, FINANCIAL pour wallets/ceilings)
        $sensitivity = match ($module) {
            'users'    => 'PII',
            'wallets'  => 'FINANCIAL',
            'ceilings' => 'FINANCIAL',
            'tontines' => 'FINANCIAL',
            default    => 'LOW',
        };

        // Si un tag explicite est déjà posé ailleurs, on le respecte
        $explicitTag = $request->attributes->get('zt.sensitivity');
        if (is_string($explicitTag) && $explicitTag !== '') {
            $sensitivity = $explicitTag;
        }

        // -------- Request Id ----------
        $requestId = $request->headers->get('X-Request-Id') ?: (string) Str::uuid();

        // -------- Attachements ----------
        $request->attributes->set('zt.subject',     $subject);
        $request->attributes->set('zt.action',      $action);
        $request->attributes->set('zt.module',      $module);
        $request->attributes->set('zt.sensitivity', $sensitivity);
        $request->attributes->set('request_id',     $requestId);

        // Pour compat avec d’autres MS
        $request->attributes->set('external_id', $subject['sub']);
        $request->attributes->set('agency_id',   $subject['agency_id']);
        $request->attributes->set('token_roles', $subject['roles']);

        return $next($request);
    }
}
