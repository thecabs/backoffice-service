<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class PolicyDecision
{
    public function handle(Request $request, Closure $next)
    {
        $requestId   = (string) ($request->attributes->get('request_id') ?? '');
        $subject     = (array)  $request->attributes->get('zt.subject', []);
        $module      = (string) ($request->attributes->get('zt.module') ?? '');
        $action      = (string) ($request->attributes->get('zt.action') ?? 'read');
        $sensitivity = (string) ($request->attributes->get('zt.sensitivity') ?? 'LOW');

        // Autorisation par table de permissions (définie dans CheckJWTFromKeycloak)
        $allowed = \App\Http\Middleware\CheckJWTFromKeycloak::hasPermission($request, $module ?: 'dashboard', $action);

        // Score de "risque" (simple & explicite pour logs/audit)
        $risk = 0;
        $risk += ($action === 'write') ? 1 : 0;
        $risk += in_array($sensitivity, ['FINANCIAL', 'PII'], true) ? 1 : 0;
        $risk = min($risk, 2); // 0..2

        // Obligations dynamiques (log uniquement ; MFA déjà appliqué par CheckJWTFromKeycloak)
        $obligations = [];
        if ($risk >= 2) {
            $obligations[] = 'mfa';
        }

        $logPayload = [
            'request_id' => $requestId,
            'sub'        => $subject['sub'] ?? null,
            'username'   => $subject['username'] ?? null,
            'roles'      => $subject['roles'] ?? [],
            'agency_id'  => $subject['agency_id'] ?? null,
            'module'     => $module,
            'action'     => $action,
            'sensitivity'=> $sensitivity,
            'risk'       => $risk,
            'obligations'=> $obligations,
            'path'       => $request->path(),
            'method'     => $request->method(),
            'allowed'    => $allowed,
        ];

        Log::info('pdp.decision', $logPayload);

        if (!$allowed) {
            return response()->json([
                'success'     => false,
                'decision'    => 'deny',
                'reason'      => 'not_permitted',
                'request_id'  => $requestId,
                'module'      => $module,
                'action'      => $action,
                'sensitivity' => $sensitivity,
            ], 403);
        }

        // On laisse passer, en ajoutant une trace header côté réponse
        /** @var \Symfony\Component\HttpFoundation\Response $resp */
        $resp = $next($request);
        $resp->headers->set('X-PDP-Decision', 'allow');
        $resp->headers->set('X-Request-Id', $requestId);

        return $resp;
    }
}
