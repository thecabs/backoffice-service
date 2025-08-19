<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

/**
 * Porte un "tag de ressource" (sensibilité) dans les attributs de la requête
 * pour la PDP (PolicyDecision). Exemple d’usage en route:
 *   ->middleware('resource.tag:FINANCIAL')
 *   ->middleware('resource.tag:PII')
 */
class ResourceTag
{
    public function handle(Request $request, Closure $next, string $tag = 'GENERIC')
    {
        $normalized = strtoupper(trim($tag));

        // Attributs utilisés par la PDP et les logs
        $request->attributes->set('resource_tag', $normalized);
        $request->attributes->set('sensitivity', $normalized);

        return $next($request);
    }
}
