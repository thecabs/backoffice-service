<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Http\Request;

/**
 * Idempotence HTTP basée sur le header `Idempotency-Key`.
 *
 * - Si pas de header => passe.
 * - Si clé déjà vue => rejoue la réponse précédente (X-Idempotent-Replay: 1).
 * - Si clé en cours (LOCK) => 409 conflict (évite doublons concurrents).
 * - Sinon => lock, exécute, met en cache le résultat pendant TTL (par défaut 600s).
 *
 * Usage route : ->middleware('idempotency:600')
 */
class Idempotency
{
    public function __construct(private CacheRepository $cache) {}

    public function handle(Request $request, Closure $next, int|string $ttlSeconds = 600)
    {
        $ttl = (int) $ttlSeconds;
        $key = $request->headers->get('Idempotency-Key');

        if (!$key) {
            return $next($request);
        }

        $cacheKey = $this->cacheKey($key);

        // 1) Déjà traité ?
        $entry = $this->cache->get($cacheKey);
        if (is_array($entry)) {
            return $this->replay($entry, $key);
        }

        // 2) Lock atomique (si existe déjà => conflit)
        if (!$this->cache->add($cacheKey, ['state' => 'LOCK'], $ttl)) {
            return response()->json([
                'success'           => false,
                'error'             => 'Idempotency key in progress',
                'idempotent_replay' => true,
            ], 409)->withHeaders(['Idempotency-Key' => $key]);
        }

        // 3) Exécute la requête puis stocke le résultat
        try {
            $response = $next($request);

            $payload = [
                'state'        => 'RESULT',
                'status'       => $response->getStatusCode(),
                'content'      => (string) $response->getContent(),
                'content_type' => $response->headers->get('Content-Type', 'application/json'),
            ];

            $this->cache->put($cacheKey, $payload, $ttl);

            // Ajoute l’entête sur la réponse courante
            $response->headers->set('Idempotency-Key', $key);
            return $response;

        } catch (\Throwable $e) {
            // Mémorise un échec générique pour rejouer une erreur cohérente
            $this->cache->put($cacheKey, [
                'state'        => 'RESULT',
                'status'       => 500,
                'content'      => json_encode(['success' => false, 'error' => 'idempotent_failed']),
                'content_type' => 'application/json',
            ], $ttl);
            throw $e;
        }
    }

    private function replay(array $entry, string $key)
    {
        // LOCK encore présent → conflit (requête concurrente)
        if (($entry['state'] ?? null) !== 'RESULT') {
            return response()->json([
                'success'           => false,
                'error'             => 'Idempotency key in progress',
                'idempotent_replay' => true,
            ], 409)->withHeaders(['Idempotency-Key' => $key]);
        }

        $status      = (int) ($entry['status'] ?? 200);
        $content     = (string) ($entry['content'] ?? '');
        $contentType = (string) ($entry['content_type'] ?? 'application/json');

        $resp = response($content, $status);
        $resp->headers->set('Content-Type', $contentType);
        $resp->headers->set('Idempotency-Key', $key);
        $resp->headers->set('X-Idempotent-Replay', '1');

        return $resp;
    }

    private function cacheKey(string $key): string
    {
        $app = config('app.name', 'laravel');
        return sprintf('idem:%s:%s', strtolower($app), sha1($key));
    }
}
