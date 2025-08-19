<?php

namespace App\Support;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * Récupère et met en cache un access_token "client_credentials"
 * pour les appels S2S vers les microservices.
 */
class KeycloakServiceToken
{
    public static function get(): ?string
    {
        $url      = (string) config('services.keycloak.token_url');
        $clientId = (string) config('services.keycloak.s2s_client_id');
        $secret   = (string) config('services.keycloak.s2s_client_secret');

        if ($url === '' || $clientId === '' || $secret === '') {
            return null; // S2S non configuré → fallback sur le token utilisateur
        }

        $cacheKey = 'kc:s2s:token:' . md5($url . '|' . $clientId);
        if ($cached = Cache::get($cacheKey)) {
            return $cached;
        }

        try {
            $res = Http::asForm()
                ->timeout(8)
                ->post($url, [
                    'grant_type'    => 'client_credentials',
                    'client_id'     => $clientId,
                    'client_secret' => $secret,
                ]);

            if (!$res->ok()) {
                Log::warning('KeycloakServiceToken: token request failed', [
                    'status' => $res->status(),
                    'body'   => $res->body(),
                ]);
                return null;
            }

            $json        = $res->json();
            $accessToken = $json['access_token'] ?? null;
            $expiresIn   = (int) ($json['expires_in'] ?? 60);

            if (!$accessToken) return null;

            Cache::put($cacheKey, $accessToken, max(1, $expiresIn - 30));
            return $accessToken;

        } catch (\Throwable $e) {
            Log::error('KeycloakServiceToken@get failed', ['error' => $e->getMessage()]);
            return null;
        }
    }

    public static function flush(): void
    {
        $url      = (string) config('services.keycloak.token_url');
        $clientId = (string) config('services.keycloak.s2s_client_id');
        if ($url === '' || $clientId === '') return;

        $cacheKey = 'kc:s2s:token:' . md5($url . '|' . $clientId);
        Cache::forget($cacheKey);
    }
}
