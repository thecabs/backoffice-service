<?php

namespace App\Services;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Illuminate\Support\Facades\Log;

class UserCeilingServiceClient
{
    private Client $client;
    private string $baseUrl;

    public function __construct()
    {
        // URL du service plafonds (fallback vers user_service si non défini)
        $this->baseUrl = rtrim(
            config('services.userceiling_service.url', config('services.user_service.url', 'http://userceiling-service:9006')),
            '/'
        );

        $timeout = (int) config('services.userceiling_service.timeout', config('services.user_service.timeout', 30));

        $this->client = new Client([
            'base_uri'    => $this->baseUrl,
            'timeout'     => $timeout,
            // On gère nous-mêmes les erreurs pour logger proprement
            'http_errors' => false,
        ]);
    }

    /**
     * Headers par défaut pour JSON
     */
    private function defaultHeaders(): array
    {
        return [
            'Accept'       => 'application/json',
            'Content-Type' => 'application/json',
        ];
    }

    /**
     * Transfert du token Keycloak de la requête entrante
     */
    private function authHeaders(): array
    {
        $token = request()->bearerToken();
        return $token ? ['Authorization' => "Bearer {$token}"] : [];
    }

    public function getCeilings(array $filters = []): array
    {
        try {
            $response = $this->client->get('/api/ceilings', [
                'query'   => $filters,
                'headers' => array_merge($this->defaultHeaders(), $this->authHeaders()),
            ]);

            return $this->handleResponse($response);

        } catch (RequestException $e) {
            Log::error('Erreur appel userceiling-service getCeilings', [
                'filters' => $filters,
                'status'  => optional($e->getResponse())->getStatusCode(),
                'body'    => optional($e->getResponse())->getBody()?->getContents(),
                'error'   => $e->getMessage(),
            ]);
            throw new \Exception('Erreur lors de la récupération des plafonds');
        }
    }

    public function getCeiling(string $ceilingId): array
    {
        try {
            $response = $this->client->get("/api/ceilings/{$ceilingId}", [
                'headers' => array_merge($this->defaultHeaders(), $this->authHeaders()),
            ]);

            return $this->handleResponse($response);

        } catch (RequestException $e) {
            Log::error('Erreur appel userceiling-service getCeiling', [
                'id'     => $ceilingId,
                'status' => optional($e->getResponse())->getStatusCode(),
                'body'   => optional($e->getResponse())->getBody()?->getContents(),
                'error'  => $e->getMessage(),
            ]);
            throw new \Exception('Erreur lors de la récupération du plafond');
        }
    }

    public function updateCeiling(string $ceilingId, array $data): array
    {
        try {
            $response = $this->client->put("/api/ceilings/{$ceilingId}", [
                'json'    => $data,
                'headers' => array_merge($this->defaultHeaders(), $this->authHeaders()),
            ]);

            return $this->handleResponse($response);

        } catch (RequestException $e) {
            Log::error('Erreur appel userceiling-service updateCeiling', [
                'id'     => $ceilingId,
                'data'   => $data,
                'status' => optional($e->getResponse())->getStatusCode(),
                'body'   => optional($e->getResponse())->getBody()?->getContents(),
                'error'  => $e->getMessage(),
            ]);
            throw new \Exception('Erreur lors de la mise à jour du plafond');
        }
    }

    public function requestCeilingChange(string $userId, array $data): array
    {
        try {
            $response = $this->client->post("/api/users/{$userId}/ceilings/request", [
                'json'    => $data,
                'headers' => array_merge($this->defaultHeaders(), $this->authHeaders()),
            ]);

            return $this->handleResponse($response);

        } catch (RequestException $e) {
            Log::error('Erreur appel userceiling-service requestCeilingChange', [
                'user_id' => $userId,
                'data'    => $data,
                'status'  => optional($e->getResponse())->getStatusCode(),
                'body'    => optional($e->getResponse())->getBody()?->getContents(),
                'error'   => $e->getMessage(),
            ]);
            throw new \Exception('Erreur lors de la demande de changement de plafond');
        }
    }

    /**
     * Gestion standard des réponses HTTP JSON
     */
    private function handleResponse($response): array
    {
        $status = $response->getStatusCode();
        $raw    = (string) $response->getBody();
        $body   = json_decode($raw, true);

        if ($status >= 200 && $status < 300) {
            // On retourne toujours un array (si corps vide => tableau vide)
            return is_array($body) ? $body : [];
        }

        // Essayer de remonter un message utile
        $message = is_array($body)
            ? ($body['message'] ?? $body['error'] ?? 'Erreur du service plafond')
            : 'Erreur du service plafond';

        throw new \Exception($message . " (HTTP {$status})");
    }
}
