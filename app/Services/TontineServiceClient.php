<?php

namespace App\Services;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Illuminate\Support\Facades\Log;

class TontineServiceClient
{
    private Client $client;
    private string $baseUrl;

    public function __construct()
    {
        $this->baseUrl = config('services.tontine_service.url', 'http://tontine-service:9005');

        $this->client = new Client([
            'base_uri' => $this->baseUrl,
            'timeout' => 30,
            'headers' => [
                'Content-Type' => 'application/json',
                'Accept' => 'application/json'
            ]
        ]);
    }

    public function getTontines(array $filters = []): array
    {
        $response = $this->client->get('/api/tontines', [
            'query' => $filters
        ]);

        return $this->handleResponse($response);
    }

    public function getTontine(string $tontineId): array
    {
        $response = $this->client->get("/api/tontines/{$tontineId}");
        return $this->handleResponse($response);
    }

    public function suspendTontine(string $tontineId, array $data): array
    {
        $response = $this->client->post("/api/tontines/{$tontineId}/suspend", [
            'json' => $data
        ]);
        return $this->handleResponse($response);
    }

    public function closeTontine(string $tontineId, array $data): array
    {
        $response = $this->client->post("/api/tontines/{$tontineId}/close", [
            'json' => $data
        ]);
        return $this->handleResponse($response);
    }

    public function getTontineStats(array $filters = []): array
    {
        $response = $this->client->get('/api/tontines/stats', [
            'query' => $filters
        ]);
        return $this->handleResponse($response);
    }

    private function handleResponse($response): array
    {
        $statusCode = $response->getStatusCode();
        $body = json_decode($response->getBody()->getContents(), true);

        if ($statusCode >= 200 && $statusCode < 300) {
            return $body;
        }

        throw new \Exception($body['message'] ?? 'Erreur inconnue du service Tontine');
    }
}
