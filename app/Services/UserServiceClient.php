<?php

namespace App\Services;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Illuminate\Support\Facades\Log;
use App\Support\KeycloakServiceToken;

class UserServiceClient
{
    private Client $client;
    private string $baseUrl;

    public function __construct()
    {
        $this->baseUrl = rtrim(config('services.user_service.url', 'http://10.91.34.206:8003'), '/');
        $timeout       = (int) config('services.user_service.timeout', 30);

        $this->client = new Client([
            'base_uri'    => $this->baseUrl,
            'timeout'     => $timeout,
            'http_errors' => false,
        ]);
    }

    private function defaultHeaders(): array
    {
        return [
            'Accept'       => 'application/json',
            'Content-Type' => 'application/json',
        ];
    }

    /** Auth S2S prioritaire + propagation identité admin pour audit */
    private function serviceHeaders(array $ctx = []): array
    {
        $headers = $this->defaultHeaders();

        // 1) Token S2S (client_credentials)
        if ($s2s = KeycloakServiceToken::get()) {
            $headers['Authorization'] = "Bearer {$s2s}";
        } else {
            // 2) Fallback: token utilisateur (au cas où)
            if ($tok = request()->bearerToken()) {
                $headers['Authorization'] = "Bearer {$tok}";
            }
        }

        // 3) En-têtes d’audit (facultatif, utile côté user-service)
        $admin = request()->attributes->get('user_data')
              ?: request()->attributes->get('admin_user');

        if (is_array($admin)) {
            if (!empty($admin['external_id'])) $headers['X-Admin-External-Id'] = $admin['external_id'];
            if (!empty($admin['username']))    $headers['X-Admin-Username']    = $admin['username'];
            if (!empty($admin['role']))        $headers['X-Admin-Role']        = $admin['role'];
            if (!empty($admin['agency_id']))   $headers['X-Admin-Agency-Id']   = $admin['agency_id'];
        }

        return $headers;
    }

    /** Normalisation + LOG en cas de non-2xx */
    private function handleResponse($response, string $where, array $ctx = []): array
    {
        $status = $response->getStatusCode();
        $raw    = (string) $response->getBody();
        $body   = json_decode($raw, true);

        if ($status >= 200 && $status < 300) {
            return is_array($body) ? $body : [];
        }

        Log::warning('user-service non-2xx', array_merge([
            'where'  => $where,
            'status' => $status,
            'body'   => $raw,
        ], $ctx));

        $message = is_array($body)
            ? ($body['message'] ?? $body['error'] ?? 'Erreur inconnue du service')
            : 'Erreur inconnue du service';

        throw new \Exception($message . " (HTTP {$status})");
    }

    /** Liste des utilisateurs */
    public function getUsers(array $filters = []): array
    {
        try {
            $resp = $this->client->get('/api/users', [
                'query'   => $filters,
                'headers' => $this->serviceHeaders(['filters' => $filters]),
            ]);
            return $this->handleResponse($resp, 'GET /api/users', ['filters' => $filters]);
        } catch (RequestException $e) {
            Log::error('Erreur user-service getUsers (network)', [
                'endpoint' => $this->baseUrl.'/api/users',
                'filters'  => $filters,
                'error'    => $e->getMessage(),
            ]);
            throw new \Exception('Erreur lors de la récupération des utilisateurs');
        }
    }

    /** Détail d’un utilisateur */
    public function getUser(string $userId): array
    {
        try {
            $resp = $this->client->get("/api/users/{$userId}", [
                'headers' => $this->serviceHeaders(),
            ]);
            if ($resp->getStatusCode() === 404) {
                Log::warning('user-service getUser: not found', [
                    'endpoint' => $this->baseUrl."/api/users/{$userId}",
                    'status'   => 404,
                ]);
                throw new \Exception('Utilisateur non trouvé');
            }
            return $this->handleResponse($resp, "GET /api/users/{$userId}");
        } catch (RequestException $e) {
            Log::error('Erreur user-service getUser (network)', [
                'endpoint' => $this->baseUrl."/api/users/{$userId}",
                'error'    => $e->getMessage(),
            ]);
            throw new \Exception('Erreur lors de la récupération de l\'utilisateur');
        }
    }

    /** Valider (KYC) */
    public function validateUser(string $userId, array $validationData): array
    {
        try {
            $resp = $this->client->post("/api/users/{$userId}/validate", [
                'json'    => $validationData,
                'headers' => $this->serviceHeaders(['payload' => $validationData]),
            ]);
            return $this->handleResponse($resp, "POST /api/users/{$userId}/validate", ['payload' => $validationData]);
        } catch (RequestException $e) {
            Log::error('Erreur user-service validateUser (network)', [
                'endpoint' => $this->baseUrl."/api/users/{$userId}/validate",
                'error'    => $e->getMessage(),
            ]);
            throw new \Exception('Erreur lors de la validation de l\'utilisateur');
        }
    }

    /** Suspendre */
    public function suspendUser(string $userId, array $suspensionData): array
    {
        try {
            $resp = $this->client->post("/api/users/{$userId}/suspend", [
                'json'    => $suspensionData,
                'headers' => $this->serviceHeaders(['payload' => $suspensionData]),
            ]);
            return $this->handleResponse($resp, "POST /api/users/{$userId}/suspend", ['payload' => $suspensionData]);
        } catch (RequestException $e) {
            Log::error('Erreur user-service suspendUser (network)', [
                'endpoint' => $this->baseUrl."/api/users/{$userId}/suspend",
                'error'    => $e->getMessage(),
            ]);
            throw new \Exception('Erreur lors de la suspension de l\'utilisateur');
        }
    }

    /** Réactiver */
    public function reactivateUser(string $userId, array $reactivationData): array
    {
        try {
            $resp = $this->client->post("/api/users/{$userId}/reactivate", [
                'json'    => $reactivationData,
                'headers' => $this->serviceHeaders(['payload' => $reactivationData]),
            ]);
            return $this->handleResponse($resp, "POST /api/users/{$userId}/reactivate", ['payload' => $reactivationData]);
        } catch (RequestException $e) {
            Log::error('Erreur user-service reactivateUser (network)', [
                'endpoint' => $this->baseUrl."/api/users/{$userId}/reactivate",
                'error'    => $e->getMessage(),
            ]);
            throw new \Exception('Erreur lors de la réactivation de l\'utilisateur');
        }
    }

    /** Update profil */
    public function updateUserProfile(string $userId, array $profileData): array
    {
        try {
            $resp = $this->client->put("/api/users/{$userId}/profile", [
                'json'    => $profileData,
                'headers' => $this->serviceHeaders(['payload' => $profileData]),
            ]);
            return $this->handleResponse($resp, "PUT /api/users/{$userId}/profile", ['payload' => $profileData]);
        } catch (RequestException $e) {
            Log::error('Erreur user-service updateUserProfile (network)', [
                'endpoint' => $this->baseUrl."/api/users/{$userId}/profile",
                'error'    => $e->getMessage(),
            ]);
            throw new \Exception('Erreur lors de la mise à jour du profil');
        }
    }

    /** Stats */
    public function getUserStats(array $filters = []): array
    {
        try {
            $resp = $this->client->get('/api/users/stats', [
                'query'   => $filters,
                'headers' => $this->serviceHeaders(['filters' => $filters]),
            ]);
            return $this->handleResponse($resp, 'GET /api/users/stats', ['filters' => $filters]);
        } catch (RequestException $e) {
            Log::error('Erreur user-service getUserStats (network)', [
                'endpoint' => $this->baseUrl.'/api/users/stats',
                'error'    => $e->getMessage(),
            ]);
            throw new \Exception('Erreur lors de la récupération des statistiques');
        }
    }

    /** Recherche */
    public function searchUsers(string $query, array $filters = []): array
    {
        try {
            $filters['search'] = $query;
            $resp = $this->client->get('/api/users/search', [
                'query'   => $filters,
                'headers' => $this->serviceHeaders(['filters' => $filters]),
            ]);
            return $this->handleResponse($resp, 'GET /api/users/search', ['filters' => $filters]);
        } catch (RequestException $e) {
            Log::error('Erreur user-service searchUsers (network)', [
                'endpoint' => $this->baseUrl.'/api/users/search',
                'error'    => $e->getMessage(),
            ]);
            throw new \Exception('Erreur lors de la recherche d\'utilisateurs');
        }
    }

    /** Historique transactions */
    public function getUserTransactionHistory(string $userId, array $filters = []): array
    {
        try {
            $resp = $this->client->get("/api/users/{$userId}/transactions", [
                'query'   => $filters,
                'headers' => $this->serviceHeaders(['filters' => $filters]),
            ]);
            return $this->handleResponse($resp, "GET /api/users/{$userId}/transactions", ['filters' => $filters]);
        } catch (RequestException $e) {
            Log::error('Erreur user-service getUserTransactionHistory (network)', [
                'endpoint' => $this->baseUrl."/api/users/{$userId}/transactions",
                'error'    => $e->getMessage(),
            ]);
            throw new \Exception('Erreur lors de la récupération de l\'historique');
        }
    }

    /** Docs KYC */
    public function getUserKYCDocuments(string $userId): array
    {
        try {
            $resp = $this->client->get("/api/users/{$userId}/kyc-documents", [
                'headers' => $this->serviceHeaders(),
            ]);
            return $this->handleResponse($resp, "GET /api/users/{$userId}/kyc-documents");
        } catch (RequestException $e) {
            Log::error('Erreur user-service getUserKYCDocuments (network)', [
                'endpoint' => $this->baseUrl."/api/users/{$userId}/kyc-documents",
                'error'    => $e->getMessage(),
            ]);
            throw new \Exception('Erreur lors de la récupération des documents KYC');
        }
    }
}
