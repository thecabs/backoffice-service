<?php

namespace App\Services;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Illuminate\Support\Facades\Log;

class WalletServiceClient
{
    private Client $client;
    private string $baseUrl;
    private string $defaultCurrency;

    public function __construct()
    {
        // URL du service Wallet
        $this->baseUrl = rtrim((string) config('services.wallet_service.url', 'http://192.168.1.225:8003'), '/');

        // Devise par défaut (utilisée si non fournie dans les filtres)
        $this->defaultCurrency = strtoupper((string) config('services.wallet_service.default_currency', 'XAF'));

        $this->client = new Client([
            'base_uri' => $this->baseUrl,
            'timeout'  => 30,
        ]);
    }

    /**
     * Récupérer la liste des wallets (POST + currency auto)
     */
    public function getWallets(array $filters = []): array
    {
        try {
            $payload = $this->injectDefaults($filters);

            // ⚠ Ton service renvoie 405 sur GET => on passe en POST
            $response = $this->client->post('/api/wallets', [
                'headers' => $this->requestHeaders(),
                'json'    => $payload,
            ]);

            return $this->handleResponse($response);

        } catch (RequestException $e) {
            Log::error('Erreur appel wallet-service getWallets', [
                'filters' => $filters,
                'error'   => $this->exMsg($e),
            ]);
            throw new \Exception('Erreur lors de la récupération des wallets');
        }
    }

    /**
     * Récupérer un wallet par son ID (laisse GET tel quel pour l’instant)
     * Si ton service attend POST, dis-le-moi et je bascule ici aussi.
     */
    public function getWallet(string $walletId): array
    {
        try {
            $response = $this->client->get("/api/wallets/{$walletId}", [
                'headers' => $this->requestHeaders(),
            ]);

            return $this->handleResponse($response);

        } catch (RequestException $e) {
            Log::error('Erreur appel wallet-service getWallet', [
                'wallet_id' => $walletId,
                'error'     => $this->exMsg($e),
            ]);
            if ($e->getResponse() && $e->getResponse()->getStatusCode() === 404) {
                throw new \Exception('Wallet non trouvé');
            }
            throw new \Exception('Erreur lors de la récupération du wallet');
        }
    }

    /**
     * Récupérer les statistiques agrégées des wallets (GET)
     */
    public function getWalletStats(array $filters = []): array
    {
        try {
            $response = $this->client->get('/api/wallets/stats', [
                'headers' => $this->requestHeaders(),
                'query'   => $filters,
            ]);
            return $this->handleResponse($response);

        } catch (RequestException $e) {
            Log::error('Erreur appel wallet-service getWalletStats', [
                'filters' => $filters,
                'error'   => $this->exMsg($e),
            ]);
            throw new \Exception('Erreur lors de la récupération des statistiques wallet');
        }
    }

    /**
     * Fermer un wallet
     */
    public function closeWallet(string $walletId, array $closureData): array
    {
        try {
            $response = $this->client->post("/api/wallets/{$walletId}/close", [
                'headers' => $this->requestHeaders(),
                'json'    => $closureData,
            ]);
            return $this->handleResponse($response);

        } catch (RequestException $e) {
            Log::error('Erreur appel wallet-service closeWallet', [
                'wallet_id' => $walletId,
                'data'      => $closureData,
                'error'     => $this->exMsg($e),
            ]);
            throw new \Exception('Erreur lors de la fermeture du wallet');
        }
    }

    /**
     * Bloquer temporairement un wallet
     */
    public function freezeWallet(string $walletId, array $freezeData): array
    {
        try {
            $response = $this->client->post("/api/wallets/{$walletId}/freeze", [
                'headers' => $this->requestHeaders(),
                'json'    => $freezeData,
            ]);
            return $this->handleResponse($response);

        } catch (RequestException $e) {
            Log::error('Erreur appel wallet-service freezeWallet', [
                'wallet_id' => $walletId,
                'data'      => $freezeData,
                'error'     => $this->exMsg($e),
            ]);
            throw new \Exception('Erreur lors du blocage du wallet');
        }
    }

    /**
     * Débloquer un wallet
     */
    public function unfreezeWallet(string $walletId, array $unfreezeData): array
    {
        try {
            $response = $this->client->post("/api/wallets/{$walletId}/unfreeze", [
                'headers' => $this->requestHeaders(),
                'json'    => $unfreezeData,
            ]);
            return $this->handleResponse($response);

        } catch (RequestException $e) {
            Log::error('Erreur appel wallet-service unfreezeWallet', [
                'wallet_id' => $walletId,
                'data'      => $unfreezeData,
                'error'     => $this->exMsg($e),
            ]);
            throw new \Exception('Erreur lors du déblocage du wallet');
        }
    }

    /**
     * Récupérer les transactions d’un wallet (GET par défaut)
     * Si ton service exige aussi `currency` ici et en POST → on adaptera pareil.
     */
    public function getWalletTransactions(string $walletId, array $filters = []): array
    {
        try {
            $response = $this->client->get("/api/wallets/{$walletId}/transactions", [
                'headers' => $this->requestHeaders(),
                'query'   => $filters,
            ]);
            return $this->handleResponse($response);

        } catch (RequestException $e) {
            Log::error('Erreur appel wallet-service getWalletTransactions', [
                'wallet_id' => $walletId,
                'filters'   => $filters,
                'error'     => $this->exMsg($e),
            ]);
            throw new \Exception('Erreur lors de la récupération des transactions du wallet');
        }
    }

    /**
     * Ajoute les champs obligatoires par défaut (ex: currency)
     */
    private function injectDefaults(array $data): array
    {
        if (empty($data['currency'])) {
            $data['currency'] = $this->defaultCurrency;
        }
        return $data;
    }

    /**
     * Entêtes dynamiques :
     * - Authorization: Bearer <token> (S2S si dispo, sinon token utilisateur)
     * - X-Admin-* (audit) si admin_user présent
     */
    private function requestHeaders(array $extra = []): array
    {
        $headers = [
            'Accept'       => 'application/json',
            'Content-Type' => 'application/json',
        ];

        // 1) Token S2S (si la classe existe)
        if (class_exists('\App\Support\KeycloakServiceToken')) {
            try {
                $t = \App\Support\KeycloakServiceToken::get();
                if (!empty($t)) {
                    $headers['Authorization'] = "Bearer {$t}";
                }
            } catch (\Throwable $e) {
                // fallback ci-dessous
            }
        }

        // 2) Fallback: token utilisateur du BO
        if (empty($headers['Authorization']) && function_exists('request')) {
            if ($tok = request()->bearerToken()) {
                $headers['Authorization'] = "Bearer {$tok}";
            }
            $admin = request()->attributes->get('admin_user') ?: request()->attributes->get('user_data');
            if (is_array($admin)) {
                if (!empty($admin['external_id'])) $headers['X-Admin-External-Id'] = (string) $admin['external_id'];
                if (!empty($admin['username']))    $headers['X-Admin-Username']    = (string) $admin['username'];
                if (!empty($admin['role']))        $headers['X-Admin-Role']        = (string) $admin['role'];
                if (!empty($admin['agency_id']))   $headers['X-Admin-Agency-Id']   = (string) $admin['agency_id'];
            }
        }

        return array_replace($headers, $extra);
    }

    /**
     * Traiter la réponse HTTP
     */
    private function handleResponse($response): array
    {
        $status = $response->getStatusCode();
        $body   = (string) $response->getBody();
        $json   = json_decode($body, true);

        if ($status >= 200 && $status < 300) {
            return is_array($json) ? $json : ['data' => $json];
        }

        $msg = is_array($json) ? ($json['message'] ?? $json['error'] ?? $body) : $body;
        throw new \Exception($msg ?: 'Erreur inconnue du service Wallet', $status);
    }

    private function exMsg(RequestException $e): string
    {
        $msg = $e->getMessage();
        if ($e->getResponse()) {
            $msg .= ' :: ' . (string) $e->getResponse()->getBody();
        }
        return $msg;
    }
}
