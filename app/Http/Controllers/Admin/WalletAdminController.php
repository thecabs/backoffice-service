<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Http;

class WalletAdminController extends Controller
{
    private string $base;

    public function __construct()
    {
        $this->base = rtrim(env('WALLET_SVC_URL', ''), '/');
    }

    private function http(Request $request)
{
    if (empty($this->base)) {
        logger()->error('wallet.bo.base_url_missing');
        abort(500, 'WALLET_SVC_URL not configured');
    }

    $token = $request->bearerToken();
    if (!$token) {
        logger()->warning('bo.http.missing_bearer');
        abort(401, 'unauthorized');
    }

    return Http::withToken($token)
        ->timeout((int) env('HTTP_CLIENT_TIMEOUT', 20))
        ->connectTimeout((int) env('HTTP_CONNECT_TIMEOUT', 10))
        ->acceptJson()
        ->withHeaders([
            'X-Request-ID'    => $request->header('X-Request-ID', uniqid('bo_', true)),
            'X-Forwarded-For' => $request->ip(),      // utile pour le calcul de trust côté service
            'X-Caller'        => 'backoffice',
        ]);
}

    private function upstreamOrProxy(JsonResponse|array $resp, int $status = 200): JsonResponse
    {
        // Helper si tu veux formater autrement plus tard
        return response()->json($resp, $status);
    }

    // GET /admin/wallets
    public function index(Request $request): JsonResponse
    {
        $resp = $this->http($request)->get($this->base . '/api/wallets', $request->query());

        if ($resp->failed()) {
            logger()->error('wallet.index upstream failed', ['status' => $resp->status(), 'body' => $resp->body()]);
            if (in_array($resp->status(), [401,403,404], true)) {
                return response()->json($resp->json(), $resp->status());
            }
            return response()->json(['error' => 'wallet_service_error'], 502);
        }

        return response()->json($resp->json(), $resp->status());
    }

    // GET /admin/wallets/{walletId}
    public function show(Request $request, string $walletId): JsonResponse
    {
        $resp = $this->http($request)->get($this->base . "/api/wallets/{$walletId}");

        if ($resp->failed()) {
            logger()->error('wallet.show upstream failed', ['walletId' => $walletId, 'status' => $resp->status(), 'body' => $resp->body()]);
            if (in_array($resp->status(), [401,403,404], true)) {
                return response()->json($resp->json(), $resp->status());
            }
            return response()->json(['error' => 'wallet_service_error'], 502);
        }

        return response()->json($resp->json(), $resp->status());
    }

    // GET /admin/wallets/{walletId}/transactions
    public function transactions(Request $request, string $walletId): JsonResponse
    {
        $resp = $this->http($request)->get($this->base . "/api/wallets/{$walletId}/transactions", $request->query());

        if ($resp->failed()) {
            logger()->error('wallet.transactions upstream failed', ['walletId' => $walletId, 'status' => $resp->status(), 'body' => $resp->body()]);
            if (in_array($resp->status(), [401,403,404], true)) {
                return response()->json($resp->json(), $resp->status());
            }
            return response()->json(['error' => 'wallet_service_error'], 502);
        }

        return response()->json($resp->json(), $resp->status());
    }

    // POST /admin/wallets/{walletId}/close  -> PUT /api/wallets/{wallet}/close
    public function close(Request $request, string $walletId): JsonResponse
    {
        $resp = $this->http($request)->put($this->base . "/api/wallets/{$walletId}/close");

        if ($resp->failed()) {
            logger()->error('wallet.close upstream failed', ['walletId' => $walletId, 'status' => $resp->status(), 'body' => $resp->body()]);
            if (in_array($resp->status(), [401,403,404], true)) {
                return response()->json($resp->json(), $resp->status());
            }
            return response()->json(['error' => 'wallet_service_error'], 502);
        }

        return response()->json($resp->json(), $resp->status());
    }

    // POST /admin/wallets/{walletId}/freeze -> PUT /api/wallets/{wallet}/suspend
    public function freeze(Request $request, string $walletId): JsonResponse
    {
        $resp = $this->http($request)->put($this->base . "/api/wallets/{$walletId}/suspend");

        if ($resp->failed()) {
            logger()->error('wallet.freeze upstream failed', ['walletId' => $walletId, 'status' => $resp->status(), 'body' => $resp->body()]);
            if (in_array($resp->status(), [401,403,404], true)) {
                return response()->json($resp->json(), $resp->status());
            }
            return response()->json(['error' => 'wallet_service_error'], 502);
        }

        return response()->json($resp->json(), $resp->status());
    }

    // POST /admin/wallets/{walletId}/unfreeze -> PUT /api/wallets/{wallet}/activate
    public function unfreeze(Request $request, string $walletId): JsonResponse
    {
        $resp = $this->http($request)->put($this->base . "/api/wallets/{$walletId}/activate");

        if ($resp->failed()) {
            logger()->error('wallet.unfreeze upstream failed', ['walletId' => $walletId, 'status' => $resp->status(), 'body' => $resp->body()]);
            if (in_array($resp->status(), [401,403,404], true)) {
                return response()->json($resp->json(), $resp->status());
            }
            return response()->json(['error' => 'wallet_service_error'], 502);
        }

        return response()->json($resp->json(), $resp->status());
    }
}
