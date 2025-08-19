<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Http\Middleware\CheckJWTFromKeycloak;
use App\Models\AdminUser;
use App\Models\BackofficeLog;
use App\Services\TontineServiceClient;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\JsonResponse;

class TontineAdminController extends Controller
{
    public function __construct(
        private TontineServiceClient $tontineService
    ) {
        $this->middleware('auth.keycloak');
    }

    public function index(Request $request): JsonResponse
    {
        $queryParams = CheckJWTFromKeycloak::applyScopeFilter($request, [
            'page' => $request->get('page', 1),
            'limit' => $request->get('limit', 20),
            'status' => $request->get('status'),
            'search' => $request->get('search')
        ]);

        try {
            $data = $this->tontineService->getTontines($queryParams);
            return response()->json([
                'success' => true,
                'data' => $data
            ]);
        } catch (\Exception $e) {
            Log::error('Erreur lors de la récupération des tontines', ['error' => $e->getMessage()]);
            return response()->json(['success' => false, 'error' => 'Erreur lors de la récupération'], 500);
        }
    }

    public function show(Request $request, string $tontineId): JsonResponse
    {
        try {
            $data = $this->tontineService->getTontine($tontineId);
            return response()->json(['success' => true, 'data' => $data]);
        } catch (\Exception $e) {
            Log::error('Erreur show tontine', ['id' => $tontineId, 'error' => $e->getMessage()]);
            return response()->json(['success' => false, 'error' => 'Tontine non trouvée'], 404);
        }
    }

    public function suspend(Request $request, string $tontineId): JsonResponse
    {
        if (!CheckJWTFromKeycloak::hasPermission($request, 'tontines', 'suspend')) {
            return response()->json(['success' => false, 'error' => 'Permission refusée'], 403);
        }

        $validator = Validator::make($request->all(), [
            'reason' => 'required|string|max:255'
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'errors' => $validator->errors()], 422);
        }

        try {
            $adminUser = $request->get('admin_user');
            $result = $this->tontineService->suspendTontine($tontineId, $request->all());

            $this->logAction($adminUser, 'suspend_tontine', 'tontine', $tontineId, $request->all());

            return response()->json(['success' => true, 'data' => $result]);
        } catch (\Exception $e) {
            Log::error('Erreur suspend tontine', ['error' => $e->getMessage()]);
            return response()->json(['success' => false, 'error' => 'Erreur suspension'], 500);
        }
    }

    public function close(Request $request, string $tontineId): JsonResponse
    {
        if (!CheckJWTFromKeycloak::hasPermission($request, 'tontines', 'close')) {
            return response()->json(['success' => false, 'error' => 'Permission refusée'], 403);
        }

        $validator = Validator::make($request->all(), [
            'reason' => 'required|string|max:255'
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'errors' => $validator->errors()], 422);
        }

        try {
            $adminUser = $request->get('admin_user');
            $result = $this->tontineService->closeTontine($tontineId, $request->all());

            $this->logAction($adminUser, 'close_tontine', 'tontine', $tontineId, $request->all());

            return response()->json(['success' => true, 'data' => $result]);
        } catch (\Exception $e) {
            Log::error('Erreur close tontine', ['error' => $e->getMessage()]);
            return response()->json(['success' => false, 'error' => 'Erreur fermeture'], 500);
        }
    }

    private function logAction(array $adminUser, string $actionType, string $targetType, string $targetId, array $payload = []): void
    {
        try {
            $adminUserModel = AdminUser::findOrCreateFromJWT($adminUser);
            BackofficeLog::logAction(
                $adminUserModel->id,
                $adminUser['role'],
                $actionType,
                $targetType,
                $targetId,
                $payload
            );
        } catch (\Exception $e) {
            Log::error('Erreur log action tontine', ['error' => $e->getMessage()]);
        }
    }
}
