<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Http\Middleware\CheckJWTFromKeycloak;
use App\Models\AdminUser;
use App\Models\BackofficeLog;
use App\Services\UserCeilingServiceClient;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\JsonResponse;

class CeilingAdminController extends Controller
{
    public function __construct(
        private UserCeilingServiceClient $ceilingService
    ) {
        $this->middleware('auth.keycloak');
    }

    public function index(Request $request): JsonResponse
    {
        $filters = CheckJWTFromKeycloak::applyScopeFilter($request, [
            'status' => $request->get('status'),
            'limit' => $request->get('limit', 20),
            'page' => $request->get('page', 1)
        ]);

        try {
            $data = $this->ceilingService->getCeilings($filters);
            return response()->json(['success' => true, 'data' => $data]);
        } catch (\Exception $e) {
            Log::error('Erreur récupération plafonds', ['error' => $e->getMessage()]);
            return response()->json(['success' => false, 'error' => 'Erreur plafonds'], 500);
        }
    }

    public function show(Request $request, string $ceilingId): JsonResponse
    {
        try {
            $data = $this->ceilingService->getCeiling($ceilingId);
            return response()->json(['success' => true, 'data' => $data]);
        } catch (\Exception $e) {
            Log::error('Erreur show plafond', ['id' => $ceilingId, 'error' => $e->getMessage()]);
            return response()->json(['success' => false, 'error' => 'Plafond non trouvé'], 404);
        }
    }

    public function update(Request $request, string $ceilingId): JsonResponse
    {
        if (!CheckJWTFromKeycloak::hasPermission($request, 'ceilings', 'write')) {
            return response()->json(['success' => false, 'error' => 'Permission insuffisante'], 403);
        }

        $validator = Validator::make($request->all(), [
            'amount' => 'required|numeric|min:0',
            'comment' => 'nullable|string|max:500'
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'errors' => $validator->errors()], 422);
        }

        try {
            $adminUser = $request->get('admin_user');
            $result = $this->ceilingService->updateCeiling($ceilingId, $request->all());

            $this->logAction($adminUser, 'update_ceiling', 'ceiling', $ceilingId, $request->all());

            return response()->json(['success' => true, 'data' => $result]);
        } catch (\Exception $e) {
            Log::error('Erreur update plafond', ['id' => $ceilingId, 'error' => $e->getMessage()]);
            return response()->json(['success' => false, 'error' => 'Erreur mise à jour'], 500);
        }
    }

    private function logAction(array $adminUser, string $actionType, string $targetType, string $targetId, array $payload = []): void
    {
        try {
            $adminModel = AdminUser::findOrCreateFromJWT($adminUser);
            BackofficeLog::logAction(
                $adminModel->id,
                $adminUser['role'],
                $actionType,
                $targetType,
                $targetId,
                $payload
            );
        } catch (\Exception $e) {
            Log::error('Erreur log plafond', ['error' => $e->getMessage()]);
        }
    }
}
