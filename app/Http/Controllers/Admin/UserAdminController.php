<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Http\Middleware\CheckJWTFromKeycloak;
use App\Models\AdminUser;
use App\Models\BackofficeLog;
use App\Services\UserServiceClient;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;

class UserAdminController extends Controller
{
    public function __construct(
        private UserServiceClient $userService
    ) {
        $this->middleware('auth.keycloak');
    }

    /**
     * Lister les utilisateurs avec filtres selon le rôle
     */
    public function index(Request $request): JsonResponse
    {
        try {
            $adminUser = $request->get('admin_user');
            
            // Construire les paramètres de requête avec les filtres de scope
            $queryParams = CheckJWTFromKeycloak::applyScopeFilter($request, [
                'page' => $request->get('page', 1),
                'limit' => $request->get('limit', 20),
                'status' => $request->get('status'),
                'search' => $request->get('search')
            ]);

            // Appel au user-service
            $users = $this->userService->getUsers($queryParams);

            return response()->json([
                'success' => true,
                'data' => $users,
                'filters_applied' => $queryParams,
                'user_role' => $adminUser['role']
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur lors de la récupération des utilisateurs', [
                'error' => $e->getMessage(),
                'admin_user' => $request->get('admin_user')
            ]);

            return response()->json([
                'success' => false,
                'error' => 'Erreur lors de la récupération des utilisateurs'
            ], 500);
        }
    }

    /**
     * Détails d'un utilisateur
     */
    public function show(Request $request, string $userId): JsonResponse
    {
        try {
            $adminUser = $request->get('admin_user');
            
            // Vérifier si l'admin peut voir cet utilisateur
            if (!$this->canAccessUser($request, $userId)) {
                return response()->json([
                    'success' => false,
                    'error' => 'Accès non autorisé à cet utilisateur'
                ], 403);
            }

            $user = $this->userService->getUser($userId);

            return response()->json([
                'success' => true,
                'data' => $user
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur lors de la récupération de l\'utilisateur', [
                'user_id' => $userId,
                'error' => $e->getMessage(),
                'admin_user' => $request->get('admin_user')
            ]);

            return response()->json([
                'success' => false,
                'error' => 'Utilisateur non trouvé'
            ], 404);
        }
    }

    /**
     * Valider un utilisateur (KYC)
     */
    public function validateUser(Request $request, string $userId): JsonResponse
    {
        // Vérifier les permissions
        if (!CheckJWTFromKeycloak::hasPermission($request, 'users', 'validate')) {
            return response()->json([
                'success' => false,
                'error' => 'Permission insuffisante'
            ], 403);
        }

        $validator = Validator::make($request->all(), [
            'reason' => 'required|string|max:500',
            'documents_validated' => 'required|array',
            'kyc_level' => 'required|in:basic,intermediate,advanced'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $adminUser = $request->get('admin_user');
            
            // Vérifier l'accès à cet utilisateur
            if (!$this->canAccessUser($request, $userId)) {
                return response()->json([
                    'success' => false,
                    'error' => 'Accès non autorisé à cet utilisateur'
                ], 403);
            }

            // Appel au user-service pour validation
            $result = $this->userService->validateUser($userId, $request->all());

            // Enregistrer l'action dans les logs
            $this->logAction(
                $adminUser,
                'validate_user',
                'user',
                $userId,
                $request->all()
            );

            return response()->json([
                'success' => true,
                'message' => 'Utilisateur validé avec succès',
                'data' => $result
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur lors de la validation de l\'utilisateur', [
                'user_id' => $userId,
                'error' => $e->getMessage(),
                'admin_user' => $request->get('admin_user')
            ]);

            return response()->json([
                'success' => false,
                'error' => 'Erreur lors de la validation'
            ], 500);
        }
    }

    /**
     * Suspendre un utilisateur
     */
    public function suspend(Request $request, string $userId): JsonResponse
    {
        // Vérifier les permissions
        if (!CheckJWTFromKeycloak::hasPermission($request, 'users', 'suspend')) {
            return response()->json([
                'success' => false,
                'error' => 'Permission insuffisante'
            ], 403);
        }

        $validator = Validator::make($request->all(), [
            'reason' => 'required|string|max:500',
            'suspension_type' => 'required|in:temporary,permanent',
            'duration_days' => 'required_if:suspension_type,temporary|integer|min:1|max:365'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $adminUser = $request->get('admin_user');
            
            // Vérifier l'accès à cet utilisateur
            if (!$this->canAccessUser($request, $userId)) {
                return response()->json([
                    'success' => false,
                    'error' => 'Accès non autorisé à cet utilisateur'
                ], 403);
            }

            // Appel au user-service pour suspension
            $result = $this->userService->suspendUser($userId, $request->all());

            // Enregistrer l'action dans les logs
            $this->logAction(
                $adminUser,
                'suspend_user',
                'user',
                $userId,
                $request->all()
            );

            return response()->json([
                'success' => true,
                'message' => 'Utilisateur suspendu avec succès',
                'data' => $result
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur lors de la suspension de l\'utilisateur', [
                'user_id' => $userId,
                'error' => $e->getMessage(),
                'admin_user' => $request->get('admin_user')
            ]);

            return response()->json([
                'success' => false,
                'error' => 'Erreur lors de la suspension'
            ], 500);
        }
    }

    /**
     * Réactiver un utilisateur suspendu
     */
    public function reactivate(Request $request, string $userId): JsonResponse
    {
        // Vérifier les permissions
        if (!CheckJWTFromKeycloak::hasPermission($request, 'users', 'suspend')) {
            return response()->json([
                'success' => false,
                'error' => 'Permission insuffisante'
            ], 403);
        }

        $validator = Validator::make($request->all(), [
            'reason' => 'required|string|max:500'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $adminUser = $request->get('admin_user');
            
            // Vérifier l'accès à cet utilisateur
            if (!$this->canAccessUser($request, $userId)) {
                return response()->json([
                    'success' => false,
                    'error' => 'Accès non autorisé à cet utilisateur'
                ], 403);
            }

            // Appel au user-service pour réactivation
            $result = $this->userService->reactivateUser($userId, $request->all());

            // Enregistrer l'action dans les logs
            $this->logAction(
                $adminUser,
                'reactivate_user',
                'user',
                $userId,
                $request->all()
            );

            return response()->json([
                'success' => true,
                'message' => 'Utilisateur réactivé avec succès',
                'data' => $result
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur lors de la réactivation de l\'utilisateur', [
                'user_id' => $userId,
                'error' => $e->getMessage(),
                'admin_user' => $request->get('admin_user')
            ]);

            return response()->json([
                'success' => false,
                'error' => 'Erreur lors de la réactivation'
            ], 500);
        }
    }

    /**
     * Historique des actions sur un utilisateur
     */
    public function actionHistory(Request $request, string $userId): JsonResponse
    {
        try {
            $adminUser = $request->get('admin_user');
            
            // Vérifier l'accès à cet utilisateur
            if (!$this->canAccessUser($request, $userId)) {
                return response()->json([
                    'success' => false,
                    'error' => 'Accès non autorisé à cet utilisateur'
                ], 403);
            }

            // Récupérer l'historique depuis les logs
            $logs = BackofficeLog::where('target_type', 'user')
                ->where('target_id', $userId)
                ->with('adminUser')
                ->orderBy('timestamp', 'desc')
                ->paginate(20);

            return response()->json([
                'success' => true,
                'data' => $logs
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur lors de la récupération de l\'historique', [
                'user_id' => $userId,
                'error' => $e->getMessage(),
                'admin_user' => $request->get('admin_user')
            ]);

            return response()->json([
                'success' => false,
                'error' => 'Erreur lors de la récupération de l\'historique'
            ], 500);
        }
    }

    /**
     * Mettre à jour le profil utilisateur (données non-KYC)
     */
    public function updateProfile(Request $request, string $userId): JsonResponse
    {
        // Vérifier les permissions
        if (!CheckJWTFromKeycloak::hasPermission($request, 'users', 'write')) {
            return response()->json([
                'success' => false,
                'error' => 'Permission insuffisante'
            ], 403);
        }

        $validator = Validator::make($request->all(), [
            'phone' => 'sometimes|string|regex:/^[0-9+\-\s()]+$/',
            'email' => 'sometimes|email',
            'preferences' => 'sometimes|array',
            'notes' => 'sometimes|string|max:1000'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $adminUser = $request->get('admin_user');
            
            // Vérifier l'accès à cet utilisateur
            if (!$this->canAccessUser($request, $userId)) {
                return response()->json([
                    'success' => false,
                    'error' => 'Accès non autorisé à cet utilisateur'
                ], 403);
            }

            // Appel au user-service pour mise à jour
            $result = $this->userService->updateUserProfile($userId, $request->all());

            // Enregistrer l'action dans les logs
            $this->logAction(
                $adminUser,
                'update_user_profile',
                'user',
                $userId,
                $request->all()
            );

            return response()->json([
                'success' => true,
                'message' => 'Profil utilisateur mis à jour avec succès',
                'data' => $result
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur lors de la mise à jour du profil', [
                'user_id' => $userId,
                'error' => $e->getMessage(),
                'admin_user' => $request->get('admin_user')
            ]);

            return response()->json([
                'success' => false,
                'error' => 'Erreur lors de la mise à jour'
            ], 500);
        }
    }

    /**
     * Vérifier si l'admin peut accéder à cet utilisateur
     */
    private function canAccessUser(Request $request, string $userId): bool
    {
        $adminUser = $request->get('admin_user');
        $permissions = CheckJWTFromKeycloak::getRolePermissions($adminUser['role']);
        
        // Superadmin et admin ont accès à tout
        if (in_array($adminUser['role'], ['superadmin', 'admin', 'AGI'])) {
            return true;
        }

        // Directeur d'agence : vérifier que l'utilisateur appartient à son agence
        if ($adminUser['role'] === 'directeur_agence') {
            try {
                $user = $this->userService->getUser($userId);
                return $user['agency_id'] === $adminUser['agency_id'] && 
                       $user['type'] === 'bancaire';
            } catch (\Exception $e) {
                return false;
            }
        }

        // GFC : seulement les comptes bancaires
        if ($adminUser['role'] === 'GFC') {
            try {
                $user = $this->userService->getUser($userId);
                return $user['type'] === 'bancaire';
            } catch (\Exception $e) {
                return false;
            }
        }

        // Lecteur : selon assignation (pour l'instant, accès global en lecture)
        if ($adminUser['role'] === 'lecteur') {
            return true;
        }

        return false;
    }

    /**
     * Enregistrer une action dans les logs
     */
    private function logAction(
        array $adminUser, 
        string $actionType, 
        string $targetType, 
        string $targetId, 
        array $payload = []
    ): void {
        try {
            // Créer ou récupérer l'admin user en base
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
            Log::error('Erreur lors de l\'enregistrement du log', [
                'error' => $e->getMessage(),
                'admin_user' => $adminUser,
                'action_type' => $actionType
            ]);
        }
    }
}