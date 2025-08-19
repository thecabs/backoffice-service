<?php
namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Http\Middleware\CheckJWTFromKeycloak;
use App\Models\BackofficeLog;
use App\Services\UserServiceClient;
use App\Services\WalletServiceClient;
use App\Services\TontineServiceClient;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Carbon\Carbon;

class DashboardController extends Controller
{
    public function __construct(
        private UserServiceClient $userService,
        private WalletServiceClient $walletService,
        private TontineServiceClient $tontineService
    ) {
        $this->middleware('auth.keycloak');
    }

    

    /**
     * Dashboard principal avec KPIs filtrés selon le rôle
     */
    public function index(Request $request): JsonResponse
    {
        try {
            $adminUser = $request->get('admin_user');
            $period = $request->get('period', '30'); // 7, 30, 90 jours
            
            // Construire les filtres de base selon le rôle
            $baseFilters = CheckJWTFromKeycloak::applyScopeFilter($request);
            
            // Calculer les dates de période
            $endDate = Carbon::now();
            $startDate = Carbon::now()->subDays((int) $period);

            // Récupérer les KPIs selon le rôle
            $kpis = $this->getKPIsByRole($adminUser, $baseFilters, $startDate, $endDate);
            
            // Récupérer les actions récentes du back office
            $recentActions = $this->getRecentActions($adminUser, $period);
            
            // Récupérer les alertes
            $alerts = $this->getAlerts($adminUser, $baseFilters);

            return response()->json([
                'success' => true,
                'data' => [
                    'kpis' => $kpis,
                    'recent_actions' => $recentActions,
                    'alerts' => $alerts,
                    'period' => $period,
                    'filters_applied' => $baseFilters,
                    'user_role' => $adminUser['role']
                ]
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur lors de la génération du dashboard', [
                'error' => $e->getMessage(),
                'admin_user' => $request->get('admin_user')
            ]);

            return response()->json([
                'success' => false,
                'error' => 'Erreur lors de la génération du dashboard'
            ], 500);
        }
    }

    /**
     * Statistiques détaillées pour les superadmins/admins
     */
    public function detailedStats(Request $request): JsonResponse
    {
        $adminUser = $request->get('admin_user');
        
        // Vérifier les permissions
        if (!in_array($adminUser['role'], ['superadmin', 'admin'])) {
            return response()->json([
                'success' => false,
                'error' => 'Accès non autorisé'
            ], 403);
        }

        try {
            $period = $request->get('period', '30');
            $startDate = Carbon::now()->subDays((int) $period);
            $endDate = Carbon::now();

            $stats = [
                'users' => $this->getDetailedUserStats($startDate, $endDate),
                'wallets' => $this->getDetailedWalletStats($startDate, $endDate),
                'tontines' => $this->getDetailedTontineStats($startDate, $endDate),
                'backoffice_activity' => $this->getBackofficeActivityStats($startDate, $endDate)
            ];

            return response()->json([
                'success' => true,
                'data' => $stats
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur lors de la génération des stats détaillées', [
                'error' => $e->getMessage(),
                'admin_user' => $adminUser
            ]);

            return response()->json([
                'success' => false,
                'error' => 'Erreur lors de la génération des statistiques'
            ], 500);
        }
    }

    /**
     * Export des données selon le rôle
     */
    public function exportData(Request $request): JsonResponse
    {
        try {
            $adminUser = $request->get('admin_user');
            $exportType = $request->get('type', 'users'); // users, wallets, tontines
            $format = $request->get('format', 'csv'); // csv, excel
            
            // Vérifier les permissions d'export
            if (!$this->canExport($adminUser['role'], $exportType)) {
                return response()->json([
                    'success' => false,
                    'error' => 'Permission d\'export insuffisante'
                ], 403);
            }

            $baseFilters = CheckJWTFromKeycloak::applyScopeFilter($request, [
                'start_date' => $request->get('start_date'),
                'end_date' => $request->get('end_date'),
                'status' => $request->get('status')
            ]);

            // Générer l'export selon le type
            $exportData = match($exportType) {
                'users' => $this->exportUsers($baseFilters, $format),
                'wallets' => $this->exportWallets($baseFilters, $format),
                'tontines' => $this->exportTontines($baseFilters, $format),
                'logs' => $this->exportLogs($baseFilters, $format),
                default => throw new \Exception('Type d\'export non supporté')
            };

            return response()->json([
                'success' => true,
                'data' => $exportData,
                'message' => 'Export généré avec succès'
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur lors de l\'export de données', [
                'error' => $e->getMessage(),
                'admin_user' => $request->get('admin_user'),
                'export_type' => $request->get('type')
            ]);

            return response()->json([
                'success' => false,
                'error' => 'Erreur lors de l\'export'
            ], 500);
        }
    }

    /**
     * Récupérer les KPIs selon le rôle
     */
    private function getKPIsByRole(array $adminUser, array $filters, Carbon $startDate, Carbon $endDate): array
    {
        $role = $adminUser['role'];
        
        return match($role) {
            'superadmin', 'admin' => $this->getGlobalKPIs($filters, $startDate, $endDate),
            'directeur_agence' => $this->getAgencyKPIs($adminUser['agency_id'], $startDate, $endDate),
            'GFC' => $this->getBankingKPIs($filters, $startDate, $endDate),
            'AGI' => $this->getKYCKPIs($filters, $startDate, $endDate),
            'lecteur' => $this->getReadOnlyKPIs($filters, $startDate, $endDate),
            default => []
        };
    }

    /**
     * KPIs globaux pour superadmin/admin
     */
    private function getGlobalKPIs(array $filters, Carbon $startDate, Carbon $endDate): array
    {
        try {
            // Statistiques utilisateurs
            $userStats = $this->userService->getUserStats(array_merge($filters, [
                'start_date' => $startDate->toDateString(),
                'end_date' => $endDate->toDateString()
            ]));

            // Statistiques wallets
            $walletStats = $this->walletService->getWalletStats(array_merge($filters, [
                'start_date' => $startDate->toDateString(),
                'end_date' => $endDate->toDateString()
            ]));

            // Statistiques tontines
            $tontineStats = $this->tontineService->getTontineStats(array_merge($filters, [
                'start_date' => $startDate->toDateString(),
                'end_date' => $endDate->toDateString()
            ]));

            return [
                'users' => [
                    'total' => $userStats['total_users'] ?? 0,
                    'active' => $userStats['active_users'] ?? 0,
                    'new_registrations' => $userStats['new_registrations'] ?? 0,
                    'kyc_pending' => $userStats['kyc_pending'] ?? 0,
                    'suspended' => $userStats['suspended_users'] ?? 0
                ],
                'wallets' => [
                    'total' => $walletStats['total_wallets'] ?? 0,
                    'active' => $walletStats['active_wallets'] ?? 0,
                    'total_balance' => $walletStats['total_balance'] ?? 0,
                    'transactions_count' => $walletStats['transactions_count'] ?? 0,
                    'transactions_volume' => $walletStats['transactions_volume'] ?? 0
                ],
                'tontines' => [
                    'total' => $tontineStats['total_tontines'] ?? 0,
                    'active' => $tontineStats['active_tontines'] ?? 0,
                    'participants' => $tontineStats['total_participants'] ?? 0,
                    'total_amount' => $tontineStats['total_amount'] ?? 0
                ]
            ];

        } catch (\Exception $e) {
            Log::error('Erreur lors de la récupération des KPIs globaux', ['error' => $e->getMessage()]);
            return [];
        }
    }

    /**
     * KPIs pour directeur d'agence
     */
    private function getAgencyKPIs(string $agencyId, Carbon $startDate, Carbon $endDate): array
    {
        try {
            $filters = [
                'agency_id' => $agencyId,
                'type' => 'bancaire',
                'start_date' => $startDate->toDateString(),
                'end_date' => $endDate->toDateString()
            ];

            $userStats = $this->userService->getUserStats($filters);
            $walletStats = $this->walletService->getWalletStats($filters);

            return [
                'agency_users' => [
                    'total' => $userStats['total_users'] ?? 0,
                    'active' => $userStats['active_users'] ?? 0,
                    'new_registrations' => $userStats['new_registrations'] ?? 0,
                    'kyc_pending' => $userStats['kyc_pending'] ?? 0
                ],
                'agency_wallets' => [
                    'total' => $walletStats['total_wallets'] ?? 0,
                    'active' => $walletStats['active_wallets'] ?? 0,
                    'total_balance' => $walletStats['total_balance'] ?? 0
                ],
                'agency_performance' => [
                    'conversion_rate' => $userStats['conversion_rate'] ?? 0,
                    'average_balance' => $walletStats['average_balance'] ?? 0
                ]
            ];

        } catch (\Exception $e) {
            Log::error('Erreur lors de la récupération des KPIs agence', [
                'agency_id' => $agencyId,
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    /**
     * KPIs pour GFC (comptes bancaires uniquement)
     */
    private function getBankingKPIs(array $filters, Carbon $startDate, Carbon $endDate): array
    {
        try {
            $bankingFilters = array_merge($filters, [
                'type' => 'bancaire',
                'start_date' => $startDate->toDateString(),
                'end_date' => $endDate->toDateString()
            ]);

            $userStats = $this->userService->getUserStats($bankingFilters);
            $walletStats = $this->walletService->getWalletStats($bankingFilters);

            return [
                'banking_accounts' => [
                    'total' => $userStats['total_users'] ?? 0,
                    'active' => $userStats['active_users'] ?? 0,
                    'total_deposits' => $walletStats['total_deposits'] ?? 0,
                    'total_withdrawals' => $walletStats['total_withdrawals'] ?? 0
                ],
                'compliance' => [
                    'kyc_validated' => $userStats['kyc_validated'] ?? 0,
                    'suspicious_activities' => $walletStats['suspicious_activities'] ?? 0,
                    'large_transactions' => $walletStats['large_transactions'] ?? 0
                ]
            ];

        } catch (\Exception $e) {
            Log::error('Erreur lors de la récupération des KPIs bancaires', ['error' => $e->getMessage()]);
            return [];
        }
    }

    /**
     * KPIs pour AGI (KYC et plafonds)
     */
    private function getKYCKPIs(array $filters, Carbon $startDate, Carbon $endDate): array
    {
        try {
            $kycFilters = array_merge($filters, [
                'start_date' => $startDate->toDateString(),
                'end_date' => $endDate->toDateString()
            ]);

            $userStats = $this->userService->getUserStats($kycFilters);

            return [
                'kyc_status' => [
                    'pending_validation' => $userStats['kyc_pending'] ?? 0,
                    'validated_today' => $userStats['kyc_validated_today'] ?? 0,
                    'rejected' => $userStats['kyc_rejected'] ?? 0,
                    'expired_documents' => $userStats['expired_documents'] ?? 0
                ],
                'user_limits' => [
                    'ceiling_requests' => $userStats['ceiling_requests'] ?? 0,
                    'limit_exceeded' => $userStats['limit_exceeded'] ?? 0,
                    'average_ceiling' => $userStats['average_ceiling'] ?? 0
                ]
            ];

        } catch (\Exception $e) {
            Log::error('Erreur lors de la récupération des KPIs KYC', ['error' => $e->getMessage()]);
            return [];
        }
    }

    /**
     * KPIs en lecture seule
     */
    private function getReadOnlyKPIs(array $filters, Carbon $startDate, Carbon $endDate): array
    {
        // Version simplifiée pour les lecteurs
        try {
            $userStats = $this->userService->getUserStats(array_merge($filters, [
                'start_date' => $startDate->toDateString(),
                'end_date' => $endDate->toDateString()
            ]));

            return [
                'overview' => [
                    'total_users' => $userStats['total_users'] ?? 0,
                    'active_users' => $userStats['active_users'] ?? 0,
                    'transactions_count' => $userStats['transactions_count'] ?? 0
                ]
            ];

        } catch (\Exception $e) {
            Log::error('Erreur lors de la récupération des KPIs lecture seule', ['error' => $e->getMessage()]);
            return [];
        }
    }

    /**
     * Récupérer les actions récentes du back office
     */
    private function getRecentActions(array $adminUser, string $period): array
    {
        try {
            $query = BackofficeLog::with('adminUser')
                ->orderBy('timestamp', 'desc')
                ->limit(10);

            // Filtrer selon le rôle
            if ($adminUser['role'] === 'directeur_agence' && $adminUser['agency_id']) {
                // Pour les directeurs d'agence, montrer seulement les actions sur leur périmètre
                $query->whereHas('adminUser', function($q) use ($adminUser) {
                    $q->where('agency_id', $adminUser['agency_id']);
                });
            }

            $recentActions = $query->get()->map(function($log) {
                return [
                    'id' => $log->id,
                    'admin_username' => $log->adminUser->username ?? 'Inconnu',
                    'admin_role' => $log->role,
                    'action_type' => $log->action_type,
                    'target_type' => $log->target_type,
                    'target_id' => $log->target_id,
                    'timestamp' => $log->timestamp->format('Y-m-d H:i:s'),
                    'payload' => $log->payload
                ];
            });

            return $recentActions->toArray();

        } catch (\Exception $e) {
            Log::error('Erreur lors de la récupération des actions récentes', [
                'error' => $e->getMessage(),
                'admin_user' => $adminUser
            ]);
            return [];
        }
    }

    /**
     * Récupérer les alertes selon le rôle
     */
    private function getAlerts(array $adminUser, array $filters): array
    {
        $alerts = [];

        try {
            // Alertes communes
            $userStats = $this->userService->getUserStats($filters);
            
            if (($userStats['kyc_pending'] ?? 0) > 50) {
                $alerts[] = [
                    'type' => 'warning',
                    'message' => 'Plus de 50 validations KYC en attente',
                    'count' => $userStats['kyc_pending'],
                    'action_url' => '/admin/users?status=kyc_pending'
                ];
            }

            if (($userStats['suspended_users'] ?? 0) > 10) {
                $alerts[] = [
                    'type' => 'info',
                    'message' => 'Utilisateurs suspendus nécessitant une révision',
                    'count' => $userStats['suspended_users'],
                    'action_url' => '/admin/users?status=suspended'
                ];
            }

            // Alertes spécifiques selon le rôle
            if (in_array($adminUser['role'], ['superadmin', 'admin', 'GFC'])) {
                $walletStats = $this->walletService->getWalletStats($filters);
                
                if (($walletStats['suspicious_activities'] ?? 0) > 0) {
                    $alerts[] = [
                        'type' => 'danger',
                        'message' => 'Activités suspectes détectées',
                        'count' => $walletStats['suspicious_activities'],
                        'action_url' => '/admin/wallets?filter=suspicious'
                    ];
                }
            }

        } catch (\Exception $e) {
            Log::error('Erreur lors de la génération des alertes', [
                'error' => $e->getMessage(),
                'admin_user' => $adminUser
            ]);
        }

        return $alerts;
    }

    /**
     * Vérifier si l'utilisateur peut exporter
     */
    private function canExport(string $role, string $exportType): bool
    {
        $exportPermissions = [
            'superadmin' => ['users', 'wallets', 'tontines', 'logs'],
            'admin' => ['users', 'wallets', 'tontines', 'logs'],
            'directeur_agence' => ['users'],
            'GFC' => ['users', 'wallets'],
            'AGI' => ['users'],
            'lecteur' => []
        ];

        return in_array($exportType, $exportPermissions[$role] ?? []);
    }

    /**
     * Exporter les utilisateurs
     */
    private function exportUsers(array $filters, string $format): array
    {
        $users = $this->userService->getUsers(array_merge($filters, ['limit' => 10000]));
        
        return [
            'filename' => 'users_export_' . date('Y-m-d_H-i-s') . '.' . $format,
            'data' => $users,
            'format' => $format
        ];
    }

    /**
     * Exporter les wallets
     */
    private function exportWallets(array $filters, string $format): array
    {
        $wallets = $this->walletService->getWallets(array_merge($filters, ['limit' => 10000]));
        
        return [
            'filename' => 'wallets_export_' . date('Y-m-d_H-i-s') . '.' . $format,
            'data' => $wallets,
            'format' => $format
        ];
    }

    /**
     * Exporter les logs
     */
    private function exportLogs(array $filters, string $format): array
    {
        $startDate = Carbon::parse($filters['start_date'] ?? Carbon::now()->subDays(30));
        $endDate = Carbon::parse($filters['end_date'] ?? Carbon::now());

        $logs = BackofficeLog::with('adminUser')
            ->whereBetween('timestamp', [$startDate, $endDate])
            ->orderBy('timestamp', 'desc')
            ->limit(10000)
            ->get()
            ->map(function($log) {
                return [
                    'timestamp' => $log->timestamp->format('Y-m-d H:i:s'),
                    'admin_username' => $log->adminUser->username ?? 'Inconnu',
                    'role' => $log->role,
                    'action_type' => $log->action_type,
                    'target_type' => $log->target_type,
                    'target_id' => $log->target_id,
                    'payload' => json_encode($log->payload)
                ];
            });

        return [
            'filename' => 'backoffice_logs_' . date('Y-m-d_H-i-s') . '.' . $format,
            'data' => $logs,
            'format' => $format
        ];
    }
}
                