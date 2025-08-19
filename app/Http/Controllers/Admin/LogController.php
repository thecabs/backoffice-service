<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\BackofficeLog;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\StreamedResponse;

class LogController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth.keycloak');
    }

    /** Liste paginée + filtres */
    public function index(Request $request): JsonResponse
    {
        try {
            $q = BackofficeLog::query()->with('adminUser');

            if ($request->filled('admin_role')) {
                $q->where('role', $request->get('admin_role'));
            }

            if ($request->filled('admin_username')) {
                $username = $request->get('admin_username');
                $q->whereHas('adminUser', function ($qq) use ($username) {
                    // portable MySQL/Postgres
                    $qq->whereRaw('LOWER(username) LIKE ?', ['%' . strtolower($username) . '%']);
                });
            }

            if ($request->filled('from')) {
                $q->where('timestamp', '>=', $request->get('from'));
            }

            if ($request->filled('to')) {
                $q->where('timestamp', '<=', $request->get('to'));
            }

            // Scope directeur_agence → restreint aux logs de son agence
            $adminUser = $request->attributes->get('admin_user');
            if (($adminUser['role'] ?? null) === 'directeur_agence' && !empty($adminUser['agency_id'])) {
                $agencyId = $adminUser['agency_id'];
                $q->whereHas('adminUser', function ($qq) use ($agencyId) {
                    $qq->where('agency_id', $agencyId);
                });
            }

            $limit = (int) $request->get('limit', 25);
            $logs  = $q->orderBy('timestamp', 'desc')->paginate($limit);

            return response()->json([
                'success' => true,
                'data'    => $logs->items(),
                'meta'    => [
                    'total' => $logs->total(),
                    'per_page' => $logs->perPage(),
                    'current_page' => $logs->currentPage(),
                ],
            ]);
        } catch (\Throwable $e) {
            Log::error('LogController@index failed', ['error' => $e->getMessage()]);
            return response()->json(['success' => false, 'error' => 'Erreur lors de la récupération des logs'], 500);
        }
    }

    /** Statistiques agrégées */
    public function stats(Request $request): JsonResponse
    {
        try {
            $q = BackofficeLog::query();

            if ($request->filled('from')) {
                $q->where('timestamp', '>=', $request->get('from'));
            }
            if ($request->filled('to')) {
                $q->where('timestamp', '<=', $request->get('to'));
            }
            if ($request->filled('admin_role')) {
                $q->where('role', $request->get('admin_role'));
            }

            $adminUser = $request->attributes->get('admin_user');
            if (($adminUser['role'] ?? null) === 'directeur_agence' && !empty($adminUser['agency_id'])) {
                $agencyId = $adminUser['agency_id'];
                $q->whereHas('adminUser', function ($qq) use ($agencyId) {
                    $qq->where('agency_id', $agencyId);
                });
            }

            $byAction = (clone $q)
                ->selectRaw('action_type, COUNT(*) as count')
                ->groupBy('action_type')
                ->orderBy('count', 'desc')
                ->get();

            $byTarget = (clone $q)
                ->selectRaw('target_type, COUNT(*) as count')
                ->groupBy('target_type')
                ->orderBy('count', 'desc')
                ->get();

            return response()->json([
                'success' => true,
                'data' => [
                    'by_action_type' => $byAction,
                    'by_target_type' => $byTarget,
                ],
                'filters' => $request->only(['from', 'to', 'admin_role']),
            ]);
        } catch (\Throwable $e) {
            Log::error('LogController@stats failed', ['error' => $e->getMessage()]);
            return response()->json(['success' => false, 'error' => 'Erreur lors du calcul des stats'], 500);
        }
    }

    /** Export CSV (streamé) */
    public function export(Request $request): StreamedResponse|JsonResponse
    {
        try {
            $q = BackofficeLog::query()->with('adminUser');

            if ($request->filled('from')) {
                $q->where('timestamp', '>=', $request->get('from'));
            }
            if ($request->filled('to')) {
                $q->where('timestamp', '<=', $request->get('to'));
            }

            $adminUser = $request->attributes->get('admin_user');
            // Seuls superadmin/admin exportent
            if (!in_array($adminUser['role'] ?? '', ['superadmin', 'admin'], true)) {
                return response()->json(['success' => false, 'error' => 'Permission insuffisante'], 403);
            }

            $rows = $q->orderBy('timestamp', 'desc')->cursor()
                ->map(function ($r) {
                    return [
                        'timestamp'      => $r->timestamp ?? $r->created_at,
                        'admin_username' => optional($r->adminUser)->username,
                        'role'           => $r->role,
                        'action_type'    => $r->action_type,
                        'target_type'    => $r->target_type,
                        'target_id'      => $r->target_id,
                        'payload'        => is_array($r->payload) ? json_encode($r->payload, JSON_UNESCAPED_UNICODE) : (string)$r->payload,
                    ];
                });

            $headers = [
                'Content-Type'        => 'text/csv; charset=UTF-8',
                'Content-Disposition' => 'attachment; filename="backoffice_logs.csv"',
            ];

            $callback = function () use ($rows) {
                $out = fopen('php://output', 'w');
                // BOM UTF-8 (Excel)
                fwrite($out, chr(0xEF) . chr(0xBB) . chr(0xBF));
                fputcsv($out, ['timestamp', 'admin_username', 'role', 'action_type', 'target_type', 'target_id', 'payload']);
                foreach ($rows as $r) fputcsv($out, array_values($r));
                fclose($out);
            };

            return new StreamedResponse($callback, 200, $headers);
        } catch (\Throwable $e) {
            Log::error('LogController@export failed', ['error' => $e->getMessage()]);
            return response()->json(['success' => false, 'error' => 'Erreur lors de l\'export'], 500);
        }
    }
}
