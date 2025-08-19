<?php

use App\Http\Controllers\Admin\UserAdminController;
use App\Http\Controllers\Admin\WalletAdminController;
use App\Http\Controllers\Admin\TontineAdminController;
use App\Http\Controllers\Admin\CeilingAdminController;
use App\Http\Controllers\Admin\DashboardController;
use App\Http\Controllers\Admin\LogController;
use Illuminate\Support\Facades\Route;

Route::middleware(['auth.keycloak'])->prefix('admin')->group(function () {

    // (Option) Dashboard
    // Route::get('/dashboard', [DashboardController::class, 'index']);

    /**
     * USERS (PII) — ZT: contexte + tag PII + PDP
     */
    Route::prefix('users')
        ->middleware(['context.enricher', 'resource.tag:PII', 'pdp'])
        ->group(function () {
            Route::get('/', [UserAdminController::class, 'index'])
                ->middleware('check.role:superadmin,admin,GFC,AGI,directeur_agence');

            Route::get('/{userId}', [UserAdminController::class, 'show'])
                ->whereUuid('userId')
                ->middleware('check.role:superadmin,admin,GFC,AGI,directeur_agence');

            Route::post('/{userId}/validate', [UserAdminController::class, 'validateUser'])
                ->whereUuid('userId')
                ->middleware(['check.role:superadmin,admin,GFC', 'throttle:api', 'idempotency:600']);

            Route::post('/{userId}/suspend', [UserAdminController::class, 'suspend'])
                ->whereUuid('userId')
                ->middleware(['check.role:superadmin,admin', 'throttle:api', 'idempotency:600']);

            Route::post('/{userId}/reactivate', [UserAdminController::class, 'reactivate'])
                ->whereUuid('userId')
                ->middleware(['check.role:superadmin,admin', 'throttle:api', 'idempotency:600']);

            Route::put('/{userId}/profile', [UserAdminController::class, 'updateProfile'])
                ->whereUuid('userId')
                ->middleware(['check.role:superadmin,admin,AGI', 'throttle:api', 'idempotency:600']);

            Route::get('/{userId}/history', [UserAdminController::class, 'actionHistory'])
                ->whereUuid('userId')
                ->middleware('check.role:superadmin,admin');
        });

    /**
     * WALLETS (FINANCIAL) — ZT: contexte + tag FINANCIAL + PDP
     */
    Route::prefix('wallets')
        ->middleware(['context.enricher', 'resource.tag:FINANCIAL', 'pdp'])
        ->group(function () {
            Route::get('/', [WalletAdminController::class, 'index'])
                ->middleware('check.role:superadmin,admin,GFC,AGI,directeur_agence');

            Route::get('/{walletId}', [WalletAdminController::class, 'show'])
                ->whereUuid('walletId')
                ->middleware('check.role:superadmin,admin,GFC,AGI,directeur_agence');

            Route::post('/{walletId}/close', [WalletAdminController::class, 'close'])
                ->whereUuid('walletId')
                ->middleware(['check.role:superadmin,admin', 'throttle:api', 'idempotency:600']);

            Route::post('/{walletId}/freeze', [WalletAdminController::class, 'freeze'])
                ->whereUuid('walletId')
                ->middleware(['check.role:superadmin,admin', 'throttle:api', 'idempotency:600']);

            Route::post('/{walletId}/unfreeze', [WalletAdminController::class, 'unfreeze'])
                ->whereUuid('walletId')
                ->middleware(['check.role:superadmin,admin', 'throttle:api', 'idempotency:600']);

            Route::get('/{walletId}/transactions', [WalletAdminController::class, 'transactions'])
                ->whereUuid('walletId')
                ->middleware('check.role:superadmin,admin,GFC,AGI,directeur_agence');
        });

    /**
     * CEILINGS (FINANCIAL) — ZT: contexte + tag FINANCIAL + PDP
     */
    Route::prefix('ceilings')
        ->middleware(['context.enricher', 'resource.tag:FINANCIAL', 'pdp'])
        ->group(function () {
            Route::get('/', [CeilingAdminController::class, 'index'])
                ->middleware('check.role:superadmin,admin,GFC');

            Route::get('/{userId}', [CeilingAdminController::class, 'show'])
                ->whereUuid('userId')
                ->middleware('check.role:superadmin,admin,GFC');

            Route::put('/{userId}', [CeilingAdminController::class, 'update'])
                ->whereUuid('userId')
                ->middleware(['check.role:superadmin,admin', 'throttle:api', 'idempotency:600']);

            Route::get('/{userId}/history', [CeilingAdminController::class, 'history'])
                ->whereUuid('userId')
                ->middleware('check.role:superadmin,admin,GFC');
        });

    /**
     * LOGS / AUDIT — lecture par rôles élevés
     */
    Route::prefix('logs')->group(function () {
        Route::get('/', [LogController::class, 'index'])
            ->middleware('check.role:superadmin,admin,GFC');

        Route::get('/stats', [LogController::class, 'stats'])
            ->middleware('check.role:superadmin,admin');

        Route::get('/export', [LogController::class, 'export'])
            ->middleware(['check.role:superadmin,admin', 'throttle:api', 'idempotency:600']);
    });
});

// Healthcheck
Route::get('/health', function () {
    return response()->json([
        'service'   => 'backoffice-service',
        'status'    => 'healthy',
        'timestamp' => now()->toIso8601String(),
    ]);
});
