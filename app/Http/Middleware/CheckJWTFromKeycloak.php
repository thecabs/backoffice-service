<?php

namespace App\Http\Middleware;

use App\Support\KeycloakJWKS;
use Closure;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class CheckJWTFromKeycloak
{
    /**
     * Mapping rôles token -> rôle canonique BackOffice (pas de régression)
     */
    private const ROLE_ALIASES = [
        // existant
        'realm_admin'           => 'superadmin',
        'backoffice_superadmin' => 'superadmin',
        'bo_superadmin'         => 'superadmin',

        'realm_manager'         => 'admin',
        'backoffice_admin'      => 'admin',
        'bo_admin'              => 'admin',

        // ajouts realm 'sara'
        'admin'                 => 'admin',
        'gfc'                   => 'GFC',
        'directeur_agence'      => 'directeur_agence',
        'agent_kyc'             => 'AGI',
    ];

    public function handle(Request $request, Closure $next)
    {
        try {
            $token = $this->extractBearer($request->header('Authorization', ''));
            if (!$token) {
                return response()->json(['error' => 'Missing bearer token'], 401);
            }

            // -- 1) Clé de signature (JWKS par kid, sinon fallback .env)
            $kid     = $this->kid($token);
            $pem     = null;
            $realm   = rtrim((string) config('services.keycloak.realm_url', ''), '/');
            $jwksUrl = (string) (config('services.keycloak.jwks_url') ?: ($realm ? $realm . '/protocol/openid-connect/certs' : ''));

            if ($kid && $jwksUrl) {
                $pem = KeycloakJWKS::getPemByKid($jwksUrl, $kid);
            }

            if (!$pem) {
                $rawKey = trim((string) config('services.keycloak.public_key', ''));
                if ($rawKey === '') {
                    Log::error('keycloak.jwt.no_key_material', ['jwks' => (bool)$jwksUrl]);
                    return response()->json(['error' => 'Invalid token key material'], 401);
                }
                $pem = "-----BEGIN PUBLIC KEY-----\n" . wordwrap($rawKey, 64, "\n", true) . "\n-----END PUBLIC KEY-----";
            }

            // -- 2) Décodage & vérifs de base
            $decoded = JWT::decode($token, new Key($pem, 'RS256'));
            $claims  = $this->toArray($decoded);

            $now       = time();
            $expectedIss = rtrim((string) config('services.keycloak.realm_url', ''), '/');
            if ($expectedIss) {
                $iss = (string) ($claims['iss'] ?? '');
                if ($iss === '' || !str_starts_with($iss, $expectedIss)) {
                    return response()->json(['error' => 'Invalid issuer'], 401);
                }
            }
            if (isset($claims['exp']) && $now >= (int) $claims['exp']) {
                return response()->json(['error' => 'Token expired'], 401);
            }
            if (isset($claims['nbf']) && $now < (int) $claims['nbf']) {
                return response()->json(['error' => 'Token not yet valid'], 401);
            }

            // -- 3) (option) anti-replay via jti (activable)
            if ((bool) config('services.keycloak.anti_replay', false)) {
                $jti = (string) ($claims['jti'] ?? '');
                if ($jti !== '') {
                    $ttl = max(60, (int) ($claims['exp'] ?? ($now + 300)) - $now);
                    $cacheKey = 'jwt:jti:' . sha1($jti);
                    // cache()->add = set if not exists ; false si déjà présent
                    if (!cache()->add($cacheKey, 1, $ttl)) {
                        Log::warning('keycloak.jwt.replay_detected', ['jti' => $jti]);
                        return response()->json(['error' => 'Token replay detected'], 401);
                    }
                }
            }

            // -- 4) Audience stricte (activable)
            $this->assertAudience($claims);

            // -- 5) Rôle BO canonique
            $tokenRoles = $this->extractRoles($claims);
            $role       = $this->mapBackofficeRole($tokenRoles);
            if (!$role) {
                Log::warning('bo.role.denied', [
                    'token_roles' => $tokenRoles,
                    'aliases'     => array_keys(self::ROLE_ALIASES),
                    'env_allowed' => $this->envAllowedRoles(),
                ]);
                return response()->json(['error' => 'Rôle non autorisé pour le back office'], 403);
            }

            // -- 6) MFA pour rôles sensibles (amr/acr + max_age)
            if (!$this->mfaSatisfied($role, $claims, $now)) {
                return response()->json(['error' => 'MFA required for privileged role'], 403);
            }

            // -- 7) Contexte exposé aux contrôleurs
            $adminUser = [
                'external_id' => (string) ($claims['sub'] ?? ''),
                'username'    => (string) ($claims['preferred_username'] ?? ''),
                'role'        => $role,
                'agency_id'   => $claims['agency_id'] ?? null,
                'email'       => $claims['email'] ?? null,
                'name'        => $claims['name'] ?? ($claims['preferred_username'] ?? null),
            ];
            $request->attributes->set('admin_user', $adminUser);
            $request->attributes->set('external_id', (string) ($claims['sub'] ?? ''));
            $request->attributes->set('token_data', $claims);
            $request->attributes->set('token_roles', $tokenRoles);

            Log::info('bo.auth.ok', [
                'user'     => $adminUser['username'],
                'role'     => $adminUser['role'],
                'agency'   => $adminUser['agency_id'],
                'endpoint' => $request->path(),
            ]);

            return $next($request);
        } catch (\Throwable $e) {
            Log::error('bo.auth.fail', ['msg' => $e->getMessage()]);
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

    // ===== Helpers ===========================================================

    private function extractBearer(string $h): ?string
    {
        return preg_match('/^Bearer\s+(.+)$/i', trim($h), $m) ? trim($m[1]) : null;
    }

    private function kid(string $jwt): ?string
    {
        $p = explode('.', $jwt);
        if (count($p) < 2) return null;
        $hdr = json_decode($this->b64u($p[0]), true);
        return is_array($hdr) ? ($hdr['kid'] ?? null) : null;
    }

    private function b64u(string $s): string
    {
        $rem = strlen($s) % 4;
        if ($rem) $s .= str_repeat('=', 4 - $rem);
        return (string) base64_decode(strtr($s, '-_', '+/'));
    }

    private function toArray(object|array $obj): array
    {
        return json_decode(json_encode($obj, JSON_UNESCAPED_UNICODE), true) ?: [];
    }

    private function assertAudience(array $claims): void
    {
        $strictAud   = (bool)  config('services.keycloak.strict_aud', false);
        if (!$strictAud) return;

        $clientId    = (string) config('services.keycloak.client_id', 'backoffice-client');
        $acceptedCSV = (string) config('services.keycloak.accepted_audiences', '');
        $acceptedArr = array_values(array_filter(array_map('trim', explode(',', $acceptedCSV))));

        $aud = $claims['aud'] ?? null;
        $azp = (string) ($claims['azp'] ?? '');
        $res = $claims['resource_access'] ?? [];

        $audList = is_array($aud) ? $aud : ($aud ? [$aud] : []);

        $audOk =
            in_array($clientId, $audList, true) ||
            ($azp !== '' && $azp === $clientId) ||
            (is_array($res) && array_key_exists($clientId, $res));

        if (!$audOk && !empty($acceptedArr)) {
            $audOk = count(array_intersect($audList, $acceptedArr)) > 0
                  || ($azp !== '' && in_array($azp, $acceptedArr, true))
                  || (is_array($res) && count(array_intersect(array_keys($res), $acceptedArr)) > 0);
        }

        if (!$audOk) {
            Log::warning('keycloak.jwt.invalid_audience', [
                'expected' => $clientId,
                'aud'      => $audList,
                'azp'      => $azp,
                'res_keys' => is_array($res) ? array_keys($res) : [],
            ]);
            throw new \RuntimeException('Invalid audience');
        }
    }

    private function extractRoles(array $claims): array
    {
        $roles = [];
        if (!empty($claims['realm_access']['roles']) && is_array($claims['realm_access']['roles'])) {
            $roles = array_merge($roles, $claims['realm_access']['roles']);
        }
        if (!empty($claims['resource_access']) && is_array($claims['resource_access'])) {
            foreach ($claims['resource_access'] as $acc) {
                if (!empty($acc['roles']) && is_array($acc['roles'])) {
                    $roles = array_merge($roles, $acc['roles']);
                }
            }
        }
        return array_values(array_unique(array_map('strtolower', $roles)));
    }

    private function mapBackofficeRole(array $tokenRoles): ?string
    {
        $aliases = [];
        foreach (self::ROLE_ALIASES as $k => $v) {
            $aliases[strtolower($k)] = $v;
        }

        foreach ($tokenRoles as $r) {
            if (isset($aliases[$r])) return $aliases[$r];
        }

        // Option .env : rôle autorisé brut → mappe "admin" par défaut (pas de régression)
        $envAllowed = $this->envAllowedRoles();
        if (!empty($envAllowed)) {
            foreach ($tokenRoles as $r) {
                if (in_array($r, $envAllowed, true)) {
                    return 'admin';
                }
            }
        }
        return null;
    }

    private function envAllowedRoles(): array
    {
        $csv = (string) config('services.keycloak.allowed_role_names', env('KEYCLOAK_ALLOWED_ROLE_NAMES', ''));
        return array_values(array_filter(array_map('trim', array_map('strtolower', explode(',', $csv)))));
    }

    private function mfaSatisfied(string $role, array $claims, int $now): bool
    {
        $csvRequired = (string) config('services.keycloak.mfa_required_roles', 'superadmin,admin,GFC,AGI');
        $reqRoles    = array_values(array_filter(array_map('trim', explode(',', strtolower($csvRequired)))));
        if (!in_array(strtolower($role), $reqRoles, true)) {
            return true; // MFA non requis pour ce rôle
        }

        $amr      = array_map('strtolower', (array) ($claims['amr'] ?? []));
        $acr      = strtolower((string) ($claims['acr'] ?? ''));
        $authTime = isset($claims['auth_time']) ? (int) $claims['auth_time'] : null;
        $maxAge   = (int) config('services.keycloak.mfa_max_age', 900);

        $okVector = !empty(array_intersect($amr, ['mfa','otp','totp','webauthn']))
                 || in_array($acr, ['mfa','aal2','2fa','urn:mace:incommon:iap:silver'], true);

        if (!$okVector) return false;

        if ($authTime !== null && $maxAge > 0) {
            if (($now - $authTime) > $maxAge) return false;
        }
        return true;
    }

    // ===== Utils publics (inchangés) =========================================

    public static function getRolePermissions(string $role): array
    {
        return match ($role) {
            'superadmin' => [
                'users' => ['read','write','delete','validate','suspend'],
                'wallets' => ['read','write','close'],
                'tontines' => ['read','write','suspend','close'],
                'ceilings' => ['read','write'],
                'admin_users' => ['read','write','delete'],
                'scope' => 'global',
            ],
            'admin' => [
                'users' => ['read','write','validate','suspend'],
                'wallets' => ['read','write','close'],
                'tontines' => ['read','write','suspend'],
                'ceilings' => ['read','write'],
                'admin_users' => ['read'],
                'scope' => 'global',
            ],
            'GFC' => [
                'users' => ['read','validate'],
                'wallets' => ['read','write'],
                'tontines' => ['read'],
                'ceilings' => ['read'],
                'admin_users' => ['read'],
                'scope' => 'banking_accounts_only',
            ],
            'AGI' => [
                'users' => ['read','validate'],
                'wallets' => ['read','write'],
                'tontines' => ['read'],
                'ceilings' => ['read'],
                'admin_users' => ['read'],
                'scope' => 'agency_only',
            ],
            'directeur_agence' => [
                'users' => ['read'],
                'wallets' => ['read'],
                'tontines' => ['read'],
                'ceilings' => ['read'],
                'scope' => 'agency_only',
            ],
            default => [
                'users' => ['read'],
                'wallets' => ['read'],
                'tontines' => ['read'],
                'ceilings' => ['read'],
                'scope' => 'depends_on_assignment',
            ],
        };
    }

    public static function hasPermission(Request $request, string $module, string $action): bool
    {
        $adminUser = $request->attributes->get('admin_user');
        if (!$adminUser) return false;
        $perms = self::getRolePermissions($adminUser['role']);
        return in_array($action, (array) ($perms[$module] ?? []), true);
    }

    public static function applyScopeFilter(Request $request, array $queryParams = []): array
    {
        $adminUser = $request->attributes->get('admin_user');
        if (!$adminUser) return $queryParams;

        $permissions = self::getRolePermissions($adminUser['role']);
        $scope = $permissions['scope'] ?? 'global';

        switch ($scope) {
            case 'agency_only':
                if (!empty($adminUser['agency_id'])) {
                    $queryParams['agency_id'] = $adminUser['agency_id'];
                    $queryParams['type']      = 'bancaire';
                }
                break;
            case 'banking_accounts_only':
                $queryParams['type'] = 'bancaire';
                break;
            case 'global':
            case 'depends_on_assignment':
            default:
                // pas de filtre
                break;
        }
        return $queryParams;
    }
}
