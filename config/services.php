<?php

$realmUrl = rtrim((string) env('KEYCLOAK_REALM_URL', ''), '/');
$jwksUrl  = (string) env('KEYCLOAK_JWKS_URL', $realmUrl ? $realmUrl . '/protocol/openid-connect/certs' : '');
$tokenUrl = (string) env('KEYCLOAK_TOKEN_URL', $realmUrl ? $realmUrl . '/protocol/openid-connect/token' : '');

return [

    // ===== Services Laravel par défaut =====
    'mailgun' => [
        'domain'   => env('MAILGUN_DOMAIN'),
        'secret'   => env('MAILGUN_SECRET'),
        'endpoint' => env('MAILGUN_ENDPOINT', 'api.mailgun.net'),
        'scheme'   => 'https',
    ],

    'postmark' => [
        'token' => env('POSTMARK_TOKEN'),
    ],

    'ses' => [
        'key'    => env('AWS_ACCESS_KEY_ID'),
        'secret' => env('AWS_SECRET_ACCESS_KEY'),
        'region' => env('AWS_DEFAULT_REGION', 'us-east-1'),
    ],

    // ===== Microservices (clients HTTP du backoffice) =====
    'user_service' => [
        'url'     => env('USER_SERVICE_URL', 'http://10.91.34.206:8003'),
        'timeout' => (int) env('USER_SERVICE_TIMEOUT', 30),
    ],

    'wallet_service' => [
        // ⚠ adapte à l’IP/port accessibles depuis le backoffice
        'url'               => env('WALLET_SERVICE_URL', 'http://192.168.1.225:8003'),
        'timeout'           => (int) env('WALLET_SERVICE_TIMEOUT', 30),
        'default_currency'  => strtoupper((string) env('WALLET_DEFAULT_CURRENCY', 'XAF')),
    ],

    'tontine_service' => [
        'url'     => env('TONTINE_SERVICE_URL', 'http://tontine-service:9005'),
        'timeout' => (int) env('TONTINE_SERVICE_TIMEOUT', 30),
    ],

    'userceiling_service' => [
        'url'     => env('USERCEILING_SERVICE_URL', 'http://192.168.1.225:8001'),
        'timeout' => (int) env('USERCEILING_SERVICE_TIMEOUT', 30),
    ],

    // ===== Keycloak (BO) =====
    'keycloak' => [
        'realm_url'  => $realmUrl,
        'client_id'  => env('KEYCLOAK_CLIENT_ID', 'backoffice-client'),

        // Vérification JWT
        'public_key' => env('KEYCLOAK_PUBLIC_KEY'), // base64 sans header/footer
        'jwks_url'   => $jwksUrl,

        // Audience stricte (optionnelle)
        'strict_aud'         => (bool) env('KEYCLOAK_STRICT_AUD', false),
        'accepted_audiences' => env('KEYCLOAK_ACCEPTED_AUDIENCES', ''),

        // MFA (périmètre BO)
        'mfa_required_roles' => env('KEYCLOAK_MFA_REQUIRED_ROLES', 'admin,GFC,AGI,superadmin'),
        'mfa_max_age'        => (int) env('KEYCLOAK_MFA_MAX_AGE', 900),

        // Mapping de rôles supplémentaires autorisés par ENV (→ admin par défaut)
        'allowed_role_names' => env('KEYCLOAK_ALLOWED_ROLE_NAMES', ''),

        // S2S (si le BO appelle les Admin/API ou d’autres MS en client_credentials)
        'token_url'         => $tokenUrl,
        's2s_client_id'     => env('KEYCLOAK_S2S_CLIENT_ID', 'backoffice-service'),
        's2s_client_secret' => env('KEYCLOAK_S2S_CLIENT_SECRET', null),
    ],
];
