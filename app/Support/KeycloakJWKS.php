<?php
// app/Support/KeycloakJWKS.php

namespace App\Support;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class KeycloakJWKS
{
    public static function getPemByKid(string $jwksUrl, string $kid): ?string
    {
        try {
            $jwks = Cache::remember("kc:jwks:" . md5($jwksUrl), 900, function () use ($jwksUrl) {
                $res = Http::timeout(5)->get($jwksUrl);
                if (!$res->ok()) return null;
                return $res->json();
            });

            if (!$jwks || empty($jwks['keys'])) {
                Log::warning('KeycloakJWKS: JWKS vide/indisponible');
                return null;
            }

            foreach ($jwks['keys'] as $jwk) {
                if (($jwk['kid'] ?? '') !== $kid) continue;

                if (!empty($jwk['x5c'][0])) {
                    $cert = "-----BEGIN CERTIFICATE-----\n"
                        . chunk_split(trim($jwk['x5c'][0]), 64, "\n")
                        . "-----END CERTIFICATE-----";
                    return $cert;
                }

                if (($jwk['kty'] ?? '') === 'RSA' && !empty($jwk['n']) && !empty($jwk['e'])) {
                    return self::rsaJwkToPem($jwk['n'], $jwk['e']);
                }
            }

            Log::warning('KeycloakJWKS: kid non trouvé', ['kid' => $kid]);
            return null;
        } catch (\Throwable $e) {
            Log::error('KeycloakJWKS@getPemByKid error', ['error' => $e->getMessage()]);
            return null;
        }
    }

    private static function b64u(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) $data .= str_repeat('=', 4 - $remainder);
        return base64_decode(strtr($data, '-_', '+/'));
    }

    private static function rsaJwkToPem(string $n, string $e): ?string
    {
        $mod = self::b64u($n);
        $exp = self::b64u($e);

        $rsaPub = self::asn1Sequence(
            self::asn1Integer($mod) . self::asn1Integer($exp)
        );

        $algId = self::asn1Sequence(
            "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01" . "\x05\x00"
        );

        $spki = self::asn1Sequence(
            $algId . self::asn1BitString($rsaPub)
        );

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----";
    }

    private static function asn1Length(int $len): string
    {
        if ($len < 128) return chr($len);
        $bin = ltrim(pack('N', $len), "\x00");
        return chr(0x80 | strlen($bin)) . $bin;
    }

    private static function asn1Integer(string $x): string
    {
        if (strlen($x) && (ord($x[0]) & 0x80)) $x = "\x00" . $x;
        return "\x02" . self::asn1Length(strlen($x)) . $x;
    }

    private static function asn1Sequence(string $der): string
    {
        return "\x30" . self::asn1Length(strlen($der)) . $der;
    }

    private static function asn1BitString(string $der): string
    {
        return "\x03" . self::asn1Length(strlen($der) + 1) . "\x00" . $der;
    }
}
