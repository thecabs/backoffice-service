<?php 

namespace App\Enums;

enum AdminRole: string
{
    case SUPERADMIN = 'superadmin';
    case ADMIN = 'admin';
    case DIRECTEUR_AGENCE = 'directeur_agence';
    case GFC = 'GFC';
    case AGI = 'AGI';
    case LECTEUR = 'lecteur';

    /**
     * Obtenir tous les rôles
     */
    public static function all(): array
    {
        return array_column(self::cases(), 'value');
    }

    /**
     * Rôles avec permissions élevées
     */
    public static function highLevel(): array
    {
        return [
            self::SUPERADMIN->value,
            self::ADMIN->value
        ];
    }

    /**
     * Rôles avec accès restreint par agence
     */
    public static function agencyRestricted(): array
    {
        return [
            self::DIRECTEUR_AGENCE->value
        ];
    }
}