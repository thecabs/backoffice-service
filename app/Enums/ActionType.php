<?php

namespace App\Enums;

enum ActionType: string
{
    case SUSPEND_USER = 'suspend_user';
    case VALIDATE_USER = 'validate_user';
    case UPDATE_CEILING = 'update_ceiling';
    case CLOSE_WALLET = 'close_wallet';
    case SUSPEND_TONTINE = 'suspend_tontine';
    case CLOSE_TONTINE = 'close_tontine';
    case VIEW_DASHBOARD = 'view_dashboard';
    
    /**
     * Actions nécessitant un log obligatoire
     */
    public static function requiresLogging(): array
    {
        return [
            self::SUSPEND_USER->value,
            self::VALIDATE_USER->value,
            self::UPDATE_CEILING->value,
            self::CLOSE_WALLET->value,
            self::SUSPEND_TONTINE->value,
            self::CLOSE_TONTINE->value
        ];
    }
}