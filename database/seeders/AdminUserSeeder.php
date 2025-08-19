<?php
namespace Database\Seeders;

use App\Models\AdminUser;
use Illuminate\Database\Seeder;
use Illuminate\Support\Str;

class AdminUserSeeder extends Seeder
{
    public function run()
    {
        // Super admin de test
        AdminUser::create([
            'external_id' => Str::uuid(),
            'username' => 'superadmin',
            'role' => 'superadmin',
            'agency_id' => null,
            'actif' => true
        ]);

        // Admin général
        AdminUser::create([
            'external_id' => Str::uuid(),
            'username' => 'admin.general',
            'role' => 'admin',
            'agency_id' => null,
            'actif' => true
        ]);

        // Directeur d'agence
        AdminUser::create([
            'external_id' => Str::uuid(),
            'username' => 'directeur.yaounde',
            'role' => 'directeur_agence',
            'agency_id' => 'AG001',
            'actif' => true
        ]);

        // GFC
        AdminUser::create([
            'external_id' => Str::uuid(),
            'username' => 'gfc.central',
            'role' => 'GFC',
            'agency_id' => null,
            'actif' => true
        ]);

        // AGI
        AdminUser::create([
            'external_id' => Str::uuid(),
            'username' => 'agi.kyc',
            'role' => 'AGI',
            'agency_id' => null,
            'actif' => true
        ]);

        // Lecteur
        AdminUser::create([
            'external_id' => Str::uuid(),
            'username' => 'lecteur.audit',
            'role' => 'lecteur',
            'agency_id' => 'AG001',
            'actif' => true
        ]);
    }
}