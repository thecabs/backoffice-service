<?php

// database/migrations/2024_01_01_000001_create_admin_users_table.php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('admin_users', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->uuid('external_id')->unique()->comment('ID Keycloak');
            $table->string('username')->unique()->comment('preferred_username du JWT');
            $table->enum('role', [
                'superadmin',
                'admin', 
                'directeur_agence',
                'GFC',
                'AGI',
                'lecteur'
            ])->comment('Rôle back office');
            $table->string('agency_id')->nullable()->comment('ID agence de rattachement');
            $table->boolean('actif')->default(true)->comment('Utilisateur actif');
            $table->timestamps();

            // Index pour optimiser les requêtes
            $table->index(['role']);
            $table->index(['agency_id']);
            $table->index(['actif']);
            $table->index(['external_id', 'actif']);
        });
    }

    public function down()
    {
        Schema::dropIfExists('admin_users');
    }
};

// database/migrations/2024_01_01_000002_create_backoffice_logs_table.php

// database/seeders/AdminUserSeeder.php (optionnel)


// database/factories/AdminUserFactory.php (pour les tests)


// database/factories/BackofficeLogFactory.php
