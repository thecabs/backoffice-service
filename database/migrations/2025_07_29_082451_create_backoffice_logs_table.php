<?php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('backoffice_logs', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->uuid('admin_id')->comment('FK vers admin_users');
            $table->string('role')->comment('Rôle au moment de l\'action');
            $table->string('action_type')->comment('Type d\'action effectuée');
            $table->string('target_type')->comment('Type d\'objet ciblé (user, wallet, etc.)');
            $table->uuid('target_id')->comment('UUID de l\'objet ciblé');
            $table->json('payload')->nullable()->comment('Données de la requête');
            $table->timestamp('timestamp')->comment('Date/heure de l\'action');

            // Foreign key
            $table->foreign('admin_id')->references('id')->on('admin_users')->onDelete('cascade');

            // Index pour optimiser les requêtes
            $table->index(['admin_id']);
            $table->index(['action_type']);
            $table->index(['target_type']);
            $table->index(['target_id']);
            $table->index(['timestamp']);
            $table->index(['admin_id', 'timestamp']);
            $table->index(['action_type', 'timestamp']);
        });
    }

    public function down()
    {
        Schema::dropIfExists('backoffice_logs');
    }
};
