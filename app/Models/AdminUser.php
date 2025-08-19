<?php

// app/Models/AdminUser.php
namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class AdminUser extends Model
{
    use HasFactory, HasUuids;

    protected $table = 'admin_users';

    protected $fillable = [
        'external_id',
        'username',
        'role',
        'agency_id',
        'actif'
    ];

    protected $casts = [
        'external_id' => 'string',
        'actif' => 'boolean',
        'created_at' => 'datetime',
        'updated_at' => 'datetime'
    ];

    /**
     * Relation avec les logs
     */
    public function logs()
    {
        return $this->hasMany(BackofficeLog::class, 'admin_id');
    }

    /**
     * Scope pour filtrer les utilisateurs actifs
     */
    public function scopeActive($query)
    {
        return $query->where('actif', true);
    }

    /**
     * Scope pour filtrer par rôle
     */
    public function scopeByRole($query, string $role)
    {
        return $query->where('role', $role);
    }

    /**
     * Scope pour filtrer par agence
     */
    public function scopeByAgency($query, string $agencyId)
    {
        return $query->where('agency_id', $agencyId);
    }

    /**
     * Vérifier si l'utilisateur a un rôle spécifique
     */
    public function hasRole(string $role): bool
    {
        return $this->role === $role;
    }

    /**
     * Vérifier si l'utilisateur a un des rôles donnés
     */
    public function hasAnyRole(array $roles): bool
    {
        return in_array($this->role, $roles);
    }

    /**
     * Obtenir ou créer un utilisateur admin depuis le JWT
     */
    public static function findOrCreateFromJWT(array $userData): self
    {
        return self::updateOrCreate(
            ['external_id' => $userData['external_id']],
            [
                'username' => $userData['username'],
                'role' => $userData['role'],
                'agency_id' => $userData['agency_id'],
                'actif' => true
            ]
        );
    }
}




