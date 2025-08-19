<? 
namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class BackofficeLog extends Model
{
    use HasFactory, HasUuids;

    protected $table = 'backoffice_logs';

    public $timestamps = false; // On utilise timestamp personnalisé

    protected $fillable = [
        'admin_id',
        'role',
        'action_type',
        'target_type',
        'target_id',
        'payload',
        'timestamp'
    ];

    protected $casts = [
        'payload' => 'array',
        'timestamp' => 'datetime'
    ];

    /**
     * Relation avec l'utilisateur admin
     */
    public function adminUser()
    {
        return $this->belongsTo(AdminUser::class, 'admin_id');
    }

    /**
     * Scope pour filtrer par type d'action
     */
    public function scopeByAction($query, string $actionType)
    {
        return $query->where('action_type', $actionType);
    }

    /**
     * Scope pour filtrer par type de cible
     */
    public function scopeByTargetType($query, string $targetType)
    {
        return $query->where('target_type', $targetType);
    }

    /**
     * Scope pour filtrer par période
     */
    public function scopeInPeriod($query, \DateTime $start, \DateTime $end)
    {
        return $query->whereBetween('timestamp', [$start, $end]);
    }

    /**
     * Enregistrer une action
     */
    public static function logAction(
        string $adminId,
        string $role,
        string $actionType,
        string $targetType,
        string $targetId,
        array $payload = []
    ): self {
        return self::create([
            'admin_id' => $adminId,
            'role' => $role,
            'action_type' => $actionType,
            'target_type' => $targetType,
            'target_id' => $targetId,
            'payload' => $payload,
            'timestamp' => now()
        ]);
    }

    /**
     * Obtenir les actions récentes
     */
    public static function getRecentActions(int $limit = 50): \Illuminate\Database\Eloquent\Collection
    {
        return self::with('adminUser')
            ->orderBy('timestamp', 'desc')
            ->limit($limit)
            ->get();
    }

    /**
     * Obtenir les statistiques d'actions par type
     */
    public static function getActionStats(\DateTime $start, \DateTime $end): array
    {
        return self::selectRaw('action_type, COUNT(*) as count')
            ->whereBetween('timestamp', [$start, $end])
            ->groupBy('action_type')
            ->pluck('count', 'action_type')
            ->toArray();
    }
}
