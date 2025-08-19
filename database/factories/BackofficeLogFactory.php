<?php
namespace Database\Factories;

use App\Models\AdminUser;
use App\Models\BackofficeLog;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

class BackofficeLogFactory extends Factory
{
    protected $model = BackofficeLog::class;

    public function definition()
    {
        $actionTypes = [
            'suspend_user', 'validate_user', 'update_ceiling',
            'close_wallet', 'suspend_tontine', 'close_tontine'
        ];
        
        $targetTypes = ['user', 'wallet', 'tontine', 'ceiling'];

        return [
            'admin_id' => AdminUser::factory(),
            'role' => $this->faker->randomElement([
                'admin', 'directeur_agence', 'GFC', 'AGI'
            ]),
            'action_type' => $this->faker->randomElement($actionTypes),
            'target_type' => $this->faker->randomElement($targetTypes),
            'target_id' => Str::uuid(),
            'payload' => [
                'reason' => $this->faker->sentence,
                'previous_status' => $this->faker->word,
                'new_status' => $this->faker->word
            ],
            'timestamp' => $this->faker->dateTimeBetween('-30 days', 'now')
        ];
    }
}