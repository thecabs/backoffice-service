<?php

namespace Database\Factories;

use App\Models\AdminUser;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

class AdminUserFactory extends Factory
{
    protected $model = AdminUser::class;

    public function definition()
    {
        return [
            'external_id' => Str::uuid(),
            'username' => $this->faker->userName,
            'role' => $this->faker->randomElement([
                'admin', 'directeur_agence', 'GFC', 'AGI', 'lecteur'
            ]),
            'agency_id' => $this->faker->optional()->regexify('AG[0-9]{3}'),
            'actif' => $this->faker->boolean(90) // 90% actifs
        ];
    }

    public function superadmin()
    {
        return $this->state(fn (array $attributes) => [
            'role' => 'superadmin',
            'agency_id' => null
        ]);
    }

    public function directeurAgence(string $agencyId = 'AG001')
    {
        return $this->state(fn (array $attributes) => [
            'role' => 'directeur_agence',
            'agency_id' => $agencyId
        ]);
    }

    public function inactive()
    {
        return $this->state(fn (array $attributes) => [
            'actif' => false
        ]);
    }
}