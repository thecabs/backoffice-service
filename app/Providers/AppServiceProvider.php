<?php

namespace App\Providers;

use App\Services\UserServiceClient;
use App\Services\WalletServiceClient;
use App\Services\TontineServiceClient;
use App\Services\UserCeilingServiceClient;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function register()
    {
        // Enregistrer les services clients
        $this->app->singleton(UserServiceClient::class, function ($app) {
            return new UserServiceClient();
        });
        
        $this->app->singleton(WalletServiceClient::class, function ($app) {
            return new WalletServiceClient();
        });
             
        $this->app->singleton(TontineServiceClient::class, function ($app) {
            return new TontineServiceClient();
        });
        
        $this->app->singleton(UserCeilingServiceClient::class, function ($app) {
            return new UserCeilingServiceClient();
        });
    }

    public function boot()
    {
        //
    }
}
