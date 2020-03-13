<?php
namespace Aacotroneo\Saml2;

use OneLogin\Saml2\Utils as OneLogin_Saml2_Utils;
use Illuminate\Support\ServiceProvider;

class Saml2ServiceProvider extends ServiceProvider
{

    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = false;

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        if(config('saml2_settings.useRoutes', false) == true ){
            include __DIR__ . '/../../routes.php';
        }

        $this->publishes([
            __DIR__.'/../../config/saml2_settings.php' => config_path('saml2_settings.php'),
            __DIR__.'/../../config/test_idp_settings.php' => config_path('saml2'.DIRECTORY_SEPARATOR.'test_idp_settings.php'),
        ]);

        if (config('saml2_settings.proxyVars', false)) {
            OneLogin_Saml2_Utils::setProxyVars(true);
        }
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton(Saml2Auth::class, function ($app) {
            $idpName = request()->route('idpName');
            if (empty($idpName)) {
                $idpName = 'company_'.isset($_COOKIE['saml_company_id']) ? $_COOKIE['saml_company_id'] : 0;
            }
            $auth = Saml2Auth::loadOneLoginAuthFromIpdConfig('company_'.$_COOKIE['saml_company_id']);
            $class = new Saml2Auth($auth);
        });
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return [Saml2Auth::class];
    }

}
