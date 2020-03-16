<?php

namespace Aacotroneo\Saml2\Http\Controllers;

use Aacotroneo\Saml2\Events\Saml2LoginEvent;
use Aacotroneo\Saml2\Saml2Auth;
use Illuminate\Routing\Controller;
use Illuminate\Http\Request;

class Saml2Controller extends Controller
{
    /**
     * Generate local sp metadata.
     *
     * @return \Illuminate\Http\Response
     */
    public function metadata()
    {
        $metadata = getSaml2Auth()->getMetadata();

        return response($metadata, 200, ['Content-Type' => 'text/xml']);
    }

    /**
     * Process an incoming saml2 assertion request.
     * Fires 'Saml2LoginEvent' event if a valid user is found.
     *
     * @param $idpName
     * @return \Illuminate\Http\Response
     */
    public function acs($idpName = null)
    {
        $saml2Auth = getSaml2Auth();
        $errors = $saml2Auth->acs();
        
        if ($idpName === null) {
            $idpName = 'company_'.@$_COOKIE['saml_company_id'];
        }

        if (!empty($errors)) {
            logger()->error('Saml2 error_detail', ['error' => $saml2Auth->getLastErrorReason()]);
            session()->flash('saml2_error_detail', [$saml2Auth->getLastErrorReason()]);

            logger()->error('Saml2 error', $errors);
            session()->flash('saml2_error', $errors);
            return redirect(config('saml2_settings.errorRoute'));
        }
        $user = $saml2Auth->getSaml2User();

        event(new Saml2LoginEvent($idpName, $user, $saml2Auth));

        $redirectUrl = $user->getIntendedUrl();

        if ($redirectUrl !== null) {
            return redirect($redirectUrl);
        } else {

            return redirect(config('saml2_settings.loginRoute'));
        }
    }

    /**
     * Process an incoming saml2 logout request.
     * Fires 'Saml2LogoutEvent' event if its valid.
     * This means the user logged out of the SSO infrastructure, you 'should' log them out locally too.
     *
     * @param $idpName
     * @return \Illuminate\Http\Response
     */
    public function sls($idpName = null )
    {
        if ($idpName === null) {
            $idpName = 'company_'.@$_COOKIE['saml_company_id'];
        }
        $saml2Auth = getSaml2Auth();
        $errors = $saml2Auth->sls($idpName, config('saml2_settings.retrieveParametersFromServer'));
        if (!empty($errors)) {
            logger()->error('Saml2 error', $errors);
            session()->flash('saml2_error', $errors);
            throw new \Exception("Could not log out");
        }

        return redirect(config('saml2_settings.logoutRoute')); //may be set a configurable default
    }

    /**
     * Initiate a logout request across all the SSO infrastructure.
     *
     * @param Request $request
     */
    public function logout(Request $request)
    {
        $saml2Auth = getSaml2Auth();
        $returnTo = $request->query('returnTo');
        $sessionIndex = $request->query('sessionIndex');
        $nameId = $request->query('nameId');
        $saml2Auth->logout($returnTo, $nameId, $sessionIndex); //will actually end up in the sls endpoint
        //does not return
    }

    /**
     * Initiate a login request.
     *
     */
    public function login()
    {
        $saml2Auth = getSaml2Auth();
        $saml2Auth->login(config('saml2_settings.loginRoute'));
    }
}
