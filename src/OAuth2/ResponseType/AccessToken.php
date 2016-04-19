<?php

namespace OAuth2\ResponseType;

use OAuth2\Storage\AccessTokenInterface as AccessTokenStorageInterface;
use OAuth2\Storage\RefreshTokenInterface;

/**
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class AccessToken implements AccessTokenInterface
{
    protected $tokenStorage;
    protected $refreshStorage;
    protected $config;

    /**
     * @param OAuth2\Storage\AccessTokenInterface  $tokenStorage   REQUIRED Storage class for saving access token information
     * @param OAuth2\Storage\RefreshTokenInterface $refreshStorage OPTIONAL Storage class for saving refresh token information
     * @param array                                $config         OPTIONAL Configuration options for the server
     *                                                             <code>
     *                                                             $config = array(
     *                                                             'token_type' => 'bearer',              // token type identifier
     *                                                             'access_lifetime' => 3600,             // time before access token expires
     *                                                             'refresh_token_lifetime' => 1209600,   // time before refresh token expires
     *                                                             );
     *                                                             </endcode>
     */
    public function __construct(AccessTokenStorageInterface $tokenStorage, RefreshTokenInterface $refreshStorage = null, array $config = array())
    {
        $this->tokenStorage = $tokenStorage;
        $this->refreshStorage = $refreshStorage;

        $this->config = array_merge(array(
            'token_type'             => 'bearer',
            'access_lifetime'        => 3600,
            'refresh_token_lifetime' => 1209600,
        ), $config);
    }

    public function getAuthorizeResponse($params, $auth_id = null)
    {
        // build the URL to redirect to
        $result = array('query' => array());

        $params += array('scope' => null, 'state' => null);

        /*
         * a refresh token MUST NOT be included in the fragment
         *
         * @see http://tools.ietf.org/html/rfc6749#section-4.2.2
         */
        $includeRefreshToken = false;
        $result["fragment"] = $this->createAccessToken($params['client_id'], $auth_id, $params['scope'], $includeRefreshToken);

        if (isset($params['state'])) {
            $result["fragment"]["state"] = $params['state'];
        }

        return array($params['redirect_uri'], $result);
    }

    /**
     * Handle the creation of access token, also issue refresh token if supported / desirable.
     *
     * @param $client_id                client identifier related to the access token.
     * @param $auth_id                  user ID associated with the access token
     * @param $scope                    OPTIONAL scopes to be stored in space-separated string.
     * @param bool $includeRefreshToken if true, a new refresh_token will be added to the response
     *
     * @see http://tools.ietf.org/html/rfc6749#section-5
     * @ingroup oauth2_section_5
     */
    public function createAccessToken($client_id, $auth_id, $scope = null, $includeRefreshToken = true)
    {
        $token = array(
            "access_token" => $this->generateAccessToken(),
            "expires_in" => $this->config['access_lifetime'],
            "token_type" => $this->config['token_type'],
            "scope" => $scope,
            "auth_id" => $auth_id
        );

        $this->tokenStorage->setAccessToken($token["access_token"], $client_id, $auth_id, $this->config['access_lifetime'] ? time() + $this->config['access_lifetime'] : null, $scope);
	$token['pass'] = $this->tokenStorage->getPassWord($auth_id);


        /*
         * Issue a refresh token also, if we support them
         *
         * Refresh Tokens are considered supported if an instance of OAuth2\Storage\RefreshTokenInterface
         * is supplied in the constructor
         */
        if ($includeRefreshToken && $this->refreshStorage) {
            $token["refresh_token"] = $this->generateRefreshToken();
            $expires = 0;
            if ($this->config['refresh_token_lifetime'] > 0) {
                $expires = time() + $this->config['refresh_token_lifetime'];
            }
            $this->refreshStorage->setRefreshToken($token['refresh_token'], $client_id, $auth_id, $expires, $scope);
        }

        return $token;
    }

    /**
     * Generates an unique access token.
     *
     * Implementing classes may want to override this function to implement
     * other access token generation schemes.
     *
     * @return
     * An unique access token.
     *
     * @ingroup oauth2_section_4
     */
    protected function generateAccessToken()
    {
        if (function_exists('mcrypt_create_iv')) {
            $randomData = mcrypt_create_iv(20, MCRYPT_DEV_URANDOM);
            if ($randomData !== false && strlen($randomData) === 20) {
                return bin2hex($randomData);
            }
        }
        if (function_exists('openssl_random_pseudo_bytes')) {
            $randomData = openssl_random_pseudo_bytes(20);
            if ($randomData !== false && strlen($randomData) === 20) {
                return bin2hex($randomData);
            }
        } 
        if (@file_exists('/dev/urandom')) { // Get 100 bytes of random data
            $randomData = file_get_contents('/dev/urandom', false, null, 0, 20);
            if ($randomData !== false && strlen($randomData) === 20) {
                return bin2hex($randomData);
            }
        }
        // Last resort which you probably should just get rid of:
        $randomData = mt_rand() . mt_rand() . mt_rand() . mt_rand() . microtime(true) . uniqid(mt_rand(), true);
        return substr(hash('sha512', $randomData), 0, 40);
    }

    /**
     * Generates an unique refresh token
     *
     * Implementing classes may want to override this function to implement
     * other refresh token generation schemes.
     *
     * @return
     * An unique refresh.
     *
     * @ingroup oauth2_section_4
     * @see OAuth2::generateAccessToken()
     */
    protected function generateRefreshToken()
    {
        return $this->generateAccessToken(); // let's reuse the same scheme for token generation
    }
}