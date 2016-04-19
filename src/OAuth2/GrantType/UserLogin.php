<?php
namespace OAuth2\GrantType;


use OAuth2\Storage\UserLoginInterface;
use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

class UserLogin implements GrantTypeInterface
{
    private $userInfo;

    protected $storage;

    /**
     * @param OAuth2\Storage\UserLoginInterface $storage REQUIRED Storage class for retrieving user credentials information
     */
    public function __construct(UserLoginInterface $storage)
    {
        $this->storage = $storage;
    }

    public function getQuerystringIdentifier()
    {
        return 'captcha';
    }

    public function validateRequest(RequestInterface $request, ResponseInterface $response)
    {
        if (!$request->request("captcha") || !$request->request("username")) {
            $response->setError(400, 'invalid_request', 'Missing parameters: "username" and "captcha" required');

            return null;
        }

        if (!$this->storage->checkUserLogin($request->request("username"))) {
            $response->setError(401, 'invalid_grant', '用户不存在');

            return null;
        }

        $userInfo = $this->storage->getUserDetails($request->request("username"));

        if (empty($userInfo)) {
            $response->setError(400, 'invalid_grant', 'Unable to retrieve user information');

            return null;
        }

        if (!isset($userInfo['auth_id'])) {
            throw new \LogicException("you must set the auth_id on the array returned by getUserDetails");
        }

        $this->userInfo = $userInfo;

        return true;
    }

    public function getClientId()
    {
        return null;
    }

    public function getUserId()
    {
        return $this->userInfo['auth_id'];
    }

    public function getScope()
    {
        return isset($this->userInfo['scope']) ? $this->userInfo['scope'] : null;
    }

    public function createAccessToken(AccessTokenInterface $accessToken, $client_id, $user_id, $scope)
    {
        return $accessToken->createAccessToken($client_id, $user_id, $scope);
    }

}
