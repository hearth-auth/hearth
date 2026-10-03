<?php

namespace Hearth\Generated\Admin\Exception;

class IdentityAdminServiceSuspendRealmForbiddenException extends ForbiddenException
{
    /**
     * @var \Psr\Http\Message\ResponseInterface
     */
    private $response;
    public function __construct(?\Psr\Http\Message\ResponseInterface $response = null)
    {
        parent::__construct('Not a system-realm hearth.realm.admin, the target is the system realm, or the target\'s trust policy refuses the crossing');
        $this->response = $response;
    }
    public function getResponse(): ?\Psr\Http\Message\ResponseInterface
    {
        return $this->response;
    }
}