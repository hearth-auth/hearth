<?php

namespace Hearth\Generated\Admin\Exception;

class IdentityAdminServiceSuspendRealmConflictException extends ConflictException
{
    /**
     * @var \Psr\Http\Message\ResponseInterface
     */
    private $response;
    public function __construct(?\Psr\Http\Message\ResponseInterface $response = null)
    {
        parent::__construct('The realm is archived or being deleted (HEARTH_REALM_ARCHIVED)');
        $this->response = $response;
    }
    public function getResponse(): ?\Psr\Http\Message\ResponseInterface
    {
        return $this->response;
    }
}