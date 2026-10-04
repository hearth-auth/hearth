<?php

namespace Hearth\Generated\Admin\Exception;

class AdminClusterTransferLeadershipServiceUnavailableException extends ServiceUnavailableException
{
    /**
     * @var \Psr\Http\Message\ResponseInterface
     */
    private $response;
    public function __construct(?\Psr\Http\Message\ResponseInterface $response = null)
    {
        parent::__construct('Not in cluster mode');
        $this->response = $response;
    }
    public function getResponse(): ?\Psr\Http\Message\ResponseInterface
    {
        return $this->response;
    }
}