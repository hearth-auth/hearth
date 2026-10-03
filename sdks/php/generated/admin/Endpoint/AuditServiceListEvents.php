<?php

namespace Hearth\Generated\Admin\Endpoint;

class AuditServiceListEvents extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    /**
    * @param array{
    *    "realmId"?: string,
    *    "startTime"?: string,
    *    "endTime"?: string,
    *    "actor"?: string,
    *    "action"?: string, // - AUDIT_ACTION_GROUP_CREATED: RBAC group management
    - AUDIT_ACTION_ORPHANED_REFERENCE_SKIPPED: Permission management
    - AUDIT_ACTION_LOGIN_FAILED: Login events
    - AUDIT_ACTION_BACKUP_CREATED: Backup and export
    - AUDIT_ACTION_REQUIRED_ACTION_ASSIGNED: Required actions
    - AUDIT_ACTION_PASSWORD_COMPROMISED_REJECTED: Password security
    - AUDIT_ACTION_SESSION_LIMIT_ENFORCED: Session management
    - AUDIT_ACTION_ABUSE_DETECTED: Abuse detection
    - AUDIT_ACTION_EMAIL_CHANGE_INITIATED: Email change
    - AUDIT_ACTION_OIDC_SILENT_AUTH_PROBED: OIDC silent auth
    - AUDIT_ACTION_AGENT_CREATED: Agent lifecycle
    - AUDIT_ACTION_AGENT_DELEGATION: Agent delegation and MCP (M2)
    - AUDIT_ACTION_AAT_ISSUED: Phase D — advanced agent surface
    - AUDIT_ACTION_MFA_ENABLED: MFA lifecycle
    - AUDIT_ACTION_INVITATION_CREATED: Organization invitation lifecycle
    *    "limit"?: int,
    * } $queryParameters
    */
    public function __construct(array $queryParameters = [])
    {
        $this->queryParameters = $queryParameters;
    }
    use \Hearth\Generated\Admin\Runtime\Client\EndpointTrait;
    public function getMethod(): string
    {
        return 'GET';
    }
    public function getUri(): string
    {
        return '/admin/audit';
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        return [[], null];
    }
    public function getExtraHeaders(): array
    {
        return ['Accept' => ['application/json']];
    }
    protected function getQueryOptionsResolver(): \Symfony\Component\OptionsResolver\OptionsResolver
    {
        $optionsResolver = parent::getQueryOptionsResolver();
        $optionsResolver->setDefined(['realmId', 'startTime', 'endTime', 'actor', 'action', 'limit']);
        $optionsResolver->setRequired([]);
        $optionsResolver->setDefaults(['action' => 'AUDIT_ACTION_UNSPECIFIED']);
        $optionsResolver->addAllowedTypes('realmId', ['string']);
        $optionsResolver->addAllowedTypes('startTime', ['string']);
        $optionsResolver->addAllowedTypes('endTime', ['string']);
        $optionsResolver->addAllowedTypes('actor', ['string']);
        $optionsResolver->addAllowedTypes('action', ['string']);
        $optionsResolver->addAllowedTypes('limit', ['int']);
        return $optionsResolver;
    }
    /**
     * {@inheritdoc}
     *
     *
     * @return null|\Hearth\Generated\Admin\Model\V1AuditEventPage|\Hearth\Generated\Admin\Model\RpcStatus
     */
    protected function transformResponseBody(\Psr\Http\Message\ResponseInterface $response, \Symfony\Component\Serializer\SerializerInterface $serializer, ?string $contentType = null)
    {
        $status = $response->getStatusCode();
        $body = (string) $response->getBody();
        if (is_null($contentType) === false && (200 === $status && stripos(strtolower($contentType), 'application/json') !== false)) {
            return $serializer->deserialize($body, 'Hearth\Generated\Admin\Model\V1AuditEventPage', 'json');
        }
        if (stripos(strtolower($contentType), 'application/json') !== false) {
            return $serializer->deserialize($body, 'Hearth\Generated\Admin\Model\RpcStatus', 'json');
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}