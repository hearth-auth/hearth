<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class V1AuditEvent implements AdditionalPropertiesInterface
{
    use AdditionalAndPatternProperties;
    /**
     * @var array
     */
    protected $initialized = [];
    public function isInitialized($property): bool
    {
        return array_key_exists($property, $this->initialized);
    }
    /**
     * @var string|null
     */
    protected $id;
    /**
     * @var string|null
     */
    protected $realmId;
    /**
     * @var string|null
     */
    protected $actor;
    /**
     * Categories of security-critical actions recorded in the audit log.
     * 
     *  - AUDIT_ACTION_GROUP_CREATED: RBAC group management
     *  - AUDIT_ACTION_ORPHANED_REFERENCE_SKIPPED: Permission management
     *  - AUDIT_ACTION_LOGIN_FAILED: Login events
     *  - AUDIT_ACTION_BACKUP_CREATED: Backup and export
     *  - AUDIT_ACTION_REQUIRED_ACTION_ASSIGNED: Required actions
     *  - AUDIT_ACTION_PASSWORD_COMPROMISED_REJECTED: Password security
     *  - AUDIT_ACTION_SESSION_LIMIT_ENFORCED: Session management
     *  - AUDIT_ACTION_ABUSE_DETECTED: Abuse detection
     *  - AUDIT_ACTION_EMAIL_CHANGE_INITIATED: Email change
     *  - AUDIT_ACTION_OIDC_SILENT_AUTH_PROBED: OIDC silent auth
     *  - AUDIT_ACTION_AGENT_CREATED: Agent lifecycle
     *  - AUDIT_ACTION_AGENT_DELEGATION: Agent delegation and MCP (M2)
     *  - AUDIT_ACTION_AAT_ISSUED: Phase D — advanced agent surface
     *  - AUDIT_ACTION_MFA_ENABLED: MFA lifecycle
     *  - AUDIT_ACTION_INVITATION_CREATED: Organization invitation lifecycle
     *
     * @var string|null
     */
    protected $action = 'AUDIT_ACTION_UNSPECIFIED';
    /**
     * @var string|null
     */
    protected $resourceType;
    /**
     * @var string|null
     */
    protected $resourceId;
    /**
     * @var string|null
     */
    protected $timestamp;
    /**
     * Optional additional context (JSON-encoded).
     *
     * @var string|null
     */
    protected $metadata;
    /**
     * @var string|null
     */
    protected $integrityHash;
    /**
     * @return string|null
     */
    public function getId(): ?string
    {
        return $this->id;
    }
    /**
     * @param string|null $id
     *
     * @return self
     */
    public function setId(?string $id): self
    {
        $this->initialized['id'] = true;
        $this->id = $id;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getRealmId(): ?string
    {
        return $this->realmId;
    }
    /**
     * @param string|null $realmId
     *
     * @return self
     */
    public function setRealmId(?string $realmId): self
    {
        $this->initialized['realmId'] = true;
        $this->realmId = $realmId;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getActor(): ?string
    {
        return $this->actor;
    }
    /**
     * @param string|null $actor
     *
     * @return self
     */
    public function setActor(?string $actor): self
    {
        $this->initialized['actor'] = true;
        $this->actor = $actor;
        return $this;
    }
    /**
     * Categories of security-critical actions recorded in the audit log.
     * 
     *  - AUDIT_ACTION_GROUP_CREATED: RBAC group management
     *  - AUDIT_ACTION_ORPHANED_REFERENCE_SKIPPED: Permission management
     *  - AUDIT_ACTION_LOGIN_FAILED: Login events
     *  - AUDIT_ACTION_BACKUP_CREATED: Backup and export
     *  - AUDIT_ACTION_REQUIRED_ACTION_ASSIGNED: Required actions
     *  - AUDIT_ACTION_PASSWORD_COMPROMISED_REJECTED: Password security
     *  - AUDIT_ACTION_SESSION_LIMIT_ENFORCED: Session management
     *  - AUDIT_ACTION_ABUSE_DETECTED: Abuse detection
     *  - AUDIT_ACTION_EMAIL_CHANGE_INITIATED: Email change
     *  - AUDIT_ACTION_OIDC_SILENT_AUTH_PROBED: OIDC silent auth
     *  - AUDIT_ACTION_AGENT_CREATED: Agent lifecycle
     *  - AUDIT_ACTION_AGENT_DELEGATION: Agent delegation and MCP (M2)
     *  - AUDIT_ACTION_AAT_ISSUED: Phase D — advanced agent surface
     *  - AUDIT_ACTION_MFA_ENABLED: MFA lifecycle
     *  - AUDIT_ACTION_INVITATION_CREATED: Organization invitation lifecycle
     *
     * @return string|null
     */
    public function getAction(): ?string
    {
        return $this->action;
    }
    /**
    * Categories of security-critical actions recorded in the audit log.
    
    - AUDIT_ACTION_GROUP_CREATED: RBAC group management
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
    *
    * @param string|null $action
    *
    * @return self
    */
    public function setAction(?string $action): self
    {
        $this->initialized['action'] = true;
        $this->action = $action;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getResourceType(): ?string
    {
        return $this->resourceType;
    }
    /**
     * @param string|null $resourceType
     *
     * @return self
     */
    public function setResourceType(?string $resourceType): self
    {
        $this->initialized['resourceType'] = true;
        $this->resourceType = $resourceType;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getResourceId(): ?string
    {
        return $this->resourceId;
    }
    /**
     * @param string|null $resourceId
     *
     * @return self
     */
    public function setResourceId(?string $resourceId): self
    {
        $this->initialized['resourceId'] = true;
        $this->resourceId = $resourceId;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getTimestamp(): ?string
    {
        return $this->timestamp;
    }
    /**
     * @param string|null $timestamp
     *
     * @return self
     */
    public function setTimestamp(?string $timestamp): self
    {
        $this->initialized['timestamp'] = true;
        $this->timestamp = $timestamp;
        return $this;
    }
    /**
     * Optional additional context (JSON-encoded).
     *
     * @return string|null
     */
    public function getMetadata(): ?string
    {
        return $this->metadata;
    }
    /**
     * Optional additional context (JSON-encoded).
     *
     * @param string|null $metadata
     *
     * @return self
     */
    public function setMetadata(?string $metadata): self
    {
        $this->initialized['metadata'] = true;
        $this->metadata = $metadata;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getIntegrityHash(): ?string
    {
        return $this->integrityHash;
    }
    /**
     * @param string|null $integrityHash
     *
     * @return self
     */
    public function setIntegrityHash(?string $integrityHash): self
    {
        $this->initialized['integrityHash'] = true;
        $this->integrityHash = $integrityHash;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['id' => ['id', 'getId', 'setId'], 'realmId' => ['realmId', 'getRealmId', 'setRealmId'], 'actor' => ['actor', 'getActor', 'setActor'], 'action' => ['action', 'getAction', 'setAction'], 'resourceType' => ['resourceType', 'getResourceType', 'setResourceType'], 'resourceId' => ['resourceId', 'getResourceId', 'setResourceId'], 'timestamp' => ['timestamp', 'getTimestamp', 'setTimestamp'], 'metadata' => ['metadata', 'getMetadata', 'setMetadata'], 'integrityHash' => ['integrityHash', 'getIntegrityHash', 'setIntegrityHash']];
    }
}