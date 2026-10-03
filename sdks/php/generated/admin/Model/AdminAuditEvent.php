<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class AdminAuditEvent implements AdditionalPropertiesInterface
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
     * The audit action name, e.g. `UserCreated`.
     *
     * @var string|null
     */
    protected $action;
    /**
     * @var string|null
     */
    protected $resourceType;
    /**
     * @var string|null
     */
    protected $resourceId;
    /**
     * Microseconds since the Unix epoch.
     *
     * @var int|null
     */
    protected $timestamp;
    /**
     * Present only when the event carries metadata.
     *
     * @var array<string, mixed>|null
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
     * The audit action name, e.g. `UserCreated`.
     *
     * @return string|null
     */
    public function getAction(): ?string
    {
        return $this->action;
    }
    /**
     * The audit action name, e.g. `UserCreated`.
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
     * Microseconds since the Unix epoch.
     *
     * @return int|null
     */
    public function getTimestamp(): ?int
    {
        return $this->timestamp;
    }
    /**
     * Microseconds since the Unix epoch.
     *
     * @param int|null $timestamp
     *
     * @return self
     */
    public function setTimestamp(?int $timestamp): self
    {
        $this->initialized['timestamp'] = true;
        $this->timestamp = $timestamp;
        return $this;
    }
    /**
     * Present only when the event carries metadata.
     *
     * @return array<string, mixed>|null
     */
    public function getMetadata(): ?iterable
    {
        return $this->metadata;
    }
    /**
     * Present only when the event carries metadata.
     *
     * @param array<string, mixed>|null $metadata
     *
     * @return self
     */
    public function setMetadata(?iterable $metadata): self
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
        return ['id' => ['id', 'getId', 'setId'], 'realmId' => ['realm_id', 'getRealmId', 'setRealmId'], 'actor' => ['actor', 'getActor', 'setActor'], 'action' => ['action', 'getAction', 'setAction'], 'resourceType' => ['resource_type', 'getResourceType', 'setResourceType'], 'resourceId' => ['resource_id', 'getResourceId', 'setResourceId'], 'timestamp' => ['timestamp', 'getTimestamp', 'setTimestamp'], 'metadata' => ['metadata', 'getMetadata', 'setMetadata'], 'integrityHash' => ['integrity_hash', 'getIntegrityHash', 'setIntegrityHash']];
    }
}