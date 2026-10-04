<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class V1ConsentEntry implements AdditionalPropertiesInterface
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
    protected $clientId;
    /**
     * @var string|null
     */
    protected $clientName;
    /**
     * @var list<string>|null
     */
    protected $grantedScopes;
    /**
     * @var int|null
     */
    protected $grantedAt;
    /**
     * @var int|null
     */
    protected $updatedAt;
    /**
     * @return string|null
     */
    public function getClientId(): ?string
    {
        return $this->clientId;
    }
    /**
     * @param string|null $clientId
     *
     * @return self
     */
    public function setClientId(?string $clientId): self
    {
        $this->initialized['clientId'] = true;
        $this->clientId = $clientId;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getClientName(): ?string
    {
        return $this->clientName;
    }
    /**
     * @param string|null $clientName
     *
     * @return self
     */
    public function setClientName(?string $clientName): self
    {
        $this->initialized['clientName'] = true;
        $this->clientName = $clientName;
        return $this;
    }
    /**
     * @return list<string>|null
     */
    public function getGrantedScopes(): ?array
    {
        return $this->grantedScopes;
    }
    /**
     * @param list<string>|null $grantedScopes
     *
     * @return self
     */
    public function setGrantedScopes(?array $grantedScopes): self
    {
        $this->initialized['grantedScopes'] = true;
        $this->grantedScopes = $grantedScopes;
        return $this;
    }
    /**
     * @return int|null
     */
    public function getGrantedAt(): ?int
    {
        return $this->grantedAt;
    }
    /**
     * @param int|null $grantedAt
     *
     * @return self
     */
    public function setGrantedAt(?int $grantedAt): self
    {
        $this->initialized['grantedAt'] = true;
        $this->grantedAt = $grantedAt;
        return $this;
    }
    /**
     * @return int|null
     */
    public function getUpdatedAt(): ?int
    {
        return $this->updatedAt;
    }
    /**
     * @param int|null $updatedAt
     *
     * @return self
     */
    public function setUpdatedAt(?int $updatedAt): self
    {
        $this->initialized['updatedAt'] = true;
        $this->updatedAt = $updatedAt;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['clientId' => ['client_id', 'getClientId', 'setClientId'], 'clientName' => ['client_name', 'getClientName', 'setClientName'], 'grantedScopes' => ['granted_scopes', 'getGrantedScopes', 'setGrantedScopes'], 'grantedAt' => ['granted_at', 'getGrantedAt', 'setGrantedAt'], 'updatedAt' => ['updated_at', 'getUpdatedAt', 'setUpdatedAt']];
    }
}