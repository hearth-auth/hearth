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
     * @var string|null
     */
    protected $grantedAt;
    /**
     * @var string|null
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
     * @return string|null
     */
    public function getGrantedAt(): ?string
    {
        return $this->grantedAt;
    }
    /**
     * @param string|null $grantedAt
     *
     * @return self
     */
    public function setGrantedAt(?string $grantedAt): self
    {
        $this->initialized['grantedAt'] = true;
        $this->grantedAt = $grantedAt;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getUpdatedAt(): ?string
    {
        return $this->updatedAt;
    }
    /**
     * @param string|null $updatedAt
     *
     * @return self
     */
    public function setUpdatedAt(?string $updatedAt): self
    {
        $this->initialized['updatedAt'] = true;
        $this->updatedAt = $updatedAt;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['clientId' => ['clientId', 'getClientId', 'setClientId'], 'clientName' => ['clientName', 'getClientName', 'setClientName'], 'grantedScopes' => ['grantedScopes', 'getGrantedScopes', 'setGrantedScopes'], 'grantedAt' => ['grantedAt', 'getGrantedAt', 'setGrantedAt'], 'updatedAt' => ['updatedAt', 'getUpdatedAt', 'setUpdatedAt']];
    }
}