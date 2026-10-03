<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class V1OrgScope implements AdditionalPropertiesInterface
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
    protected $orgId;
    /**
     * @return string|null
     */
    public function getOrgId(): ?string
    {
        return $this->orgId;
    }
    /**
     * @param string|null $orgId
     *
     * @return self
     */
    public function setOrgId(?string $orgId): self
    {
        $this->initialized['orgId'] = true;
        $this->orgId = $orgId;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['orgId' => ['orgId', 'getOrgId', 'setOrgId']];
    }
}