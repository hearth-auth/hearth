<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class RbacAdminServiceAssignUserRoleBody implements AdditionalPropertiesInterface
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
    protected $realmId;
    /**
     * @var string|null
     */
    protected $roleId;
    /**
     * @var V1Scope|null
     */
    protected $scope;
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
    public function getRoleId(): ?string
    {
        return $this->roleId;
    }
    /**
     * @param string|null $roleId
     *
     * @return self
     */
    public function setRoleId(?string $roleId): self
    {
        $this->initialized['roleId'] = true;
        $this->roleId = $roleId;
        return $this;
    }
    /**
     * @return V1Scope|null
     */
    public function getScope(): ?V1Scope
    {
        return $this->scope;
    }
    /**
     * @param V1Scope|null $scope
     *
     * @return self
     */
    public function setScope(?V1Scope $scope): self
    {
        $this->initialized['scope'] = true;
        $this->scope = $scope;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['realmId' => ['realmId', 'getRealmId', 'setRealmId'], 'roleId' => ['roleId', 'getRoleId', 'setRoleId'], 'scope' => ['scope', 'getScope', 'setScope']];
    }
}