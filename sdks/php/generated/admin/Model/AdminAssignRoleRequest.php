<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class AdminAssignRoleRequest implements AdditionalPropertiesInterface
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
    protected $roleId;
    /**
     * Assign inside this organization only; absent or null assigns realm-wide.
     *
     * @var string|null
     */
    protected $orgId;
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
     * Assign inside this organization only; absent or null assigns realm-wide.
     *
     * @return string|null
     */
    public function getOrgId(): ?string
    {
        return $this->orgId;
    }
    /**
     * Assign inside this organization only; absent or null assigns realm-wide.
     *
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
        return ['roleId' => ['role_id', 'getRoleId', 'setRoleId'], 'orgId' => ['org_id', 'getOrgId', 'setOrgId']];
    }
}