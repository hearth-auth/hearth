<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class V1CreateRoleRequest implements AdditionalPropertiesInterface
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
    protected $name;
    /**
     * @var string|null
     */
    protected $description;
    /**
     * @var list<string>|null
     */
    protected $permissions;
    /**
     * @var list<string>|null
     */
    protected $parentRoleIds;
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
    public function getName(): ?string
    {
        return $this->name;
    }
    /**
     * @param string|null $name
     *
     * @return self
     */
    public function setName(?string $name): self
    {
        $this->initialized['name'] = true;
        $this->name = $name;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getDescription(): ?string
    {
        return $this->description;
    }
    /**
     * @param string|null $description
     *
     * @return self
     */
    public function setDescription(?string $description): self
    {
        $this->initialized['description'] = true;
        $this->description = $description;
        return $this;
    }
    /**
     * @return list<string>|null
     */
    public function getPermissions(): ?array
    {
        return $this->permissions;
    }
    /**
     * @param list<string>|null $permissions
     *
     * @return self
     */
    public function setPermissions(?array $permissions): self
    {
        $this->initialized['permissions'] = true;
        $this->permissions = $permissions;
        return $this;
    }
    /**
     * @return list<string>|null
     */
    public function getParentRoleIds(): ?array
    {
        return $this->parentRoleIds;
    }
    /**
     * @param list<string>|null $parentRoleIds
     *
     * @return self
     */
    public function setParentRoleIds(?array $parentRoleIds): self
    {
        $this->initialized['parentRoleIds'] = true;
        $this->parentRoleIds = $parentRoleIds;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['realmId' => ['realmId', 'getRealmId', 'setRealmId'], 'name' => ['name', 'getName', 'setName'], 'description' => ['description', 'getDescription', 'setDescription'], 'permissions' => ['permissions', 'getPermissions', 'setPermissions'], 'parentRoleIds' => ['parentRoleIds', 'getParentRoleIds', 'setParentRoleIds']];
    }
}