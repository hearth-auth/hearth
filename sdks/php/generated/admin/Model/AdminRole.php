<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class AdminRole implements AdditionalPropertiesInterface
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
    protected $parentRoles;
    /**
     * @var string|null
     */
    protected $scopeKind;
    /**
     * @var string|null
     */
    protected $status;
    /**
     * Declared in hearth.yaml; the admin API cannot change it.
     *
     * @var bool|null
     */
    protected $yamlManaged;
    /**
     * Microseconds since the Unix epoch.
     *
     * @var int|null
     */
    protected $createdAt;
    /**
     * Microseconds since the Unix epoch.
     *
     * @var int|null
     */
    protected $updatedAt;
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
    public function getParentRoles(): ?array
    {
        return $this->parentRoles;
    }
    /**
     * @param list<string>|null $parentRoles
     *
     * @return self
     */
    public function setParentRoles(?array $parentRoles): self
    {
        $this->initialized['parentRoles'] = true;
        $this->parentRoles = $parentRoles;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getScopeKind(): ?string
    {
        return $this->scopeKind;
    }
    /**
     * @param string|null $scopeKind
     *
     * @return self
     */
    public function setScopeKind(?string $scopeKind): self
    {
        $this->initialized['scopeKind'] = true;
        $this->scopeKind = $scopeKind;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getStatus(): ?string
    {
        return $this->status;
    }
    /**
     * @param string|null $status
     *
     * @return self
     */
    public function setStatus(?string $status): self
    {
        $this->initialized['status'] = true;
        $this->status = $status;
        return $this;
    }
    /**
     * Declared in hearth.yaml; the admin API cannot change it.
     *
     * @return bool|null
     */
    public function getYamlManaged(): ?bool
    {
        return $this->yamlManaged;
    }
    /**
     * Declared in hearth.yaml; the admin API cannot change it.
     *
     * @param bool|null $yamlManaged
     *
     * @return self
     */
    public function setYamlManaged(?bool $yamlManaged): self
    {
        $this->initialized['yamlManaged'] = true;
        $this->yamlManaged = $yamlManaged;
        return $this;
    }
    /**
     * Microseconds since the Unix epoch.
     *
     * @return int|null
     */
    public function getCreatedAt(): ?int
    {
        return $this->createdAt;
    }
    /**
     * Microseconds since the Unix epoch.
     *
     * @param int|null $createdAt
     *
     * @return self
     */
    public function setCreatedAt(?int $createdAt): self
    {
        $this->initialized['createdAt'] = true;
        $this->createdAt = $createdAt;
        return $this;
    }
    /**
     * Microseconds since the Unix epoch.
     *
     * @return int|null
     */
    public function getUpdatedAt(): ?int
    {
        return $this->updatedAt;
    }
    /**
     * Microseconds since the Unix epoch.
     *
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
        return ['id' => ['id', 'getId', 'setId'], 'realmId' => ['realm_id', 'getRealmId', 'setRealmId'], 'name' => ['name', 'getName', 'setName'], 'description' => ['description', 'getDescription', 'setDescription'], 'permissions' => ['permissions', 'getPermissions', 'setPermissions'], 'parentRoles' => ['parent_roles', 'getParentRoles', 'setParentRoles'], 'scopeKind' => ['scope_kind', 'getScopeKind', 'setScopeKind'], 'status' => ['status', 'getStatus', 'setStatus'], 'yamlManaged' => ['yaml_managed', 'getYamlManaged', 'setYamlManaged'], 'createdAt' => ['created_at', 'getCreatedAt', 'setCreatedAt'], 'updatedAt' => ['updated_at', 'getUpdatedAt', 'setUpdatedAt']];
    }
}