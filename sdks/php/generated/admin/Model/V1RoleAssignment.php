<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class V1RoleAssignment implements AdditionalPropertiesInterface
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
    protected $subjectId;
    /**
     * @var string|null
     */
    protected $subjectType = 'TYPE_UNSPECIFIED';
    /**
     * @var string|null
     */
    protected $roleId;
    /**
     * @var V1Scope|null
     */
    protected $scope;
    /**
     * @var string|null
     */
    protected $assignedAtMicros;
    /**
     * @var string|null
     */
    protected $assignedByUserId;
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
    public function getSubjectId(): ?string
    {
        return $this->subjectId;
    }
    /**
     * @param string|null $subjectId
     *
     * @return self
     */
    public function setSubjectId(?string $subjectId): self
    {
        $this->initialized['subjectId'] = true;
        $this->subjectId = $subjectId;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getSubjectType(): ?string
    {
        return $this->subjectType;
    }
    /**
     * @param string|null $subjectType
     *
     * @return self
     */
    public function setSubjectType(?string $subjectType): self
    {
        $this->initialized['subjectType'] = true;
        $this->subjectType = $subjectType;
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
    /**
     * @return string|null
     */
    public function getAssignedAtMicros(): ?string
    {
        return $this->assignedAtMicros;
    }
    /**
     * @param string|null $assignedAtMicros
     *
     * @return self
     */
    public function setAssignedAtMicros(?string $assignedAtMicros): self
    {
        $this->initialized['assignedAtMicros'] = true;
        $this->assignedAtMicros = $assignedAtMicros;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getAssignedByUserId(): ?string
    {
        return $this->assignedByUserId;
    }
    /**
     * @param string|null $assignedByUserId
     *
     * @return self
     */
    public function setAssignedByUserId(?string $assignedByUserId): self
    {
        $this->initialized['assignedByUserId'] = true;
        $this->assignedByUserId = $assignedByUserId;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['id' => ['id', 'getId', 'setId'], 'realmId' => ['realmId', 'getRealmId', 'setRealmId'], 'subjectId' => ['subjectId', 'getSubjectId', 'setSubjectId'], 'subjectType' => ['subjectType', 'getSubjectType', 'setSubjectType'], 'roleId' => ['roleId', 'getRoleId', 'setRoleId'], 'scope' => ['scope', 'getScope', 'setScope'], 'assignedAtMicros' => ['assignedAtMicros', 'getAssignedAtMicros', 'setAssignedAtMicros'], 'assignedByUserId' => ['assignedByUserId', 'getAssignedByUserId', 'setAssignedByUserId']];
    }
}