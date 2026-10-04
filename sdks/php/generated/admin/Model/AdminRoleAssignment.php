<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class AdminRoleAssignment implements AdditionalPropertiesInterface
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
     * A user or a group, as a group member or a role-assignment subject.
     *
     * @var AdminSubject|null
     */
    protected $subject;
    /**
     * @var string|null
     */
    protected $roleId;
    /**
     * @var AdminAssignmentScope|null
     */
    protected $scope;
    /**
     * Microseconds since the Unix epoch.
     *
     * @var int|null
     */
    protected $assignedAt;
    /**
     * @var string|null
     */
    protected $assignedBy;
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
     * A user or a group, as a group member or a role-assignment subject.
     *
     * @return AdminSubject|null
     */
    public function getSubject(): ?AdminSubject
    {
        return $this->subject;
    }
    /**
     * A user or a group, as a group member or a role-assignment subject.
     *
     * @param AdminSubject|null $subject
     *
     * @return self
     */
    public function setSubject(?AdminSubject $subject): self
    {
        $this->initialized['subject'] = true;
        $this->subject = $subject;
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
     * @return AdminAssignmentScope|null
     */
    public function getScope(): ?AdminAssignmentScope
    {
        return $this->scope;
    }
    /**
     * @param AdminAssignmentScope|null $scope
     *
     * @return self
     */
    public function setScope(?AdminAssignmentScope $scope): self
    {
        $this->initialized['scope'] = true;
        $this->scope = $scope;
        return $this;
    }
    /**
     * Microseconds since the Unix epoch.
     *
     * @return int|null
     */
    public function getAssignedAt(): ?int
    {
        return $this->assignedAt;
    }
    /**
     * Microseconds since the Unix epoch.
     *
     * @param int|null $assignedAt
     *
     * @return self
     */
    public function setAssignedAt(?int $assignedAt): self
    {
        $this->initialized['assignedAt'] = true;
        $this->assignedAt = $assignedAt;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getAssignedBy(): ?string
    {
        return $this->assignedBy;
    }
    /**
     * @param string|null $assignedBy
     *
     * @return self
     */
    public function setAssignedBy(?string $assignedBy): self
    {
        $this->initialized['assignedBy'] = true;
        $this->assignedBy = $assignedBy;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['id' => ['id', 'getId', 'setId'], 'realmId' => ['realm_id', 'getRealmId', 'setRealmId'], 'subject' => ['subject', 'getSubject', 'setSubject'], 'roleId' => ['role_id', 'getRoleId', 'setRoleId'], 'scope' => ['scope', 'getScope', 'setScope'], 'assignedAt' => ['assigned_at', 'getAssignedAt', 'setAssignedAt'], 'assignedBy' => ['assigned_by', 'getAssignedBy', 'setAssignedBy']];
    }
}