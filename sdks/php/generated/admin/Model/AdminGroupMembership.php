<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class AdminGroupMembership implements AdditionalPropertiesInterface
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
    protected $groupId;
    /**
     * A user or a group, as a group member or a role-assignment subject.
     *
     * @var AdminSubject|null
     */
    protected $member;
    /**
     * Microseconds since the Unix epoch.
     *
     * @var int|null
     */
    protected $addedAt;
    /**
     * @var string|null
     */
    protected $addedBy;
    /**
     * @return string|null
     */
    public function getGroupId(): ?string
    {
        return $this->groupId;
    }
    /**
     * @param string|null $groupId
     *
     * @return self
     */
    public function setGroupId(?string $groupId): self
    {
        $this->initialized['groupId'] = true;
        $this->groupId = $groupId;
        return $this;
    }
    /**
     * A user or a group, as a group member or a role-assignment subject.
     *
     * @return AdminSubject|null
     */
    public function getMember(): ?AdminSubject
    {
        return $this->member;
    }
    /**
     * A user or a group, as a group member or a role-assignment subject.
     *
     * @param AdminSubject|null $member
     *
     * @return self
     */
    public function setMember(?AdminSubject $member): self
    {
        $this->initialized['member'] = true;
        $this->member = $member;
        return $this;
    }
    /**
     * Microseconds since the Unix epoch.
     *
     * @return int|null
     */
    public function getAddedAt(): ?int
    {
        return $this->addedAt;
    }
    /**
     * Microseconds since the Unix epoch.
     *
     * @param int|null $addedAt
     *
     * @return self
     */
    public function setAddedAt(?int $addedAt): self
    {
        $this->initialized['addedAt'] = true;
        $this->addedAt = $addedAt;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getAddedBy(): ?string
    {
        return $this->addedBy;
    }
    /**
     * @param string|null $addedBy
     *
     * @return self
     */
    public function setAddedBy(?string $addedBy): self
    {
        $this->initialized['addedBy'] = true;
        $this->addedBy = $addedBy;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['groupId' => ['group_id', 'getGroupId', 'setGroupId'], 'member' => ['member', 'getMember', 'setMember'], 'addedAt' => ['added_at', 'getAddedAt', 'setAddedAt'], 'addedBy' => ['added_by', 'getAddedBy', 'setAddedBy']];
    }
}