<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class V1GroupMembership implements AdditionalPropertiesInterface
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
     * @var V1GroupMember|null
     */
    protected $member;
    /**
     * @var string|null
     */
    protected $addedAtMicros;
    /**
     * @var string|null
     */
    protected $addedByUserId;
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
     * @return V1GroupMember|null
     */
    public function getMember(): ?V1GroupMember
    {
        return $this->member;
    }
    /**
     * @param V1GroupMember|null $member
     *
     * @return self
     */
    public function setMember(?V1GroupMember $member): self
    {
        $this->initialized['member'] = true;
        $this->member = $member;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getAddedAtMicros(): ?string
    {
        return $this->addedAtMicros;
    }
    /**
     * @param string|null $addedAtMicros
     *
     * @return self
     */
    public function setAddedAtMicros(?string $addedAtMicros): self
    {
        $this->initialized['addedAtMicros'] = true;
        $this->addedAtMicros = $addedAtMicros;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getAddedByUserId(): ?string
    {
        return $this->addedByUserId;
    }
    /**
     * @param string|null $addedByUserId
     *
     * @return self
     */
    public function setAddedByUserId(?string $addedByUserId): self
    {
        $this->initialized['addedByUserId'] = true;
        $this->addedByUserId = $addedByUserId;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['groupId' => ['groupId', 'getGroupId', 'setGroupId'], 'member' => ['member', 'getMember', 'setMember'], 'addedAtMicros' => ['addedAtMicros', 'getAddedAtMicros', 'setAddedAtMicros'], 'addedByUserId' => ['addedByUserId', 'getAddedByUserId', 'setAddedByUserId']];
    }
}