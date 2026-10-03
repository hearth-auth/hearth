<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class RbacAdminServiceAddGroupMemberBody implements AdditionalPropertiesInterface
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
     * @var V1GroupMember|null
     */
    protected $member;
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
    public function definedProperties(): array
    {
        return ['realmId' => ['realmId', 'getRealmId', 'setRealmId'], 'member' => ['member', 'getMember', 'setMember']];
    }
}