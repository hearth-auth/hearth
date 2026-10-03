<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class V1ListGroupMembersResponse implements AdditionalPropertiesInterface
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
     * @var list<V1GroupMember>|null
     */
    protected $members;
    /**
     * @var string|null
     */
    protected $nextCursor;
    /**
     * @return list<V1GroupMember>|null
     */
    public function getMembers(): ?array
    {
        return $this->members;
    }
    /**
     * @param list<V1GroupMember>|null $members
     *
     * @return self
     */
    public function setMembers(?array $members): self
    {
        $this->initialized['members'] = true;
        $this->members = $members;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getNextCursor(): ?string
    {
        return $this->nextCursor;
    }
    /**
     * @param string|null $nextCursor
     *
     * @return self
     */
    public function setNextCursor(?string $nextCursor): self
    {
        $this->initialized['nextCursor'] = true;
        $this->nextCursor = $nextCursor;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['members' => ['members', 'getMembers', 'setMembers'], 'nextCursor' => ['nextCursor', 'getNextCursor', 'setNextCursor']];
    }
}