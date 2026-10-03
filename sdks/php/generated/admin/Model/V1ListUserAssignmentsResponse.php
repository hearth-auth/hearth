<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class V1ListUserAssignmentsResponse implements AdditionalPropertiesInterface
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
     * @var list<V1RoleAssignment>|null
     */
    protected $assignments;
    /**
     * @return list<V1RoleAssignment>|null
     */
    public function getAssignments(): ?array
    {
        return $this->assignments;
    }
    /**
     * @param list<V1RoleAssignment>|null $assignments
     *
     * @return self
     */
    public function setAssignments(?array $assignments): self
    {
        $this->initialized['assignments'] = true;
        $this->assignments = $assignments;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['assignments' => ['assignments', 'getAssignments', 'setAssignments']];
    }
}