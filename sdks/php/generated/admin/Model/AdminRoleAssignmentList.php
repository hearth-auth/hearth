<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class AdminRoleAssignmentList implements AdditionalPropertiesInterface
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
     * @var list<AdminRoleAssignment>|null
     */
    protected $items;
    /**
     * @return list<AdminRoleAssignment>|null
     */
    public function getItems(): ?array
    {
        return $this->items;
    }
    /**
     * @param list<AdminRoleAssignment>|null $items
     *
     * @return self
     */
    public function setItems(?array $items): self
    {
        $this->initialized['items'] = true;
        $this->items = $items;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['items' => ['items', 'getItems', 'setItems']];
    }
}