<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class AdminGroupPage implements AdditionalPropertiesInterface
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
     * @var list<AdminGroup>|null
     */
    protected $items;
    /**
     * @var string|null
     */
    protected $nextCursor;
    /**
     * @var int|null
     */
    protected $total;
    /**
     * @return list<AdminGroup>|null
     */
    public function getItems(): ?array
    {
        return $this->items;
    }
    /**
     * @param list<AdminGroup>|null $items
     *
     * @return self
     */
    public function setItems(?array $items): self
    {
        $this->initialized['items'] = true;
        $this->items = $items;
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
    /**
     * @return int|null
     */
    public function getTotal(): ?int
    {
        return $this->total;
    }
    /**
     * @param int|null $total
     *
     * @return self
     */
    public function setTotal(?int $total): self
    {
        $this->initialized['total'] = true;
        $this->total = $total;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['items' => ['items', 'getItems', 'setItems'], 'nextCursor' => ['next_cursor', 'getNextCursor', 'setNextCursor'], 'total' => ['total', 'getTotal', 'setTotal']];
    }
}