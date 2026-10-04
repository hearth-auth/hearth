<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class AdminAuditEventList implements AdditionalPropertiesInterface
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
     * @var list<AdminAuditEvent>|null
     */
    protected $events;
    /**
     * @return list<AdminAuditEvent>|null
     */
    public function getEvents(): ?array
    {
        return $this->events;
    }
    /**
     * @param list<AdminAuditEvent>|null $events
     *
     * @return self
     */
    public function setEvents(?array $events): self
    {
        $this->initialized['events'] = true;
        $this->events = $events;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['events' => ['events', 'getEvents', 'setEvents']];
    }
}