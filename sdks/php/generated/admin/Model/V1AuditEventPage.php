<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class V1AuditEventPage implements AdditionalPropertiesInterface
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
     * @var list<V1AuditEvent>|null
     */
    protected $events;
    /**
     * @return list<V1AuditEvent>|null
     */
    public function getEvents(): ?array
    {
        return $this->events;
    }
    /**
     * @param list<V1AuditEvent>|null $events
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