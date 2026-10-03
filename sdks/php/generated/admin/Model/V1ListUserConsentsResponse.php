<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class V1ListUserConsentsResponse implements AdditionalPropertiesInterface
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
     * @var list<V1ConsentEntry>|null
     */
    protected $consents;
    /**
     * @return list<V1ConsentEntry>|null
     */
    public function getConsents(): ?array
    {
        return $this->consents;
    }
    /**
     * @param list<V1ConsentEntry>|null $consents
     *
     * @return self
     */
    public function setConsents(?array $consents): self
    {
        $this->initialized['consents'] = true;
        $this->consents = $consents;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['consents' => ['consents', 'getConsents', 'setConsents']];
    }
}