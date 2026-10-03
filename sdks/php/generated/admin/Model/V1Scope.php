<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class V1Scope implements AdditionalPropertiesInterface
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
     * @var array<string, mixed>|null
     */
    protected $realm;
    /**
     * @var V1OrgScope|null
     */
    protected $org;
    /**
     * @return array<string, mixed>|null
     */
    public function getRealm(): ?iterable
    {
        return $this->realm;
    }
    /**
     * @param array<string, mixed>|null $realm
     *
     * @return self
     */
    public function setRealm(?iterable $realm): self
    {
        $this->initialized['realm'] = true;
        $this->realm = $realm;
        return $this;
    }
    /**
     * @return V1OrgScope|null
     */
    public function getOrg(): ?V1OrgScope
    {
        return $this->org;
    }
    /**
     * @param V1OrgScope|null $org
     *
     * @return self
     */
    public function setOrg(?V1OrgScope $org): self
    {
        $this->initialized['org'] = true;
        $this->org = $org;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['realm' => ['realm', 'getRealm', 'setRealm'], 'org' => ['org', 'getOrg', 'setOrg']];
    }
}