<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class V1RealmConfig implements AdditionalPropertiesInterface
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
    protected $sessionTtlMicros;
    /**
     * @var int|null
     */
    protected $passwordMemoryCost;
    /**
     * @var int|null
     */
    protected $passwordTimeCost;
    /**
     * @return string|null
     */
    public function getSessionTtlMicros(): ?string
    {
        return $this->sessionTtlMicros;
    }
    /**
     * @param string|null $sessionTtlMicros
     *
     * @return self
     */
    public function setSessionTtlMicros(?string $sessionTtlMicros): self
    {
        $this->initialized['sessionTtlMicros'] = true;
        $this->sessionTtlMicros = $sessionTtlMicros;
        return $this;
    }
    /**
     * @return int|null
     */
    public function getPasswordMemoryCost(): ?int
    {
        return $this->passwordMemoryCost;
    }
    /**
     * @param int|null $passwordMemoryCost
     *
     * @return self
     */
    public function setPasswordMemoryCost(?int $passwordMemoryCost): self
    {
        $this->initialized['passwordMemoryCost'] = true;
        $this->passwordMemoryCost = $passwordMemoryCost;
        return $this;
    }
    /**
     * @return int|null
     */
    public function getPasswordTimeCost(): ?int
    {
        return $this->passwordTimeCost;
    }
    /**
     * @param int|null $passwordTimeCost
     *
     * @return self
     */
    public function setPasswordTimeCost(?int $passwordTimeCost): self
    {
        $this->initialized['passwordTimeCost'] = true;
        $this->passwordTimeCost = $passwordTimeCost;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['sessionTtlMicros' => ['sessionTtlMicros', 'getSessionTtlMicros', 'setSessionTtlMicros'], 'passwordMemoryCost' => ['passwordMemoryCost', 'getPasswordMemoryCost', 'setPasswordMemoryCost'], 'passwordTimeCost' => ['passwordTimeCost', 'getPasswordTimeCost', 'setPasswordTimeCost']];
    }
}