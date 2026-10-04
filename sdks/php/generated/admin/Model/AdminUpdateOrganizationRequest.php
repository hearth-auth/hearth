<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class AdminUpdateOrganizationRequest implements AdditionalPropertiesInterface
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
    protected $displayName;
    /**
     * @var string|null
     */
    protected $status;
    /**
     * @var int|null
     */
    protected $memberLimit;
    /**
     * @var bool|null
     */
    protected $mfaRequired;
    /**
     * Replaces the whole attribute map.
     *
     * @var array<string, string>|null
     */
    protected $attributes;
    /**
     * @return string|null
     */
    public function getDisplayName(): ?string
    {
        return $this->displayName;
    }
    /**
     * @param string|null $displayName
     *
     * @return self
     */
    public function setDisplayName(?string $displayName): self
    {
        $this->initialized['displayName'] = true;
        $this->displayName = $displayName;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getStatus(): ?string
    {
        return $this->status;
    }
    /**
     * @param string|null $status
     *
     * @return self
     */
    public function setStatus(?string $status): self
    {
        $this->initialized['status'] = true;
        $this->status = $status;
        return $this;
    }
    /**
     * @return int|null
     */
    public function getMemberLimit(): ?int
    {
        return $this->memberLimit;
    }
    /**
     * @param int|null $memberLimit
     *
     * @return self
     */
    public function setMemberLimit(?int $memberLimit): self
    {
        $this->initialized['memberLimit'] = true;
        $this->memberLimit = $memberLimit;
        return $this;
    }
    /**
     * @return bool|null
     */
    public function getMfaRequired(): ?bool
    {
        return $this->mfaRequired;
    }
    /**
     * @param bool|null $mfaRequired
     *
     * @return self
     */
    public function setMfaRequired(?bool $mfaRequired): self
    {
        $this->initialized['mfaRequired'] = true;
        $this->mfaRequired = $mfaRequired;
        return $this;
    }
    /**
     * Replaces the whole attribute map.
     *
     * @return array<string, string>|null
     */
    public function getAttributes(): ?iterable
    {
        return $this->attributes;
    }
    /**
     * Replaces the whole attribute map.
     *
     * @param array<string, string>|null $attributes
     *
     * @return self
     */
    public function setAttributes(?iterable $attributes): self
    {
        $this->initialized['attributes'] = true;
        $this->attributes = $attributes;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['displayName' => ['display_name', 'getDisplayName', 'setDisplayName'], 'status' => ['status', 'getStatus', 'setStatus'], 'memberLimit' => ['member_limit', 'getMemberLimit', 'setMemberLimit'], 'mfaRequired' => ['mfa_required', 'getMfaRequired', 'setMfaRequired'], 'attributes' => ['attributes', 'getAttributes', 'setAttributes']];
    }
}