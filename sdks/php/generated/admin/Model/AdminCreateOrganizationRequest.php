<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class AdminCreateOrganizationRequest implements AdditionalPropertiesInterface
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
    protected $slug;
    /**
     * @var string|null
     */
    protected $displayName;
    /**
     * @var int|null
     */
    protected $memberLimit;
    /**
     * @var bool|null
     */
    protected $mfaRequired = false;
    /**
     * @var array<string, string>|null
     */
    protected $attributes;
    /**
     * @return string|null
     */
    public function getSlug(): ?string
    {
        return $this->slug;
    }
    /**
     * @param string|null $slug
     *
     * @return self
     */
    public function setSlug(?string $slug): self
    {
        $this->initialized['slug'] = true;
        $this->slug = $slug;
        return $this;
    }
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
     * @return array<string, string>|null
     */
    public function getAttributes(): ?iterable
    {
        return $this->attributes;
    }
    /**
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
        return ['slug' => ['slug', 'getSlug', 'setSlug'], 'displayName' => ['display_name', 'getDisplayName', 'setDisplayName'], 'memberLimit' => ['member_limit', 'getMemberLimit', 'setMemberLimit'], 'mfaRequired' => ['mfa_required', 'getMfaRequired', 'setMfaRequired'], 'attributes' => ['attributes', 'getAttributes', 'setAttributes']];
    }
}