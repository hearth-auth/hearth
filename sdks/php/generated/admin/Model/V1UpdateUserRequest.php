<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class V1UpdateUserRequest implements AdditionalPropertiesInterface
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
    protected $email;
    /**
     * @var string|null
     */
    protected $displayName;
    /**
     * The lifecycle status of a user account.
     *
     * @var string|null
     */
    protected $status = 'USER_STATUS_UNSPECIFIED';
    /**
     * @var string|null
     */
    protected $firstName;
    /**
     * @var string|null
     */
    protected $lastName;
    /**
     * When non-empty, replaces the user's entire custom attribute map.
     * An empty map is treated as "no change"; use clear_attributes to remove all.
     *
     * @var array<string, string>|null
     */
    protected $attributes;
    /**
     * When true and attributes is empty, clears all custom attributes.
     *
     * @var bool|null
     */
    protected $clearAttributes;
    /**
     * @return string|null
     */
    public function getEmail(): ?string
    {
        return $this->email;
    }
    /**
     * @param string|null $email
     *
     * @return self
     */
    public function setEmail(?string $email): self
    {
        $this->initialized['email'] = true;
        $this->email = $email;
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
     * The lifecycle status of a user account.
     *
     * @return string|null
     */
    public function getStatus(): ?string
    {
        return $this->status;
    }
    /**
     * The lifecycle status of a user account.
     *
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
     * @return string|null
     */
    public function getFirstName(): ?string
    {
        return $this->firstName;
    }
    /**
     * @param string|null $firstName
     *
     * @return self
     */
    public function setFirstName(?string $firstName): self
    {
        $this->initialized['firstName'] = true;
        $this->firstName = $firstName;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getLastName(): ?string
    {
        return $this->lastName;
    }
    /**
     * @param string|null $lastName
     *
     * @return self
     */
    public function setLastName(?string $lastName): self
    {
        $this->initialized['lastName'] = true;
        $this->lastName = $lastName;
        return $this;
    }
    /**
     * When non-empty, replaces the user's entire custom attribute map.
     * An empty map is treated as "no change"; use clear_attributes to remove all.
     *
     * @return array<string, string>|null
     */
    public function getAttributes(): ?iterable
    {
        return $this->attributes;
    }
    /**
    * When non-empty, replaces the user's entire custom attribute map.
    An empty map is treated as "no change"; use clear_attributes to remove all.
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
    /**
     * When true and attributes is empty, clears all custom attributes.
     *
     * @return bool|null
     */
    public function getClearAttributes(): ?bool
    {
        return $this->clearAttributes;
    }
    /**
     * When true and attributes is empty, clears all custom attributes.
     *
     * @param bool|null $clearAttributes
     *
     * @return self
     */
    public function setClearAttributes(?bool $clearAttributes): self
    {
        $this->initialized['clearAttributes'] = true;
        $this->clearAttributes = $clearAttributes;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['email' => ['email', 'getEmail', 'setEmail'], 'displayName' => ['displayName', 'getDisplayName', 'setDisplayName'], 'status' => ['status', 'getStatus', 'setStatus'], 'firstName' => ['firstName', 'getFirstName', 'setFirstName'], 'lastName' => ['lastName', 'getLastName', 'setLastName'], 'attributes' => ['attributes', 'getAttributes', 'setAttributes'], 'clearAttributes' => ['clearAttributes', 'getClearAttributes', 'setClearAttributes']];
    }
}