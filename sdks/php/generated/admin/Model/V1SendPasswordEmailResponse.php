<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class V1SendPasswordEmailResponse implements AdditionalPropertiesInterface
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
     * Which password email Hearth sent.
     * 
     *  - PASSWORD_EMAIL_KIND_SETUP: The user has no password: the welcome email with a set-password link.
     *  - PASSWORD_EMAIL_KIND_RESET: The user has a password: the password-reset email.
     *
     * @var string|null
     */
    protected $kind = 'PASSWORD_EMAIL_KIND_UNSPECIFIED';
    /**
     * Which password email Hearth sent.
     * 
     *  - PASSWORD_EMAIL_KIND_SETUP: The user has no password: the welcome email with a set-password link.
     *  - PASSWORD_EMAIL_KIND_RESET: The user has a password: the password-reset email.
     *
     * @return string|null
     */
    public function getKind(): ?string
    {
        return $this->kind;
    }
    /**
    * Which password email Hearth sent.
    
    - PASSWORD_EMAIL_KIND_SETUP: The user has no password: the welcome email with a set-password link.
    - PASSWORD_EMAIL_KIND_RESET: The user has a password: the password-reset email.
    *
    * @param string|null $kind
    *
    * @return self
    */
    public function setKind(?string $kind): self
    {
        $this->initialized['kind'] = true;
        $this->kind = $kind;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['kind' => ['kind', 'getKind', 'setKind']];
    }
}