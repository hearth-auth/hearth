<?php

namespace Hearth\Generated\Admin\Model;

class AdminImportUserEntry
{
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
     * @var string|null
     */
    protected $firstName;
    /**
     * @var string|null
     */
    protected $lastName;
    /**
     * `active` (the default), `disabled` or `pending_verification`. Another value fails the entry.
     *
     * @var string|null
     */
    protected $status;
    /**
     * @var array<string, string>|null
     */
    protected $attributes;
    /**
     * A PHC password hash from another system: bcrypt (`$2a$`, `$2b$`, `$2y$`), `$argon2id$`, `$scrypt$` or `$pbkdf2-sha256$`. Sign-in verifies it, and the first successful sign-in replaces it with an Argon2id hash. A hash that is malformed, in another format, or with a work factor above the server's ceilings fails the entry. Without it, the user gets no password.
     *
     * @var string|null
     */
    protected $passwordHash;
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
     * `active` (the default), `disabled` or `pending_verification`. Another value fails the entry.
     *
     * @return string|null
     */
    public function getStatus(): ?string
    {
        return $this->status;
    }
    /**
     * `active` (the default), `disabled` or `pending_verification`. Another value fails the entry.
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
    /**
     * A PHC password hash from another system: bcrypt (`$2a$`, `$2b$`, `$2y$`), `$argon2id$`, `$scrypt$` or `$pbkdf2-sha256$`. Sign-in verifies it, and the first successful sign-in replaces it with an Argon2id hash. A hash that is malformed, in another format, or with a work factor above the server's ceilings fails the entry. Without it, the user gets no password.
     *
     * @return string|null
     */
    public function getPasswordHash(): ?string
    {
        return $this->passwordHash;
    }
    /**
     * A PHC password hash from another system: bcrypt (`$2a$`, `$2b$`, `$2y$`), `$argon2id$`, `$scrypt$` or `$pbkdf2-sha256$`. Sign-in verifies it, and the first successful sign-in replaces it with an Argon2id hash. A hash that is malformed, in another format, or with a work factor above the server's ceilings fails the entry. Without it, the user gets no password.
     *
     * @param string|null $passwordHash
     *
     * @return self
     */
    public function setPasswordHash(?string $passwordHash): self
    {
        $this->initialized['passwordHash'] = true;
        $this->passwordHash = $passwordHash;
        return $this;
    }
}