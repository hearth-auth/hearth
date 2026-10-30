<?php

namespace Hearth\Generated\Admin\Model;

class AdminImportUsersRequest
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
     * @var list<AdminImportUserEntry>|null
     */
    protected $users;
    /**
     * @return list<AdminImportUserEntry>|null
     */
    public function getUsers(): ?array
    {
        return $this->users;
    }
    /**
     * @param list<AdminImportUserEntry>|null $users
     *
     * @return self
     */
    public function setUsers(?array $users): self
    {
        $this->initialized['users'] = true;
        $this->users = $users;
        return $this;
    }
}