<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class V1ListRolesResponse implements AdditionalPropertiesInterface
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
     * @var list<V1Role>|null
     */
    protected $roles;
    /**
     * @var string|null
     */
    protected $nextCursor;
    /**
     * @return list<V1Role>|null
     */
    public function getRoles(): ?array
    {
        return $this->roles;
    }
    /**
     * @param list<V1Role>|null $roles
     *
     * @return self
     */
    public function setRoles(?array $roles): self
    {
        $this->initialized['roles'] = true;
        $this->roles = $roles;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getNextCursor(): ?string
    {
        return $this->nextCursor;
    }
    /**
     * @param string|null $nextCursor
     *
     * @return self
     */
    public function setNextCursor(?string $nextCursor): self
    {
        $this->initialized['nextCursor'] = true;
        $this->nextCursor = $nextCursor;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['roles' => ['roles', 'getRoles', 'setRoles'], 'nextCursor' => ['nextCursor', 'getNextCursor', 'setNextCursor']];
    }
}