<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class V1Group implements AdditionalPropertiesInterface
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
    protected $id;
    /**
     * @var string|null
     */
    protected $realmId;
    /**
     * @var string|null
     */
    protected $name;
    /**
     * @var string|null
     */
    protected $slug;
    /**
     * @var string|null
     */
    protected $description;
    /**
     * @var string|null
     */
    protected $createdAtMicros;
    /**
     * @var string|null
     */
    protected $updatedAtMicros;
    /**
     * @return string|null
     */
    public function getId(): ?string
    {
        return $this->id;
    }
    /**
     * @param string|null $id
     *
     * @return self
     */
    public function setId(?string $id): self
    {
        $this->initialized['id'] = true;
        $this->id = $id;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getRealmId(): ?string
    {
        return $this->realmId;
    }
    /**
     * @param string|null $realmId
     *
     * @return self
     */
    public function setRealmId(?string $realmId): self
    {
        $this->initialized['realmId'] = true;
        $this->realmId = $realmId;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getName(): ?string
    {
        return $this->name;
    }
    /**
     * @param string|null $name
     *
     * @return self
     */
    public function setName(?string $name): self
    {
        $this->initialized['name'] = true;
        $this->name = $name;
        return $this;
    }
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
    public function getDescription(): ?string
    {
        return $this->description;
    }
    /**
     * @param string|null $description
     *
     * @return self
     */
    public function setDescription(?string $description): self
    {
        $this->initialized['description'] = true;
        $this->description = $description;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getCreatedAtMicros(): ?string
    {
        return $this->createdAtMicros;
    }
    /**
     * @param string|null $createdAtMicros
     *
     * @return self
     */
    public function setCreatedAtMicros(?string $createdAtMicros): self
    {
        $this->initialized['createdAtMicros'] = true;
        $this->createdAtMicros = $createdAtMicros;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getUpdatedAtMicros(): ?string
    {
        return $this->updatedAtMicros;
    }
    /**
     * @param string|null $updatedAtMicros
     *
     * @return self
     */
    public function setUpdatedAtMicros(?string $updatedAtMicros): self
    {
        $this->initialized['updatedAtMicros'] = true;
        $this->updatedAtMicros = $updatedAtMicros;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['id' => ['id', 'getId', 'setId'], 'realmId' => ['realmId', 'getRealmId', 'setRealmId'], 'name' => ['name', 'getName', 'setName'], 'slug' => ['slug', 'getSlug', 'setSlug'], 'description' => ['description', 'getDescription', 'setDescription'], 'createdAtMicros' => ['createdAtMicros', 'getCreatedAtMicros', 'setCreatedAtMicros'], 'updatedAtMicros' => ['updatedAtMicros', 'getUpdatedAtMicros', 'setUpdatedAtMicros']];
    }
}