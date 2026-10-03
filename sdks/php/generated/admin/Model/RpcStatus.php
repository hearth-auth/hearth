<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class RpcStatus implements AdditionalPropertiesInterface
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
     * @var int|null
     */
    protected $code;
    /**
     * @var string|null
     */
    protected $message;
    /**
     * @var list<ProtobufAny>|null
     */
    protected $details;
    /**
     * @return int|null
     */
    public function getCode(): ?int
    {
        return $this->code;
    }
    /**
     * @param int|null $code
     *
     * @return self
     */
    public function setCode(?int $code): self
    {
        $this->initialized['code'] = true;
        $this->code = $code;
        return $this;
    }
    /**
     * @return string|null
     */
    public function getMessage(): ?string
    {
        return $this->message;
    }
    /**
     * @param string|null $message
     *
     * @return self
     */
    public function setMessage(?string $message): self
    {
        $this->initialized['message'] = true;
        $this->message = $message;
        return $this;
    }
    /**
     * @return list<ProtobufAny>|null
     */
    public function getDetails(): ?array
    {
        return $this->details;
    }
    /**
     * @param list<ProtobufAny>|null $details
     *
     * @return self
     */
    public function setDetails(?array $details): self
    {
        $this->initialized['details'] = true;
        $this->details = $details;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['code' => ['code', 'getCode', 'setCode'], 'message' => ['message', 'getMessage', 'setMessage'], 'details' => ['details', 'getDetails', 'setDetails']];
    }
}