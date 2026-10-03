<?php

namespace Hearth\Generated\Admin\Normalizer;

use Jane\Component\JsonSchemaRuntime\Reference;
use Hearth\Generated\Admin\Runtime\Normalizer\CheckArray;
use Hearth\Generated\Admin\Runtime\Normalizer\ValidatorTrait;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
class V1RealmConfigNormalizer implements DenormalizerInterface, NormalizerInterface, DenormalizerAwareInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;
    use CheckArray;
    use ValidatorTrait;
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return $type === \Hearth\Generated\Admin\Model\V1RealmConfig::class;
    }
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return is_object($data) && get_class($data) === \Hearth\Generated\Admin\Model\V1RealmConfig::class;
    }
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        $object = new \Hearth\Generated\Admin\Model\V1RealmConfig();
        if (null === $data || false === \is_array($data)) {
            return $object;
        }
        if (isset($data['$ref']) && !isset($data['type']) && !isset($data['properties']) && !isset($data['allOf'])) {
            return new Reference($data['$ref'], $context['document-origin']);
        }
        if (isset($data['$recursiveRef'])) {
            return new Reference($data['$recursiveRef'], $context['document-origin']);
        }
        if (\array_key_exists('session_ttl_micros', $data) && $data['session_ttl_micros'] !== null) {
            $object->setSessionTtlMicros($data['session_ttl_micros']);
            unset($data['session_ttl_micros']);
        }
        elseif (\array_key_exists('session_ttl_micros', $data) && $data['session_ttl_micros'] === null) {
            $object->setSessionTtlMicros(null);
            unset($data['session_ttl_micros']);
        }
        if (\array_key_exists('password_memory_cost', $data) && $data['password_memory_cost'] !== null) {
            $object->setPasswordMemoryCost($data['password_memory_cost']);
            unset($data['password_memory_cost']);
        }
        elseif (\array_key_exists('password_memory_cost', $data) && $data['password_memory_cost'] === null) {
            $object->setPasswordMemoryCost(null);
            unset($data['password_memory_cost']);
        }
        if (\array_key_exists('password_time_cost', $data) && $data['password_time_cost'] !== null) {
            $object->setPasswordTimeCost($data['password_time_cost']);
            unset($data['password_time_cost']);
        }
        elseif (\array_key_exists('password_time_cost', $data) && $data['password_time_cost'] === null) {
            $object->setPasswordTimeCost(null);
            unset($data['password_time_cost']);
        }
        foreach ($data as $key => $value) {
            if (preg_match('/.*/', (string) $key)) {
                $object[$key] = $value;
            }
        }
        return $object;
    }
    public function normalize(mixed $data, ?string $format = null, array $context = []): array|string|int|float|bool|\ArrayObject|null
    {
        $dataArray = [];
        if ($data->isInitialized('sessionTtlMicros') && null !== $data->getSessionTtlMicros()) {
            $dataArray['session_ttl_micros'] = $data->getSessionTtlMicros();
        }
        if ($data->isInitialized('passwordMemoryCost') && null !== $data->getPasswordMemoryCost()) {
            $dataArray['password_memory_cost'] = $data->getPasswordMemoryCost();
        }
        if ($data->isInitialized('passwordTimeCost') && null !== $data->getPasswordTimeCost()) {
            $dataArray['password_time_cost'] = $data->getPasswordTimeCost();
        }
        foreach ($data->additionalPropertyEntries() as $key => $value) {
            if (preg_match('/.*/', (string) $key)) {
                $dataArray[$key] = $value;
            }
        }
        return $dataArray;
    }
    public function getSupportedTypes(?string $format = null): array
    {
        return [\Hearth\Generated\Admin\Model\V1RealmConfig::class => false];
    }
}