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
        if (\array_key_exists('sessionTtlMicros', $data) && $data['sessionTtlMicros'] !== null) {
            $object->setSessionTtlMicros($data['sessionTtlMicros']);
            unset($data['sessionTtlMicros']);
        }
        elseif (\array_key_exists('sessionTtlMicros', $data) && $data['sessionTtlMicros'] === null) {
            $object->setSessionTtlMicros(null);
            unset($data['sessionTtlMicros']);
        }
        if (\array_key_exists('passwordMemoryCost', $data) && $data['passwordMemoryCost'] !== null) {
            $object->setPasswordMemoryCost($data['passwordMemoryCost']);
            unset($data['passwordMemoryCost']);
        }
        elseif (\array_key_exists('passwordMemoryCost', $data) && $data['passwordMemoryCost'] === null) {
            $object->setPasswordMemoryCost(null);
            unset($data['passwordMemoryCost']);
        }
        if (\array_key_exists('passwordTimeCost', $data) && $data['passwordTimeCost'] !== null) {
            $object->setPasswordTimeCost($data['passwordTimeCost']);
            unset($data['passwordTimeCost']);
        }
        elseif (\array_key_exists('passwordTimeCost', $data) && $data['passwordTimeCost'] === null) {
            $object->setPasswordTimeCost(null);
            unset($data['passwordTimeCost']);
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
            $dataArray['sessionTtlMicros'] = $data->getSessionTtlMicros();
        }
        if ($data->isInitialized('passwordMemoryCost') && null !== $data->getPasswordMemoryCost()) {
            $dataArray['passwordMemoryCost'] = $data->getPasswordMemoryCost();
        }
        if ($data->isInitialized('passwordTimeCost') && null !== $data->getPasswordTimeCost()) {
            $dataArray['passwordTimeCost'] = $data->getPasswordTimeCost();
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