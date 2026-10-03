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
class V1ScopeNormalizer implements DenormalizerInterface, NormalizerInterface, DenormalizerAwareInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;
    use CheckArray;
    use ValidatorTrait;
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return $type === \Hearth\Generated\Admin\Model\V1Scope::class;
    }
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return is_object($data) && get_class($data) === \Hearth\Generated\Admin\Model\V1Scope::class;
    }
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        $object = new \Hearth\Generated\Admin\Model\V1Scope();
        if (null === $data || false === \is_array($data)) {
            return $object;
        }
        if (isset($data['$ref']) && !isset($data['type']) && !isset($data['properties']) && !isset($data['allOf'])) {
            return new Reference($data['$ref'], $context['document-origin']);
        }
        if (isset($data['$recursiveRef'])) {
            return new Reference($data['$recursiveRef'], $context['document-origin']);
        }
        if (\array_key_exists('realm', $data) && $data['realm'] !== null) {
            $values = new \Hearth\Generated\Admin\Runtime\JsonObject();
            foreach ($data['realm'] as $key => $value) {
                $values[$key] = $value;
            }
            $object->setRealm($values);
            unset($data['realm']);
        }
        elseif (\array_key_exists('realm', $data) && $data['realm'] === null) {
            $object->setRealm(null);
            unset($data['realm']);
        }
        if (\array_key_exists('org', $data) && $data['org'] !== null) {
            $object->setOrg($this->denormalizer->denormalize($data['org'], \Hearth\Generated\Admin\Model\V1OrgScope::class, 'json', $context));
            unset($data['org']);
        }
        elseif (\array_key_exists('org', $data) && $data['org'] === null) {
            $object->setOrg(null);
            unset($data['org']);
        }
        foreach ($data as $key_1 => $value_1) {
            if (preg_match('/.*/', (string) $key_1)) {
                $object[$key_1] = $value_1;
            }
        }
        return $object;
    }
    public function normalize(mixed $data, ?string $format = null, array $context = []): array|string|int|float|bool|\ArrayObject|null
    {
        $dataArray = [];
        if ($data->isInitialized('realm') && null !== $data->getRealm()) {
            $values = new \Hearth\Generated\Admin\Runtime\JsonObject();
            foreach ($data->getRealm() as $key => $value) {
                $values[$key] = $value;
            }
            $dataArray['realm'] = $values;
        }
        if ($data->isInitialized('org') && null !== $data->getOrg()) {
            $dataArray['org'] = $data->getOrg() === null ? null : new \Hearth\Generated\Admin\Runtime\JsonObject($this->normalizer->normalize($data->getOrg(), 'json', $context));
        }
        foreach ($data->additionalPropertyEntries() as $key_1 => $value_1) {
            if (preg_match('/.*/', (string) $key_1)) {
                $dataArray[$key_1] = $value_1;
            }
        }
        return $dataArray;
    }
    public function getSupportedTypes(?string $format = null): array
    {
        return [\Hearth\Generated\Admin\Model\V1Scope::class => false];
    }
}