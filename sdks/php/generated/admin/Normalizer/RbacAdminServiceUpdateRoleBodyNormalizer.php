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
class RbacAdminServiceUpdateRoleBodyNormalizer implements DenormalizerInterface, NormalizerInterface, DenormalizerAwareInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;
    use CheckArray;
    use ValidatorTrait;
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return $type === \Hearth\Generated\Admin\Model\RbacAdminServiceUpdateRoleBody::class;
    }
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return is_object($data) && get_class($data) === \Hearth\Generated\Admin\Model\RbacAdminServiceUpdateRoleBody::class;
    }
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        $object = new \Hearth\Generated\Admin\Model\RbacAdminServiceUpdateRoleBody();
        if (null === $data || false === \is_array($data)) {
            return $object;
        }
        if (isset($data['$ref']) && !isset($data['type']) && !isset($data['properties']) && !isset($data['allOf'])) {
            return new Reference($data['$ref'], $context['document-origin']);
        }
        if (isset($data['$recursiveRef'])) {
            return new Reference($data['$recursiveRef'], $context['document-origin']);
        }
        if (\array_key_exists('realmId', $data) && $data['realmId'] !== null) {
            $object->setRealmId($data['realmId']);
            unset($data['realmId']);
        }
        elseif (\array_key_exists('realmId', $data) && $data['realmId'] === null) {
            $object->setRealmId(null);
            unset($data['realmId']);
        }
        if (\array_key_exists('name', $data) && $data['name'] !== null) {
            $object->setName($data['name']);
            unset($data['name']);
        }
        elseif (\array_key_exists('name', $data) && $data['name'] === null) {
            $object->setName(null);
            unset($data['name']);
        }
        if (\array_key_exists('description', $data) && $data['description'] !== null) {
            $object->setDescription($data['description']);
            unset($data['description']);
        }
        elseif (\array_key_exists('description', $data) && $data['description'] === null) {
            $object->setDescription(null);
            unset($data['description']);
        }
        if (\array_key_exists('permissions', $data) && $data['permissions'] !== null) {
            $values = [];
            foreach ($data['permissions'] as $value) {
                $values[] = $value;
            }
            $object->setPermissions($values);
            unset($data['permissions']);
        }
        elseif (\array_key_exists('permissions', $data) && $data['permissions'] === null) {
            $object->setPermissions(null);
            unset($data['permissions']);
        }
        if (\array_key_exists('parentRoleIds', $data) && $data['parentRoleIds'] !== null) {
            $values_1 = [];
            foreach ($data['parentRoleIds'] as $value_1) {
                $values_1[] = $value_1;
            }
            $object->setParentRoleIds($values_1);
            unset($data['parentRoleIds']);
        }
        elseif (\array_key_exists('parentRoleIds', $data) && $data['parentRoleIds'] === null) {
            $object->setParentRoleIds(null);
            unset($data['parentRoleIds']);
        }
        foreach ($data as $key => $value_2) {
            if (preg_match('/.*/', (string) $key)) {
                $object[$key] = $value_2;
            }
        }
        return $object;
    }
    public function normalize(mixed $data, ?string $format = null, array $context = []): array|string|int|float|bool|\ArrayObject|null
    {
        $dataArray = [];
        if ($data->isInitialized('realmId') && null !== $data->getRealmId()) {
            $dataArray['realmId'] = $data->getRealmId();
        }
        if ($data->isInitialized('name') && null !== $data->getName()) {
            $dataArray['name'] = $data->getName();
        }
        if ($data->isInitialized('description') && null !== $data->getDescription()) {
            $dataArray['description'] = $data->getDescription();
        }
        if ($data->isInitialized('permissions') && null !== $data->getPermissions()) {
            $values = [];
            foreach ($data->getPermissions() as $value) {
                $values[] = $value;
            }
            $dataArray['permissions'] = $values;
        }
        if ($data->isInitialized('parentRoleIds') && null !== $data->getParentRoleIds()) {
            $values_1 = [];
            foreach ($data->getParentRoleIds() as $value_1) {
                $values_1[] = $value_1;
            }
            $dataArray['parentRoleIds'] = $values_1;
        }
        foreach ($data->additionalPropertyEntries() as $key => $value_2) {
            if (preg_match('/.*/', (string) $key)) {
                $dataArray[$key] = $value_2;
            }
        }
        return $dataArray;
    }
    public function getSupportedTypes(?string $format = null): array
    {
        return [\Hearth\Generated\Admin\Model\RbacAdminServiceUpdateRoleBody::class => false];
    }
}