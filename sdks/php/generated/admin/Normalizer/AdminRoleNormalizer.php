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
class AdminRoleNormalizer implements DenormalizerInterface, NormalizerInterface, DenormalizerAwareInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;
    use CheckArray;
    use ValidatorTrait;
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return $type === \Hearth\Generated\Admin\Model\AdminRole::class;
    }
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return is_object($data) && get_class($data) === \Hearth\Generated\Admin\Model\AdminRole::class;
    }
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        $object = new \Hearth\Generated\Admin\Model\AdminRole();
        if (null === $data || false === \is_array($data)) {
            return $object;
        }
        if (isset($data['$ref']) && !isset($data['type']) && !isset($data['properties']) && !isset($data['allOf'])) {
            return new Reference($data['$ref'], $context['document-origin']);
        }
        if (isset($data['$recursiveRef'])) {
            return new Reference($data['$recursiveRef'], $context['document-origin']);
        }
        if (\array_key_exists('yaml_managed', $data) && \is_int($data['yaml_managed'])) {
            $data['yaml_managed'] = (bool) $data['yaml_managed'];
        }
        if (\array_key_exists('id', $data) && $data['id'] !== null) {
            $object->setId($data['id']);
            unset($data['id']);
        }
        elseif (\array_key_exists('id', $data) && $data['id'] === null) {
            $object->setId(null);
            unset($data['id']);
        }
        if (\array_key_exists('realm_id', $data) && $data['realm_id'] !== null) {
            $object->setRealmId($data['realm_id']);
            unset($data['realm_id']);
        }
        elseif (\array_key_exists('realm_id', $data) && $data['realm_id'] === null) {
            $object->setRealmId(null);
            unset($data['realm_id']);
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
        if (\array_key_exists('parent_roles', $data) && $data['parent_roles'] !== null) {
            $values_1 = [];
            foreach ($data['parent_roles'] as $value_1) {
                $values_1[] = $value_1;
            }
            $object->setParentRoles($values_1);
            unset($data['parent_roles']);
        }
        elseif (\array_key_exists('parent_roles', $data) && $data['parent_roles'] === null) {
            $object->setParentRoles(null);
            unset($data['parent_roles']);
        }
        if (\array_key_exists('scope_kind', $data) && $data['scope_kind'] !== null) {
            $object->setScopeKind($data['scope_kind']);
            unset($data['scope_kind']);
        }
        elseif (\array_key_exists('scope_kind', $data) && $data['scope_kind'] === null) {
            $object->setScopeKind(null);
            unset($data['scope_kind']);
        }
        if (\array_key_exists('status', $data) && $data['status'] !== null) {
            $object->setStatus($data['status']);
            unset($data['status']);
        }
        elseif (\array_key_exists('status', $data) && $data['status'] === null) {
            $object->setStatus(null);
            unset($data['status']);
        }
        if (\array_key_exists('yaml_managed', $data) && $data['yaml_managed'] !== null) {
            $object->setYamlManaged($data['yaml_managed']);
            unset($data['yaml_managed']);
        }
        elseif (\array_key_exists('yaml_managed', $data) && $data['yaml_managed'] === null) {
            $object->setYamlManaged(null);
            unset($data['yaml_managed']);
        }
        if (\array_key_exists('created_at', $data) && $data['created_at'] !== null) {
            $object->setCreatedAt($data['created_at']);
            unset($data['created_at']);
        }
        elseif (\array_key_exists('created_at', $data) && $data['created_at'] === null) {
            $object->setCreatedAt(null);
            unset($data['created_at']);
        }
        if (\array_key_exists('updated_at', $data) && $data['updated_at'] !== null) {
            $object->setUpdatedAt($data['updated_at']);
            unset($data['updated_at']);
        }
        elseif (\array_key_exists('updated_at', $data) && $data['updated_at'] === null) {
            $object->setUpdatedAt(null);
            unset($data['updated_at']);
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
        $dataArray['id'] = $data->getId();
        $dataArray['realm_id'] = $data->getRealmId();
        $dataArray['name'] = $data->getName();
        $dataArray['description'] = $data->getDescription();
        $values = [];
        foreach ($data->getPermissions() as $value) {
            $values[] = $value;
        }
        $dataArray['permissions'] = $values;
        $values_1 = [];
        foreach ($data->getParentRoles() as $value_1) {
            $values_1[] = $value_1;
        }
        $dataArray['parent_roles'] = $values_1;
        $dataArray['scope_kind'] = $data->getScopeKind();
        $dataArray['status'] = $data->getStatus();
        $dataArray['yaml_managed'] = $data->getYamlManaged();
        $dataArray['created_at'] = $data->getCreatedAt();
        $dataArray['updated_at'] = $data->getUpdatedAt();
        foreach ($data->additionalPropertyEntries() as $key => $value_2) {
            if (preg_match('/.*/', (string) $key)) {
                $dataArray[$key] = $value_2;
            }
        }
        return $dataArray;
    }
    public function getSupportedTypes(?string $format = null): array
    {
        return [\Hearth\Generated\Admin\Model\AdminRole::class => false];
    }
}