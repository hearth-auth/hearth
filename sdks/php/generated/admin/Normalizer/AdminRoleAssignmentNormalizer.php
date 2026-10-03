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
class AdminRoleAssignmentNormalizer implements DenormalizerInterface, NormalizerInterface, DenormalizerAwareInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;
    use CheckArray;
    use ValidatorTrait;
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return $type === \Hearth\Generated\Admin\Model\AdminRoleAssignment::class;
    }
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return is_object($data) && get_class($data) === \Hearth\Generated\Admin\Model\AdminRoleAssignment::class;
    }
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        $object = new \Hearth\Generated\Admin\Model\AdminRoleAssignment();
        if (null === $data || false === \is_array($data)) {
            return $object;
        }
        if (isset($data['$ref']) && !isset($data['type']) && !isset($data['properties']) && !isset($data['allOf'])) {
            return new Reference($data['$ref'], $context['document-origin']);
        }
        if (isset($data['$recursiveRef'])) {
            return new Reference($data['$recursiveRef'], $context['document-origin']);
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
        if (\array_key_exists('subject', $data) && $data['subject'] !== null) {
            $object->setSubject($this->denormalizer->denormalize($data['subject'], \Hearth\Generated\Admin\Model\AdminSubject::class, 'json', $context));
            unset($data['subject']);
        }
        elseif (\array_key_exists('subject', $data) && $data['subject'] === null) {
            $object->setSubject(null);
            unset($data['subject']);
        }
        if (\array_key_exists('role_id', $data) && $data['role_id'] !== null) {
            $object->setRoleId($data['role_id']);
            unset($data['role_id']);
        }
        elseif (\array_key_exists('role_id', $data) && $data['role_id'] === null) {
            $object->setRoleId(null);
            unset($data['role_id']);
        }
        if (\array_key_exists('scope', $data) && $data['scope'] !== null) {
            $object->setScope($this->denormalizer->denormalize($data['scope'], \Hearth\Generated\Admin\Model\AdminAssignmentScope::class, 'json', $context));
            unset($data['scope']);
        }
        elseif (\array_key_exists('scope', $data) && $data['scope'] === null) {
            $object->setScope(null);
            unset($data['scope']);
        }
        if (\array_key_exists('assigned_at', $data) && $data['assigned_at'] !== null) {
            $object->setAssignedAt($data['assigned_at']);
            unset($data['assigned_at']);
        }
        elseif (\array_key_exists('assigned_at', $data) && $data['assigned_at'] === null) {
            $object->setAssignedAt(null);
            unset($data['assigned_at']);
        }
        if (\array_key_exists('assigned_by', $data) && $data['assigned_by'] !== null) {
            $object->setAssignedBy($data['assigned_by']);
            unset($data['assigned_by']);
        }
        elseif (\array_key_exists('assigned_by', $data) && $data['assigned_by'] === null) {
            $object->setAssignedBy(null);
            unset($data['assigned_by']);
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
        $dataArray['id'] = $data->getId();
        $dataArray['realm_id'] = $data->getRealmId();
        $dataArray['subject'] = $data->getSubject() === null ? null : new \Hearth\Generated\Admin\Runtime\JsonObject($this->normalizer->normalize($data->getSubject(), 'json', $context));
        $dataArray['role_id'] = $data->getRoleId();
        $dataArray['scope'] = $data->getScope() === null ? null : new \Hearth\Generated\Admin\Runtime\JsonObject($this->normalizer->normalize($data->getScope(), 'json', $context));
        $dataArray['assigned_at'] = $data->getAssignedAt();
        $dataArray['assigned_by'] = $data->getAssignedBy();
        foreach ($data->additionalPropertyEntries() as $key => $value) {
            if (preg_match('/.*/', (string) $key)) {
                $dataArray[$key] = $value;
            }
        }
        return $dataArray;
    }
    public function getSupportedTypes(?string $format = null): array
    {
        return [\Hearth\Generated\Admin\Model\AdminRoleAssignment::class => false];
    }
}