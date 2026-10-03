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
class AdminAuditEventNormalizer implements DenormalizerInterface, NormalizerInterface, DenormalizerAwareInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;
    use CheckArray;
    use ValidatorTrait;
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return $type === \Hearth\Generated\Admin\Model\AdminAuditEvent::class;
    }
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return is_object($data) && get_class($data) === \Hearth\Generated\Admin\Model\AdminAuditEvent::class;
    }
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        $object = new \Hearth\Generated\Admin\Model\AdminAuditEvent();
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
        if (\array_key_exists('actor', $data) && $data['actor'] !== null) {
            $object->setActor($data['actor']);
            unset($data['actor']);
        }
        elseif (\array_key_exists('actor', $data) && $data['actor'] === null) {
            $object->setActor(null);
            unset($data['actor']);
        }
        if (\array_key_exists('action', $data) && $data['action'] !== null) {
            $object->setAction($data['action']);
            unset($data['action']);
        }
        elseif (\array_key_exists('action', $data) && $data['action'] === null) {
            $object->setAction(null);
            unset($data['action']);
        }
        if (\array_key_exists('resource_type', $data) && $data['resource_type'] !== null) {
            $object->setResourceType($data['resource_type']);
            unset($data['resource_type']);
        }
        elseif (\array_key_exists('resource_type', $data) && $data['resource_type'] === null) {
            $object->setResourceType(null);
            unset($data['resource_type']);
        }
        if (\array_key_exists('resource_id', $data) && $data['resource_id'] !== null) {
            $object->setResourceId($data['resource_id']);
            unset($data['resource_id']);
        }
        elseif (\array_key_exists('resource_id', $data) && $data['resource_id'] === null) {
            $object->setResourceId(null);
            unset($data['resource_id']);
        }
        if (\array_key_exists('timestamp', $data) && $data['timestamp'] !== null) {
            $object->setTimestamp($data['timestamp']);
            unset($data['timestamp']);
        }
        elseif (\array_key_exists('timestamp', $data) && $data['timestamp'] === null) {
            $object->setTimestamp(null);
            unset($data['timestamp']);
        }
        if (\array_key_exists('metadata', $data) && $data['metadata'] !== null) {
            $values = new \Hearth\Generated\Admin\Runtime\JsonObject();
            foreach ($data['metadata'] as $key => $value) {
                $values[$key] = $value;
            }
            $object->setMetadata($values);
            unset($data['metadata']);
        }
        elseif (\array_key_exists('metadata', $data) && $data['metadata'] === null) {
            $object->setMetadata(null);
            unset($data['metadata']);
        }
        if (\array_key_exists('integrity_hash', $data) && $data['integrity_hash'] !== null) {
            $object->setIntegrityHash($data['integrity_hash']);
            unset($data['integrity_hash']);
        }
        elseif (\array_key_exists('integrity_hash', $data) && $data['integrity_hash'] === null) {
            $object->setIntegrityHash(null);
            unset($data['integrity_hash']);
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
        $dataArray['id'] = $data->getId();
        $dataArray['realm_id'] = $data->getRealmId();
        $dataArray['actor'] = $data->getActor();
        $dataArray['action'] = $data->getAction();
        $dataArray['resource_type'] = $data->getResourceType();
        $dataArray['resource_id'] = $data->getResourceId();
        $dataArray['timestamp'] = $data->getTimestamp();
        if ($data->isInitialized('metadata') && null !== $data->getMetadata()) {
            $values = new \Hearth\Generated\Admin\Runtime\JsonObject();
            foreach ($data->getMetadata() as $key => $value) {
                $values[$key] = $value;
            }
            $dataArray['metadata'] = $values;
        }
        $dataArray['integrity_hash'] = $data->getIntegrityHash();
        foreach ($data->additionalPropertyEntries() as $key_1 => $value_1) {
            if (preg_match('/.*/', (string) $key_1)) {
                $dataArray[$key_1] = $value_1;
            }
        }
        return $dataArray;
    }
    public function getSupportedTypes(?string $format = null): array
    {
        return [\Hearth\Generated\Admin\Model\AdminAuditEvent::class => false];
    }
}