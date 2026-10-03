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
class V1AuditEventNormalizer implements DenormalizerInterface, NormalizerInterface, DenormalizerAwareInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;
    use CheckArray;
    use ValidatorTrait;
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return $type === \Hearth\Generated\Admin\Model\V1AuditEvent::class;
    }
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return is_object($data) && get_class($data) === \Hearth\Generated\Admin\Model\V1AuditEvent::class;
    }
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        $object = new \Hearth\Generated\Admin\Model\V1AuditEvent();
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
        if (\array_key_exists('realmId', $data) && $data['realmId'] !== null) {
            $object->setRealmId($data['realmId']);
            unset($data['realmId']);
        }
        elseif (\array_key_exists('realmId', $data) && $data['realmId'] === null) {
            $object->setRealmId(null);
            unset($data['realmId']);
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
        if (\array_key_exists('resourceType', $data) && $data['resourceType'] !== null) {
            $object->setResourceType($data['resourceType']);
            unset($data['resourceType']);
        }
        elseif (\array_key_exists('resourceType', $data) && $data['resourceType'] === null) {
            $object->setResourceType(null);
            unset($data['resourceType']);
        }
        if (\array_key_exists('resourceId', $data) && $data['resourceId'] !== null) {
            $object->setResourceId($data['resourceId']);
            unset($data['resourceId']);
        }
        elseif (\array_key_exists('resourceId', $data) && $data['resourceId'] === null) {
            $object->setResourceId(null);
            unset($data['resourceId']);
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
            $object->setMetadata($data['metadata']);
            unset($data['metadata']);
        }
        elseif (\array_key_exists('metadata', $data) && $data['metadata'] === null) {
            $object->setMetadata(null);
            unset($data['metadata']);
        }
        if (\array_key_exists('integrityHash', $data) && $data['integrityHash'] !== null) {
            $object->setIntegrityHash($data['integrityHash']);
            unset($data['integrityHash']);
        }
        elseif (\array_key_exists('integrityHash', $data) && $data['integrityHash'] === null) {
            $object->setIntegrityHash(null);
            unset($data['integrityHash']);
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
        if ($data->isInitialized('id') && null !== $data->getId()) {
            $dataArray['id'] = $data->getId();
        }
        if ($data->isInitialized('realmId') && null !== $data->getRealmId()) {
            $dataArray['realmId'] = $data->getRealmId();
        }
        if ($data->isInitialized('actor') && null !== $data->getActor()) {
            $dataArray['actor'] = $data->getActor();
        }
        if ($data->isInitialized('action') && null !== $data->getAction()) {
            $dataArray['action'] = $data->getAction();
        }
        if ($data->isInitialized('resourceType') && null !== $data->getResourceType()) {
            $dataArray['resourceType'] = $data->getResourceType();
        }
        if ($data->isInitialized('resourceId') && null !== $data->getResourceId()) {
            $dataArray['resourceId'] = $data->getResourceId();
        }
        if ($data->isInitialized('timestamp') && null !== $data->getTimestamp()) {
            $dataArray['timestamp'] = $data->getTimestamp();
        }
        if ($data->isInitialized('metadata') && null !== $data->getMetadata()) {
            $dataArray['metadata'] = $data->getMetadata();
        }
        if ($data->isInitialized('integrityHash') && null !== $data->getIntegrityHash()) {
            $dataArray['integrityHash'] = $data->getIntegrityHash();
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
        return [\Hearth\Generated\Admin\Model\V1AuditEvent::class => false];
    }
}