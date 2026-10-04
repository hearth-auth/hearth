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
class V1ConsentEntryNormalizer implements DenormalizerInterface, NormalizerInterface, DenormalizerAwareInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;
    use CheckArray;
    use ValidatorTrait;
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return $type === \Hearth\Generated\Admin\Model\V1ConsentEntry::class;
    }
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return is_object($data) && get_class($data) === \Hearth\Generated\Admin\Model\V1ConsentEntry::class;
    }
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        $object = new \Hearth\Generated\Admin\Model\V1ConsentEntry();
        if (null === $data || false === \is_array($data)) {
            return $object;
        }
        if (isset($data['$ref']) && !isset($data['type']) && !isset($data['properties']) && !isset($data['allOf'])) {
            return new Reference($data['$ref'], $context['document-origin']);
        }
        if (isset($data['$recursiveRef'])) {
            return new Reference($data['$recursiveRef'], $context['document-origin']);
        }
        if (\array_key_exists('client_id', $data) && $data['client_id'] !== null) {
            $object->setClientId($data['client_id']);
            unset($data['client_id']);
        }
        elseif (\array_key_exists('client_id', $data) && $data['client_id'] === null) {
            $object->setClientId(null);
            unset($data['client_id']);
        }
        if (\array_key_exists('client_name', $data) && $data['client_name'] !== null) {
            $object->setClientName($data['client_name']);
            unset($data['client_name']);
        }
        elseif (\array_key_exists('client_name', $data) && $data['client_name'] === null) {
            $object->setClientName(null);
            unset($data['client_name']);
        }
        if (\array_key_exists('granted_scopes', $data) && $data['granted_scopes'] !== null) {
            $values = [];
            foreach ($data['granted_scopes'] as $value) {
                $values[] = $value;
            }
            $object->setGrantedScopes($values);
            unset($data['granted_scopes']);
        }
        elseif (\array_key_exists('granted_scopes', $data) && $data['granted_scopes'] === null) {
            $object->setGrantedScopes(null);
            unset($data['granted_scopes']);
        }
        if (\array_key_exists('granted_at', $data) && $data['granted_at'] !== null) {
            $object->setGrantedAt($data['granted_at']);
            unset($data['granted_at']);
        }
        elseif (\array_key_exists('granted_at', $data) && $data['granted_at'] === null) {
            $object->setGrantedAt(null);
            unset($data['granted_at']);
        }
        if (\array_key_exists('updated_at', $data) && $data['updated_at'] !== null) {
            $object->setUpdatedAt($data['updated_at']);
            unset($data['updated_at']);
        }
        elseif (\array_key_exists('updated_at', $data) && $data['updated_at'] === null) {
            $object->setUpdatedAt(null);
            unset($data['updated_at']);
        }
        foreach ($data as $key => $value_1) {
            if (preg_match('/.*/', (string) $key)) {
                $object[$key] = $value_1;
            }
        }
        return $object;
    }
    public function normalize(mixed $data, ?string $format = null, array $context = []): array|string|int|float|bool|\ArrayObject|null
    {
        $dataArray = [];
        if ($data->isInitialized('clientId') && null !== $data->getClientId()) {
            $dataArray['client_id'] = $data->getClientId();
        }
        if ($data->isInitialized('clientName') && null !== $data->getClientName()) {
            $dataArray['client_name'] = $data->getClientName();
        }
        if ($data->isInitialized('grantedScopes') && null !== $data->getGrantedScopes()) {
            $values = [];
            foreach ($data->getGrantedScopes() as $value) {
                $values[] = $value;
            }
            $dataArray['granted_scopes'] = $values;
        }
        if ($data->isInitialized('grantedAt') && null !== $data->getGrantedAt()) {
            $dataArray['granted_at'] = $data->getGrantedAt();
        }
        if ($data->isInitialized('updatedAt') && null !== $data->getUpdatedAt()) {
            $dataArray['updated_at'] = $data->getUpdatedAt();
        }
        foreach ($data->additionalPropertyEntries() as $key => $value_1) {
            if (preg_match('/.*/', (string) $key)) {
                $dataArray[$key] = $value_1;
            }
        }
        return $dataArray;
    }
    public function getSupportedTypes(?string $format = null): array
    {
        return [\Hearth\Generated\Admin\Model\V1ConsentEntry::class => false];
    }
}