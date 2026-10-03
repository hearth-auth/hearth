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
class V1ListGroupMembersResponseNormalizer implements DenormalizerInterface, NormalizerInterface, DenormalizerAwareInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;
    use CheckArray;
    use ValidatorTrait;
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return $type === \Hearth\Generated\Admin\Model\V1ListGroupMembersResponse::class;
    }
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return is_object($data) && get_class($data) === \Hearth\Generated\Admin\Model\V1ListGroupMembersResponse::class;
    }
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        $object = new \Hearth\Generated\Admin\Model\V1ListGroupMembersResponse();
        if (null === $data || false === \is_array($data)) {
            return $object;
        }
        if (isset($data['$ref']) && !isset($data['type']) && !isset($data['properties']) && !isset($data['allOf'])) {
            return new Reference($data['$ref'], $context['document-origin']);
        }
        if (isset($data['$recursiveRef'])) {
            return new Reference($data['$recursiveRef'], $context['document-origin']);
        }
        if (\array_key_exists('members', $data) && $data['members'] !== null) {
            $values = [];
            foreach ($data['members'] as $value) {
                $values[] = $this->denormalizer->denormalize($value, \Hearth\Generated\Admin\Model\V1GroupMember::class, 'json', $context);
            }
            $object->setMembers($values);
            unset($data['members']);
        }
        elseif (\array_key_exists('members', $data) && $data['members'] === null) {
            $object->setMembers(null);
            unset($data['members']);
        }
        if (\array_key_exists('nextCursor', $data) && $data['nextCursor'] !== null) {
            $object->setNextCursor($data['nextCursor']);
            unset($data['nextCursor']);
        }
        elseif (\array_key_exists('nextCursor', $data) && $data['nextCursor'] === null) {
            $object->setNextCursor(null);
            unset($data['nextCursor']);
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
        if ($data->isInitialized('members') && null !== $data->getMembers()) {
            $values = [];
            foreach ($data->getMembers() as $value) {
                $values[] = $value === null ? null : new \Hearth\Generated\Admin\Runtime\JsonObject($this->normalizer->normalize($value, 'json', $context));
            }
            $dataArray['members'] = $values;
        }
        if ($data->isInitialized('nextCursor') && null !== $data->getNextCursor()) {
            $dataArray['nextCursor'] = $data->getNextCursor();
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
        return [\Hearth\Generated\Admin\Model\V1ListGroupMembersResponse::class => false];
    }
}