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
class V1GroupMembershipNormalizer implements DenormalizerInterface, NormalizerInterface, DenormalizerAwareInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;
    use CheckArray;
    use ValidatorTrait;
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return $type === \Hearth\Generated\Admin\Model\V1GroupMembership::class;
    }
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return is_object($data) && get_class($data) === \Hearth\Generated\Admin\Model\V1GroupMembership::class;
    }
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        $object = new \Hearth\Generated\Admin\Model\V1GroupMembership();
        if (null === $data || false === \is_array($data)) {
            return $object;
        }
        if (isset($data['$ref']) && !isset($data['type']) && !isset($data['properties']) && !isset($data['allOf'])) {
            return new Reference($data['$ref'], $context['document-origin']);
        }
        if (isset($data['$recursiveRef'])) {
            return new Reference($data['$recursiveRef'], $context['document-origin']);
        }
        if (\array_key_exists('groupId', $data) && $data['groupId'] !== null) {
            $object->setGroupId($data['groupId']);
            unset($data['groupId']);
        }
        elseif (\array_key_exists('groupId', $data) && $data['groupId'] === null) {
            $object->setGroupId(null);
            unset($data['groupId']);
        }
        if (\array_key_exists('member', $data) && $data['member'] !== null) {
            $object->setMember($this->denormalizer->denormalize($data['member'], \Hearth\Generated\Admin\Model\V1GroupMember::class, 'json', $context));
            unset($data['member']);
        }
        elseif (\array_key_exists('member', $data) && $data['member'] === null) {
            $object->setMember(null);
            unset($data['member']);
        }
        if (\array_key_exists('addedAtMicros', $data) && $data['addedAtMicros'] !== null) {
            $object->setAddedAtMicros($data['addedAtMicros']);
            unset($data['addedAtMicros']);
        }
        elseif (\array_key_exists('addedAtMicros', $data) && $data['addedAtMicros'] === null) {
            $object->setAddedAtMicros(null);
            unset($data['addedAtMicros']);
        }
        if (\array_key_exists('addedByUserId', $data) && $data['addedByUserId'] !== null) {
            $object->setAddedByUserId($data['addedByUserId']);
            unset($data['addedByUserId']);
        }
        elseif (\array_key_exists('addedByUserId', $data) && $data['addedByUserId'] === null) {
            $object->setAddedByUserId(null);
            unset($data['addedByUserId']);
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
        if ($data->isInitialized('groupId') && null !== $data->getGroupId()) {
            $dataArray['groupId'] = $data->getGroupId();
        }
        if ($data->isInitialized('member') && null !== $data->getMember()) {
            $dataArray['member'] = $data->getMember() === null ? null : new \Hearth\Generated\Admin\Runtime\JsonObject($this->normalizer->normalize($data->getMember(), 'json', $context));
        }
        if ($data->isInitialized('addedAtMicros') && null !== $data->getAddedAtMicros()) {
            $dataArray['addedAtMicros'] = $data->getAddedAtMicros();
        }
        if ($data->isInitialized('addedByUserId') && null !== $data->getAddedByUserId()) {
            $dataArray['addedByUserId'] = $data->getAddedByUserId();
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
        return [\Hearth\Generated\Admin\Model\V1GroupMembership::class => false];
    }
}