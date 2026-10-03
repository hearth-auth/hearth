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
class AdminGroupMembershipNormalizer implements DenormalizerInterface, NormalizerInterface, DenormalizerAwareInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;
    use CheckArray;
    use ValidatorTrait;
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return $type === \Hearth\Generated\Admin\Model\AdminGroupMembership::class;
    }
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return is_object($data) && get_class($data) === \Hearth\Generated\Admin\Model\AdminGroupMembership::class;
    }
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        $object = new \Hearth\Generated\Admin\Model\AdminGroupMembership();
        if (null === $data || false === \is_array($data)) {
            return $object;
        }
        if (isset($data['$ref']) && !isset($data['type']) && !isset($data['properties']) && !isset($data['allOf'])) {
            return new Reference($data['$ref'], $context['document-origin']);
        }
        if (isset($data['$recursiveRef'])) {
            return new Reference($data['$recursiveRef'], $context['document-origin']);
        }
        if (\array_key_exists('group_id', $data) && $data['group_id'] !== null) {
            $object->setGroupId($data['group_id']);
            unset($data['group_id']);
        }
        elseif (\array_key_exists('group_id', $data) && $data['group_id'] === null) {
            $object->setGroupId(null);
            unset($data['group_id']);
        }
        if (\array_key_exists('member', $data) && $data['member'] !== null) {
            $object->setMember($this->denormalizer->denormalize($data['member'], \Hearth\Generated\Admin\Model\AdminSubject::class, 'json', $context));
            unset($data['member']);
        }
        elseif (\array_key_exists('member', $data) && $data['member'] === null) {
            $object->setMember(null);
            unset($data['member']);
        }
        if (\array_key_exists('added_at', $data) && $data['added_at'] !== null) {
            $object->setAddedAt($data['added_at']);
            unset($data['added_at']);
        }
        elseif (\array_key_exists('added_at', $data) && $data['added_at'] === null) {
            $object->setAddedAt(null);
            unset($data['added_at']);
        }
        if (\array_key_exists('added_by', $data) && $data['added_by'] !== null) {
            $object->setAddedBy($data['added_by']);
            unset($data['added_by']);
        }
        elseif (\array_key_exists('added_by', $data) && $data['added_by'] === null) {
            $object->setAddedBy(null);
            unset($data['added_by']);
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
        $dataArray['group_id'] = $data->getGroupId();
        $dataArray['member'] = $data->getMember() === null ? null : new \Hearth\Generated\Admin\Runtime\JsonObject($this->normalizer->normalize($data->getMember(), 'json', $context));
        $dataArray['added_at'] = $data->getAddedAt();
        $dataArray['added_by'] = $data->getAddedBy();
        foreach ($data->additionalPropertyEntries() as $key => $value) {
            if (preg_match('/.*/', (string) $key)) {
                $dataArray[$key] = $value;
            }
        }
        return $dataArray;
    }
    public function getSupportedTypes(?string $format = null): array
    {
        return [\Hearth\Generated\Admin\Model\AdminGroupMembership::class => false];
    }
}