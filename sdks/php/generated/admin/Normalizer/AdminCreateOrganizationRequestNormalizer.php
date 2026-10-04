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
class AdminCreateOrganizationRequestNormalizer implements DenormalizerInterface, NormalizerInterface, DenormalizerAwareInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;
    use CheckArray;
    use ValidatorTrait;
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return $type === \Hearth\Generated\Admin\Model\AdminCreateOrganizationRequest::class;
    }
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return is_object($data) && get_class($data) === \Hearth\Generated\Admin\Model\AdminCreateOrganizationRequest::class;
    }
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        $object = new \Hearth\Generated\Admin\Model\AdminCreateOrganizationRequest();
        if (null === $data || false === \is_array($data)) {
            return $object;
        }
        if (isset($data['$ref']) && !isset($data['type']) && !isset($data['properties']) && !isset($data['allOf'])) {
            return new Reference($data['$ref'], $context['document-origin']);
        }
        if (isset($data['$recursiveRef'])) {
            return new Reference($data['$recursiveRef'], $context['document-origin']);
        }
        if (\array_key_exists('mfa_required', $data) && \is_int($data['mfa_required'])) {
            $data['mfa_required'] = (bool) $data['mfa_required'];
        }
        if (\array_key_exists('slug', $data) && $data['slug'] !== null) {
            $object->setSlug($data['slug']);
            unset($data['slug']);
        }
        elseif (\array_key_exists('slug', $data) && $data['slug'] === null) {
            $object->setSlug(null);
            unset($data['slug']);
        }
        if (\array_key_exists('display_name', $data) && $data['display_name'] !== null) {
            $object->setDisplayName($data['display_name']);
            unset($data['display_name']);
        }
        elseif (\array_key_exists('display_name', $data) && $data['display_name'] === null) {
            $object->setDisplayName(null);
            unset($data['display_name']);
        }
        if (\array_key_exists('member_limit', $data) && $data['member_limit'] !== null) {
            $object->setMemberLimit($data['member_limit']);
            unset($data['member_limit']);
        }
        elseif (\array_key_exists('member_limit', $data) && $data['member_limit'] === null) {
            $object->setMemberLimit(null);
            unset($data['member_limit']);
        }
        if (\array_key_exists('mfa_required', $data) && $data['mfa_required'] !== null) {
            $object->setMfaRequired($data['mfa_required']);
            unset($data['mfa_required']);
        }
        elseif (\array_key_exists('mfa_required', $data) && $data['mfa_required'] === null) {
            $object->setMfaRequired(null);
            unset($data['mfa_required']);
        }
        if (\array_key_exists('attributes', $data) && $data['attributes'] !== null) {
            $values = new \Hearth\Generated\Admin\Runtime\JsonObject();
            foreach ($data['attributes'] as $key => $value) {
                $values[$key] = $value;
            }
            $object->setAttributes($values);
            unset($data['attributes']);
        }
        elseif (\array_key_exists('attributes', $data) && $data['attributes'] === null) {
            $object->setAttributes(null);
            unset($data['attributes']);
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
        $dataArray['slug'] = $data->getSlug();
        $dataArray['display_name'] = $data->getDisplayName();
        if ($data->isInitialized('memberLimit') && null !== $data->getMemberLimit()) {
            $dataArray['member_limit'] = $data->getMemberLimit();
        }
        if ($data->isInitialized('mfaRequired') && null !== $data->getMfaRequired()) {
            $dataArray['mfa_required'] = $data->getMfaRequired();
        }
        if ($data->isInitialized('attributes') && null !== $data->getAttributes()) {
            $values = new \Hearth\Generated\Admin\Runtime\JsonObject();
            foreach ($data->getAttributes() as $key => $value) {
                $values[$key] = $value;
            }
            $dataArray['attributes'] = $values;
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
        return [\Hearth\Generated\Admin\Model\AdminCreateOrganizationRequest::class => false];
    }
}