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
class RbacAdminServiceAssignUserRoleBodyNormalizer implements DenormalizerInterface, NormalizerInterface, DenormalizerAwareInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;
    use CheckArray;
    use ValidatorTrait;
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return $type === \Hearth\Generated\Admin\Model\RbacAdminServiceAssignUserRoleBody::class;
    }
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return is_object($data) && get_class($data) === \Hearth\Generated\Admin\Model\RbacAdminServiceAssignUserRoleBody::class;
    }
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        $object = new \Hearth\Generated\Admin\Model\RbacAdminServiceAssignUserRoleBody();
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
        if (\array_key_exists('roleId', $data) && $data['roleId'] !== null) {
            $object->setRoleId($data['roleId']);
            unset($data['roleId']);
        }
        elseif (\array_key_exists('roleId', $data) && $data['roleId'] === null) {
            $object->setRoleId(null);
            unset($data['roleId']);
        }
        if (\array_key_exists('scope', $data) && $data['scope'] !== null) {
            $object->setScope($this->denormalizer->denormalize($data['scope'], \Hearth\Generated\Admin\Model\V1Scope::class, 'json', $context));
            unset($data['scope']);
        }
        elseif (\array_key_exists('scope', $data) && $data['scope'] === null) {
            $object->setScope(null);
            unset($data['scope']);
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
        if ($data->isInitialized('realmId') && null !== $data->getRealmId()) {
            $dataArray['realmId'] = $data->getRealmId();
        }
        if ($data->isInitialized('roleId') && null !== $data->getRoleId()) {
            $dataArray['roleId'] = $data->getRoleId();
        }
        if ($data->isInitialized('scope') && null !== $data->getScope()) {
            $dataArray['scope'] = $data->getScope() === null ? null : new \Hearth\Generated\Admin\Runtime\JsonObject($this->normalizer->normalize($data->getScope(), 'json', $context));
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
        return [\Hearth\Generated\Admin\Model\RbacAdminServiceAssignUserRoleBody::class => false];
    }
}