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
class AdminBootstrapPostResponse200Normalizer implements DenormalizerInterface, NormalizerInterface, DenormalizerAwareInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;
    use CheckArray;
    use ValidatorTrait;
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return $type === \Hearth\Generated\Admin\Model\AdminBootstrapPostResponse200::class;
    }
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return is_object($data) && get_class($data) === \Hearth\Generated\Admin\Model\AdminBootstrapPostResponse200::class;
    }
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        $object = new \Hearth\Generated\Admin\Model\AdminBootstrapPostResponse200();
        if (null === $data || false === \is_array($data)) {
            return $object;
        }
        if (isset($data['$ref']) && !isset($data['type']) && !isset($data['properties']) && !isset($data['allOf'])) {
            return new Reference($data['$ref'], $context['document-origin']);
        }
        if (isset($data['$recursiveRef'])) {
            return new Reference($data['$recursiveRef'], $context['document-origin']);
        }
        if (\array_key_exists('realm_id', $data) && $data['realm_id'] !== null) {
            $object->setRealmId($data['realm_id']);
            unset($data['realm_id']);
        }
        elseif (\array_key_exists('realm_id', $data) && $data['realm_id'] === null) {
            $object->setRealmId(null);
            unset($data['realm_id']);
        }
        if (\array_key_exists('user_id', $data) && $data['user_id'] !== null) {
            $object->setUserId($data['user_id']);
            unset($data['user_id']);
        }
        elseif (\array_key_exists('user_id', $data) && $data['user_id'] === null) {
            $object->setUserId(null);
            unset($data['user_id']);
        }
        if (\array_key_exists('access_token', $data) && $data['access_token'] !== null) {
            $object->setAccessToken($data['access_token']);
            unset($data['access_token']);
        }
        elseif (\array_key_exists('access_token', $data) && $data['access_token'] === null) {
            $object->setAccessToken(null);
            unset($data['access_token']);
        }
        if (\array_key_exists('refresh_token', $data) && $data['refresh_token'] !== null) {
            $object->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }
        elseif (\array_key_exists('refresh_token', $data) && $data['refresh_token'] === null) {
            $object->setRefreshToken(null);
            unset($data['refresh_token']);
        }
        if (\array_key_exists('admin_password', $data) && $data['admin_password'] !== null) {
            $object->setAdminPassword($data['admin_password']);
            unset($data['admin_password']);
        }
        elseif (\array_key_exists('admin_password', $data) && $data['admin_password'] === null) {
            $object->setAdminPassword(null);
            unset($data['admin_password']);
        }
        if (\array_key_exists('quickstart', $data) && $data['quickstart'] !== null) {
            $object->setQuickstart($data['quickstart']);
            unset($data['quickstart']);
        }
        elseif (\array_key_exists('quickstart', $data) && $data['quickstart'] === null) {
            $object->setQuickstart(null);
            unset($data['quickstart']);
        }
        if (\array_key_exists('system_access_token', $data) && $data['system_access_token'] !== null) {
            $object->setSystemAccessToken($data['system_access_token']);
            unset($data['system_access_token']);
        }
        elseif (\array_key_exists('system_access_token', $data) && $data['system_access_token'] === null) {
            $object->setSystemAccessToken(null);
            unset($data['system_access_token']);
        }
        if (\array_key_exists('system_realm_id', $data) && $data['system_realm_id'] !== null) {
            $object->setSystemRealmId($data['system_realm_id']);
            unset($data['system_realm_id']);
        }
        elseif (\array_key_exists('system_realm_id', $data) && $data['system_realm_id'] === null) {
            $object->setSystemRealmId(null);
            unset($data['system_realm_id']);
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
            $dataArray['realm_id'] = $data->getRealmId();
        }
        if ($data->isInitialized('userId') && null !== $data->getUserId()) {
            $dataArray['user_id'] = $data->getUserId();
        }
        if ($data->isInitialized('accessToken') && null !== $data->getAccessToken()) {
            $dataArray['access_token'] = $data->getAccessToken();
        }
        if ($data->isInitialized('refreshToken') && null !== $data->getRefreshToken()) {
            $dataArray['refresh_token'] = $data->getRefreshToken();
        }
        if ($data->isInitialized('adminPassword') && null !== $data->getAdminPassword()) {
            $dataArray['admin_password'] = $data->getAdminPassword();
        }
        if ($data->isInitialized('quickstart') && null !== $data->getQuickstart()) {
            $dataArray['quickstart'] = $data->getQuickstart();
        }
        if ($data->isInitialized('systemAccessToken') && null !== $data->getSystemAccessToken()) {
            $dataArray['system_access_token'] = $data->getSystemAccessToken();
        }
        if ($data->isInitialized('systemRealmId') && null !== $data->getSystemRealmId()) {
            $dataArray['system_realm_id'] = $data->getSystemRealmId();
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
        return [\Hearth\Generated\Admin\Model\AdminBootstrapPostResponse200::class => false];
    }
}