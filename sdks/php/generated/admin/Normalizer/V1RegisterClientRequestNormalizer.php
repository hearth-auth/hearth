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
class V1RegisterClientRequestNormalizer implements DenormalizerInterface, NormalizerInterface, DenormalizerAwareInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;
    use CheckArray;
    use ValidatorTrait;
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return $type === \Hearth\Generated\Admin\Model\V1RegisterClientRequest::class;
    }
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return is_object($data) && get_class($data) === \Hearth\Generated\Admin\Model\V1RegisterClientRequest::class;
    }
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        $object = new \Hearth\Generated\Admin\Model\V1RegisterClientRequest();
        if (null === $data || false === \is_array($data)) {
            return $object;
        }
        if (isset($data['$ref']) && !isset($data['type']) && !isset($data['properties']) && !isset($data['allOf'])) {
            return new Reference($data['$ref'], $context['document-origin']);
        }
        if (isset($data['$recursiveRef'])) {
            return new Reference($data['$recursiveRef'], $context['document-origin']);
        }
        if (\array_key_exists('client_name', $data) && $data['client_name'] !== null) {
            $object->setClientName($data['client_name']);
            unset($data['client_name']);
        }
        elseif (\array_key_exists('client_name', $data) && $data['client_name'] === null) {
            $object->setClientName(null);
            unset($data['client_name']);
        }
        if (\array_key_exists('redirect_uris', $data) && $data['redirect_uris'] !== null) {
            $values = [];
            foreach ($data['redirect_uris'] as $value) {
                $values[] = $value;
            }
            $object->setRedirectUris($values);
            unset($data['redirect_uris']);
        }
        elseif (\array_key_exists('redirect_uris', $data) && $data['redirect_uris'] === null) {
            $object->setRedirectUris(null);
            unset($data['redirect_uris']);
        }
        if (\array_key_exists('client_secret', $data) && $data['client_secret'] !== null) {
            $object->setClientSecret($data['client_secret']);
            unset($data['client_secret']);
        }
        elseif (\array_key_exists('client_secret', $data) && $data['client_secret'] === null) {
            $object->setClientSecret(null);
            unset($data['client_secret']);
        }
        if (\array_key_exists('grant_types', $data) && $data['grant_types'] !== null) {
            $values_1 = [];
            foreach ($data['grant_types'] as $value_1) {
                $values_1[] = $value_1;
            }
            $object->setGrantTypes($values_1);
            unset($data['grant_types']);
        }
        elseif (\array_key_exists('grant_types', $data) && $data['grant_types'] === null) {
            $object->setGrantTypes(null);
            unset($data['grant_types']);
        }
        if (\array_key_exists('access_token_authorization', $data) && $data['access_token_authorization'] !== null) {
            $object->setAccessTokenAuthorization($data['access_token_authorization']);
            unset($data['access_token_authorization']);
        }
        elseif (\array_key_exists('access_token_authorization', $data) && $data['access_token_authorization'] === null) {
            $object->setAccessTokenAuthorization(null);
            unset($data['access_token_authorization']);
        }
        if (\array_key_exists('trust_level', $data) && $data['trust_level'] !== null) {
            $object->setTrustLevel($data['trust_level']);
            unset($data['trust_level']);
        }
        elseif (\array_key_exists('trust_level', $data) && $data['trust_level'] === null) {
            $object->setTrustLevel(null);
            unset($data['trust_level']);
        }
        if (\array_key_exists('id_token_signed_response_alg', $data) && $data['id_token_signed_response_alg'] !== null) {
            $object->setIdTokenSignedResponseAlg($data['id_token_signed_response_alg']);
            unset($data['id_token_signed_response_alg']);
        }
        elseif (\array_key_exists('id_token_signed_response_alg', $data) && $data['id_token_signed_response_alg'] === null) {
            $object->setIdTokenSignedResponseAlg(null);
            unset($data['id_token_signed_response_alg']);
        }
        if (\array_key_exists('token_endpoint_auth_method', $data) && $data['token_endpoint_auth_method'] !== null) {
            $object->setTokenEndpointAuthMethod($data['token_endpoint_auth_method']);
            unset($data['token_endpoint_auth_method']);
        }
        elseif (\array_key_exists('token_endpoint_auth_method', $data) && $data['token_endpoint_auth_method'] === null) {
            $object->setTokenEndpointAuthMethod(null);
            unset($data['token_endpoint_auth_method']);
        }
        foreach ($data as $key => $value_2) {
            if (preg_match('/.*/', (string) $key)) {
                $object[$key] = $value_2;
            }
        }
        return $object;
    }
    public function normalize(mixed $data, ?string $format = null, array $context = []): array|string|int|float|bool|\ArrayObject|null
    {
        $dataArray = [];
        if ($data->isInitialized('clientName') && null !== $data->getClientName()) {
            $dataArray['client_name'] = $data->getClientName();
        }
        if ($data->isInitialized('redirectUris') && null !== $data->getRedirectUris()) {
            $values = [];
            foreach ($data->getRedirectUris() as $value) {
                $values[] = $value;
            }
            $dataArray['redirect_uris'] = $values;
        }
        if ($data->isInitialized('clientSecret') && null !== $data->getClientSecret()) {
            $dataArray['client_secret'] = $data->getClientSecret();
        }
        if ($data->isInitialized('grantTypes') && null !== $data->getGrantTypes()) {
            $values_1 = [];
            foreach ($data->getGrantTypes() as $value_1) {
                $values_1[] = $value_1;
            }
            $dataArray['grant_types'] = $values_1;
        }
        if ($data->isInitialized('accessTokenAuthorization') && null !== $data->getAccessTokenAuthorization()) {
            $dataArray['access_token_authorization'] = $data->getAccessTokenAuthorization();
        }
        if ($data->isInitialized('trustLevel') && null !== $data->getTrustLevel()) {
            $dataArray['trust_level'] = $data->getTrustLevel();
        }
        if ($data->isInitialized('idTokenSignedResponseAlg') && null !== $data->getIdTokenSignedResponseAlg()) {
            $dataArray['id_token_signed_response_alg'] = $data->getIdTokenSignedResponseAlg();
        }
        if ($data->isInitialized('tokenEndpointAuthMethod') && null !== $data->getTokenEndpointAuthMethod()) {
            $dataArray['token_endpoint_auth_method'] = $data->getTokenEndpointAuthMethod();
        }
        foreach ($data->additionalPropertyEntries() as $key => $value_2) {
            if (preg_match('/.*/', (string) $key)) {
                $dataArray[$key] = $value_2;
            }
        }
        return $dataArray;
    }
    public function getSupportedTypes(?string $format = null): array
    {
        return [\Hearth\Generated\Admin\Model\V1RegisterClientRequest::class => false];
    }
}