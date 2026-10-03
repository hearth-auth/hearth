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
class V1OAuthClientNormalizer implements DenormalizerInterface, NormalizerInterface, DenormalizerAwareInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;
    use CheckArray;
    use ValidatorTrait;
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return $type === \Hearth\Generated\Admin\Model\V1OAuthClient::class;
    }
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return is_object($data) && get_class($data) === \Hearth\Generated\Admin\Model\V1OAuthClient::class;
    }
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        $object = new \Hearth\Generated\Admin\Model\V1OAuthClient();
        if (null === $data || false === \is_array($data)) {
            return $object;
        }
        if (isset($data['$ref']) && !isset($data['type']) && !isset($data['properties']) && !isset($data['allOf'])) {
            return new Reference($data['$ref'], $context['document-origin']);
        }
        if (isset($data['$recursiveRef'])) {
            return new Reference($data['$recursiveRef'], $context['document-origin']);
        }
        if (\array_key_exists('isConfidential', $data) && \is_int($data['isConfidential'])) {
            $data['isConfidential'] = (bool) $data['isConfidential'];
        }
        if (\array_key_exists('dpop_bound_access_tokens', $data) && \is_int($data['dpop_bound_access_tokens'])) {
            $data['dpop_bound_access_tokens'] = (bool) $data['dpop_bound_access_tokens'];
        }
        if (\array_key_exists('clientId', $data) && $data['clientId'] !== null) {
            $object->setClientId($data['clientId']);
            unset($data['clientId']);
        }
        elseif (\array_key_exists('clientId', $data) && $data['clientId'] === null) {
            $object->setClientId(null);
            unset($data['clientId']);
        }
        if (\array_key_exists('clientName', $data) && $data['clientName'] !== null) {
            $object->setClientName($data['clientName']);
            unset($data['clientName']);
        }
        elseif (\array_key_exists('clientName', $data) && $data['clientName'] === null) {
            $object->setClientName(null);
            unset($data['clientName']);
        }
        if (\array_key_exists('redirectUris', $data) && $data['redirectUris'] !== null) {
            $values = [];
            foreach ($data['redirectUris'] as $value) {
                $values[] = $value;
            }
            $object->setRedirectUris($values);
            unset($data['redirectUris']);
        }
        elseif (\array_key_exists('redirectUris', $data) && $data['redirectUris'] === null) {
            $object->setRedirectUris(null);
            unset($data['redirectUris']);
        }
        if (\array_key_exists('createdAt', $data) && $data['createdAt'] !== null) {
            $object->setCreatedAt($data['createdAt']);
            unset($data['createdAt']);
        }
        elseif (\array_key_exists('createdAt', $data) && $data['createdAt'] === null) {
            $object->setCreatedAt(null);
            unset($data['createdAt']);
        }
        if (\array_key_exists('isConfidential', $data) && $data['isConfidential'] !== null) {
            $object->setIsConfidential($data['isConfidential']);
            unset($data['isConfidential']);
        }
        elseif (\array_key_exists('isConfidential', $data) && $data['isConfidential'] === null) {
            $object->setIsConfidential(null);
            unset($data['isConfidential']);
        }
        if (\array_key_exists('grantTypes', $data) && $data['grantTypes'] !== null) {
            $values_1 = [];
            foreach ($data['grantTypes'] as $value_1) {
                $values_1[] = $value_1;
            }
            $object->setGrantTypes($values_1);
            unset($data['grantTypes']);
        }
        elseif (\array_key_exists('grantTypes', $data) && $data['grantTypes'] === null) {
            $object->setGrantTypes(null);
            unset($data['grantTypes']);
        }
        if (\array_key_exists('accessTokenAuthorization', $data) && $data['accessTokenAuthorization'] !== null) {
            $object->setAccessTokenAuthorization($data['accessTokenAuthorization']);
            unset($data['accessTokenAuthorization']);
        }
        elseif (\array_key_exists('accessTokenAuthorization', $data) && $data['accessTokenAuthorization'] === null) {
            $object->setAccessTokenAuthorization(null);
            unset($data['accessTokenAuthorization']);
        }
        if (\array_key_exists('id_token_signed_response_alg', $data) && $data['id_token_signed_response_alg'] !== null) {
            $object->setIdTokenSignedResponseAlg($data['id_token_signed_response_alg']);
            unset($data['id_token_signed_response_alg']);
        }
        elseif (\array_key_exists('id_token_signed_response_alg', $data) && $data['id_token_signed_response_alg'] === null) {
            $object->setIdTokenSignedResponseAlg(null);
            unset($data['id_token_signed_response_alg']);
        }
        if (\array_key_exists('client_secret', $data) && $data['client_secret'] !== null) {
            $object->setClientSecret($data['client_secret']);
            unset($data['client_secret']);
        }
        elseif (\array_key_exists('client_secret', $data) && $data['client_secret'] === null) {
            $object->setClientSecret(null);
            unset($data['client_secret']);
        }
        if (\array_key_exists('dpop_bound_access_tokens', $data) && $data['dpop_bound_access_tokens'] !== null) {
            $object->setDpopBoundAccessTokens($data['dpop_bound_access_tokens']);
            unset($data['dpop_bound_access_tokens']);
        }
        elseif (\array_key_exists('dpop_bound_access_tokens', $data) && $data['dpop_bound_access_tokens'] === null) {
            $object->setDpopBoundAccessTokens(null);
            unset($data['dpop_bound_access_tokens']);
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
        if ($data->isInitialized('clientId') && null !== $data->getClientId()) {
            $dataArray['clientId'] = $data->getClientId();
        }
        if ($data->isInitialized('clientName') && null !== $data->getClientName()) {
            $dataArray['clientName'] = $data->getClientName();
        }
        if ($data->isInitialized('redirectUris') && null !== $data->getRedirectUris()) {
            $values = [];
            foreach ($data->getRedirectUris() as $value) {
                $values[] = $value;
            }
            $dataArray['redirectUris'] = $values;
        }
        if ($data->isInitialized('createdAt') && null !== $data->getCreatedAt()) {
            $dataArray['createdAt'] = $data->getCreatedAt();
        }
        if ($data->isInitialized('isConfidential') && null !== $data->getIsConfidential()) {
            $dataArray['isConfidential'] = $data->getIsConfidential();
        }
        if ($data->isInitialized('grantTypes') && null !== $data->getGrantTypes()) {
            $values_1 = [];
            foreach ($data->getGrantTypes() as $value_1) {
                $values_1[] = $value_1;
            }
            $dataArray['grantTypes'] = $values_1;
        }
        if ($data->isInitialized('accessTokenAuthorization') && null !== $data->getAccessTokenAuthorization()) {
            $dataArray['accessTokenAuthorization'] = $data->getAccessTokenAuthorization();
        }
        if ($data->isInitialized('idTokenSignedResponseAlg') && null !== $data->getIdTokenSignedResponseAlg()) {
            $dataArray['id_token_signed_response_alg'] = $data->getIdTokenSignedResponseAlg();
        }
        if ($data->isInitialized('clientSecret') && null !== $data->getClientSecret()) {
            $dataArray['client_secret'] = $data->getClientSecret();
        }
        if ($data->isInitialized('dpopBoundAccessTokens') && null !== $data->getDpopBoundAccessTokens()) {
            $dataArray['dpop_bound_access_tokens'] = $data->getDpopBoundAccessTokens();
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
        return [\Hearth\Generated\Admin\Model\V1OAuthClient::class => false];
    }
}