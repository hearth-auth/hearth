<?php

namespace Hearth\Generated\Admin\Normalizer;

use Hearth\Generated\Admin\Runtime\Normalizer\CheckArray;
use Hearth\Generated\Admin\Runtime\Normalizer\ValidatorTrait;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
class JaneObjectNormalizer implements DenormalizerInterface, NormalizerInterface, DenormalizerAwareInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;
    use CheckArray;
    use ValidatorTrait;
    protected $normalizers = [
        
        \Hearth\Generated\Admin\Model\AdminAddAdditionalRoleRequest::class => \Hearth\Generated\Admin\Normalizer\AdminAddAdditionalRoleRequestNormalizer::class,
        
        \Hearth\Generated\Admin\Model\AdminCreateOrganizationRequest::class => \Hearth\Generated\Admin\Normalizer\AdminCreateOrganizationRequestNormalizer::class,
        
        \Hearth\Generated\Admin\Model\AdminOrganization::class => \Hearth\Generated\Admin\Normalizer\AdminOrganizationNormalizer::class,
        
        \Hearth\Generated\Admin\Model\AdminOrganizationPage::class => \Hearth\Generated\Admin\Normalizer\AdminOrganizationPageNormalizer::class,
        
        \Hearth\Generated\Admin\Model\AdminRoleNameList::class => \Hearth\Generated\Admin\Normalizer\AdminRoleNameListNormalizer::class,
        
        \Hearth\Generated\Admin\Model\AdminUpdateOrganizationRequest::class => \Hearth\Generated\Admin\Normalizer\AdminUpdateOrganizationRequestNormalizer::class,
        
        \Hearth\Generated\Admin\Model\RbacAdminServiceAddGroupMemberBody::class => \Hearth\Generated\Admin\Normalizer\RbacAdminServiceAddGroupMemberBodyNormalizer::class,
        
        \Hearth\Generated\Admin\Model\RbacAdminServiceAssignUserRoleBody::class => \Hearth\Generated\Admin\Normalizer\RbacAdminServiceAssignUserRoleBodyNormalizer::class,
        
        \Hearth\Generated\Admin\Model\RbacAdminServiceUpdateGroupBody::class => \Hearth\Generated\Admin\Normalizer\RbacAdminServiceUpdateGroupBodyNormalizer::class,
        
        \Hearth\Generated\Admin\Model\RbacAdminServiceUpdateRoleBody::class => \Hearth\Generated\Admin\Normalizer\RbacAdminServiceUpdateRoleBodyNormalizer::class,
        
        \Hearth\Generated\Admin\Model\ProtobufAny::class => \Hearth\Generated\Admin\Normalizer\ProtobufAnyNormalizer::class,
        
        \Hearth\Generated\Admin\Model\RpcStatus::class => \Hearth\Generated\Admin\Normalizer\RpcStatusNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1AuditEvent::class => \Hearth\Generated\Admin\Normalizer\V1AuditEventNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1AuditEventPage::class => \Hearth\Generated\Admin\Normalizer\V1AuditEventPageNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1ConsentEntry::class => \Hearth\Generated\Admin\Normalizer\V1ConsentEntryNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1CreateGroupRequest::class => \Hearth\Generated\Admin\Normalizer\V1CreateGroupRequestNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1CreateRoleRequest::class => \Hearth\Generated\Admin\Normalizer\V1CreateRoleRequestNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1CreateUserRequest::class => \Hearth\Generated\Admin\Normalizer\V1CreateUserRequestNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1Group::class => \Hearth\Generated\Admin\Normalizer\V1GroupNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1GroupMember::class => \Hearth\Generated\Admin\Normalizer\V1GroupMemberNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1GroupMembership::class => \Hearth\Generated\Admin\Normalizer\V1GroupMembershipNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1ListGroupMembersResponse::class => \Hearth\Generated\Admin\Normalizer\V1ListGroupMembersResponseNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1ListGroupsResponse::class => \Hearth\Generated\Admin\Normalizer\V1ListGroupsResponseNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1ListRolesResponse::class => \Hearth\Generated\Admin\Normalizer\V1ListRolesResponseNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1ListUserAssignmentsResponse::class => \Hearth\Generated\Admin\Normalizer\V1ListUserAssignmentsResponseNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1ListUserConsentsResponse::class => \Hearth\Generated\Admin\Normalizer\V1ListUserConsentsResponseNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1OAuthClient::class => \Hearth\Generated\Admin\Normalizer\V1OAuthClientNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1OAuthClientPage::class => \Hearth\Generated\Admin\Normalizer\V1OAuthClientPageNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1OrgScope::class => \Hearth\Generated\Admin\Normalizer\V1OrgScopeNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1Realm::class => \Hearth\Generated\Admin\Normalizer\V1RealmNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1RealmConfig::class => \Hearth\Generated\Admin\Normalizer\V1RealmConfigNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1RealmPage::class => \Hearth\Generated\Admin\Normalizer\V1RealmPageNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1RegisterClientRequest::class => \Hearth\Generated\Admin\Normalizer\V1RegisterClientRequestNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1ResolveEffectivePermissionsResponse::class => \Hearth\Generated\Admin\Normalizer\V1ResolveEffectivePermissionsResponseNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1Role::class => \Hearth\Generated\Admin\Normalizer\V1RoleNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1RoleAssignment::class => \Hearth\Generated\Admin\Normalizer\V1RoleAssignmentNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1Scope::class => \Hearth\Generated\Admin\Normalizer\V1ScopeNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1UpdateClientRequest::class => \Hearth\Generated\Admin\Normalizer\V1UpdateClientRequestNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1UpdateUserRequest::class => \Hearth\Generated\Admin\Normalizer\V1UpdateUserRequestNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1User::class => \Hearth\Generated\Admin\Normalizer\V1UserNormalizer::class,
        
        \Hearth\Generated\Admin\Model\V1UserPage::class => \Hearth\Generated\Admin\Normalizer\V1UserPageNormalizer::class,
        
        \Hearth\Generated\Admin\Model\AdminBootstrapPostResponse200::class => \Hearth\Generated\Admin\Normalizer\AdminBootstrapPostResponse200Normalizer::class,
        
        \Jane\Component\JsonSchemaRuntime\Reference::class => \Hearth\Generated\Admin\Runtime\Normalizer\ReferenceNormalizer::class,
    ], $normalizersCache = [];
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return array_key_exists($type, $this->normalizers);
    }
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return is_object($data) && array_key_exists(get_class($data), $this->normalizers);
    }
    public function normalize(mixed $data, ?string $format = null, array $context = []): array|string|int|float|bool|\ArrayObject|null
    {
        $normalizerClass = $this->normalizers[get_class($data)];
        $normalizer = $this->getNormalizer($normalizerClass);
        return $normalizer->normalize($data, $format, $context);
    }
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        $denormalizerClass = $this->normalizers[$type];
        $denormalizer = $this->getNormalizer($denormalizerClass);
        return $denormalizer->denormalize($data, $type, $format, $context);
    }
    private function getNormalizer(string $normalizerClass)
    {
        return $this->normalizersCache[$normalizerClass] ?? $this->initNormalizer($normalizerClass);
    }
    private function initNormalizer(string $normalizerClass)
    {
        $normalizer = new $normalizerClass();
        $normalizer->setNormalizer($this->normalizer);
        $normalizer->setDenormalizer($this->denormalizer);
        $this->normalizersCache[$normalizerClass] = $normalizer;
        return $normalizer;
    }
    public function getSupportedTypes(?string $format = null): array
    {
        return array_combine(array_keys($this->normalizers), array_fill(0, count($this->normalizers), false));
    }
}