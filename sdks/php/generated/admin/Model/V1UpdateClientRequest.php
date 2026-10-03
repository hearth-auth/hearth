<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class V1UpdateClientRequest implements AdditionalPropertiesInterface
{
    use AdditionalAndPatternProperties;
    /**
     * @var array
     */
    protected $initialized = [];
    public function isInitialized($property): bool
    {
        return array_key_exists($property, $this->initialized);
    }
    /**
     * @var string|null
     */
    protected $clientName;
    /**
     * @var list<string>|null
     */
    protected $redirectUris;
    /**
     * @var list<string>|null
     */
    protected $grantTypes;
    /**
     * Controls how access-token authorization data is exposed to resource servers.
     * 
     *  - EMBEDDED: Permissions, roles, and groups are embedded in the JWT at issuance (default).
     *  - INTROSPECTION: JWT carries only identity claims; resource servers call /introspect.
     *  - DECISION: JWT carries only identity claims; resource servers call POST /oauth/authorize.
     *
     * @var string|null
     */
    protected $accessTokenAuthorization = 'EMBEDDED';
    /**
     * Controls whether a client is trusted as a first-party application.
     * 
     * FirstParty clients skip the consent screen and receive the full
     * `permissions`, `roles`, and `groups` claims in issued JWTs.  ThirdParty
     * clients are shown the consent screen and do not receive those claims.
     * Unspecified defaults to ThirdParty on the DCR path; on the authenticated
     * admin path the caller must pass FIRST_PARTY explicitly to grant first-party
     * trust.
     *
     * @var string|null
     */
    protected $trustLevel = 'CLIENT_TRUST_LEVEL_UNSPECIFIED';
    /**
     * ID-token signing algorithm: "RS256" or "EdDSA". Omit to leave unchanged.
     *
     * @var string|null
     */
    protected $idTokenSignedResponseAlg;
    /**
     * @return string|null
     */
    public function getClientName(): ?string
    {
        return $this->clientName;
    }
    /**
     * @param string|null $clientName
     *
     * @return self
     */
    public function setClientName(?string $clientName): self
    {
        $this->initialized['clientName'] = true;
        $this->clientName = $clientName;
        return $this;
    }
    /**
     * @return list<string>|null
     */
    public function getRedirectUris(): ?array
    {
        return $this->redirectUris;
    }
    /**
     * @param list<string>|null $redirectUris
     *
     * @return self
     */
    public function setRedirectUris(?array $redirectUris): self
    {
        $this->initialized['redirectUris'] = true;
        $this->redirectUris = $redirectUris;
        return $this;
    }
    /**
     * @return list<string>|null
     */
    public function getGrantTypes(): ?array
    {
        return $this->grantTypes;
    }
    /**
     * @param list<string>|null $grantTypes
     *
     * @return self
     */
    public function setGrantTypes(?array $grantTypes): self
    {
        $this->initialized['grantTypes'] = true;
        $this->grantTypes = $grantTypes;
        return $this;
    }
    /**
     * Controls how access-token authorization data is exposed to resource servers.
     * 
     *  - EMBEDDED: Permissions, roles, and groups are embedded in the JWT at issuance (default).
     *  - INTROSPECTION: JWT carries only identity claims; resource servers call /introspect.
     *  - DECISION: JWT carries only identity claims; resource servers call POST /oauth/authorize.
     *
     * @return string|null
     */
    public function getAccessTokenAuthorization(): ?string
    {
        return $this->accessTokenAuthorization;
    }
    /**
    * Controls how access-token authorization data is exposed to resource servers.
    
    - EMBEDDED: Permissions, roles, and groups are embedded in the JWT at issuance (default).
    - INTROSPECTION: JWT carries only identity claims; resource servers call /introspect.
    - DECISION: JWT carries only identity claims; resource servers call POST /oauth/authorize.
    *
    * @param string|null $accessTokenAuthorization
    *
    * @return self
    */
    public function setAccessTokenAuthorization(?string $accessTokenAuthorization): self
    {
        $this->initialized['accessTokenAuthorization'] = true;
        $this->accessTokenAuthorization = $accessTokenAuthorization;
        return $this;
    }
    /**
     * Controls whether a client is trusted as a first-party application.
     * 
     * FirstParty clients skip the consent screen and receive the full
     * `permissions`, `roles`, and `groups` claims in issued JWTs.  ThirdParty
     * clients are shown the consent screen and do not receive those claims.
     * Unspecified defaults to ThirdParty on the DCR path; on the authenticated
     * admin path the caller must pass FIRST_PARTY explicitly to grant first-party
     * trust.
     *
     * @return string|null
     */
    public function getTrustLevel(): ?string
    {
        return $this->trustLevel;
    }
    /**
    * Controls whether a client is trusted as a first-party application.
    
    FirstParty clients skip the consent screen and receive the full
    `permissions`, `roles`, and `groups` claims in issued JWTs.  ThirdParty
    clients are shown the consent screen and do not receive those claims.
    Unspecified defaults to ThirdParty on the DCR path; on the authenticated
    admin path the caller must pass FIRST_PARTY explicitly to grant first-party
    trust.
    *
    * @param string|null $trustLevel
    *
    * @return self
    */
    public function setTrustLevel(?string $trustLevel): self
    {
        $this->initialized['trustLevel'] = true;
        $this->trustLevel = $trustLevel;
        return $this;
    }
    /**
     * ID-token signing algorithm: "RS256" or "EdDSA". Omit to leave unchanged.
     *
     * @return string|null
     */
    public function getIdTokenSignedResponseAlg(): ?string
    {
        return $this->idTokenSignedResponseAlg;
    }
    /**
     * ID-token signing algorithm: "RS256" or "EdDSA". Omit to leave unchanged.
     *
     * @param string|null $idTokenSignedResponseAlg
     *
     * @return self
     */
    public function setIdTokenSignedResponseAlg(?string $idTokenSignedResponseAlg): self
    {
        $this->initialized['idTokenSignedResponseAlg'] = true;
        $this->idTokenSignedResponseAlg = $idTokenSignedResponseAlg;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['clientName' => ['client_name', 'getClientName', 'setClientName'], 'redirectUris' => ['redirect_uris', 'getRedirectUris', 'setRedirectUris'], 'grantTypes' => ['grant_types', 'getGrantTypes', 'setGrantTypes'], 'accessTokenAuthorization' => ['access_token_authorization', 'getAccessTokenAuthorization', 'setAccessTokenAuthorization'], 'trustLevel' => ['trust_level', 'getTrustLevel', 'setTrustLevel'], 'idTokenSignedResponseAlg' => ['id_token_signed_response_alg', 'getIdTokenSignedResponseAlg', 'setIdTokenSignedResponseAlg']];
    }
}