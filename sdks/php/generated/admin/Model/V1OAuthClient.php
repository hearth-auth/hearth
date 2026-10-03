<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class V1OAuthClient implements AdditionalPropertiesInterface
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
    protected $clientId;
    /**
     * @var string|null
     */
    protected $clientName;
    /**
     * @var list<string>|null
     */
    protected $redirectUris;
    /**
     * @var string|null
     */
    protected $createdAt;
    /**
     * @var bool|null
     */
    protected $isConfidential;
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
     * The algorithm this client's ID tokens are signed with: "RS256" or "EdDSA".
     *
     * @var string|null
     */
    protected $idTokenSignedResponseAlg;
    /**
     * The client secret Hearth generated for a confidential client. Present
     * only in the response that created the client (token_endpoint_auth_method
     * "client_secret_basic" or "client_secret_post"); never returned again.
     * Store it on receipt: Hearth keeps only its hash. Also set, once, by
     * RegenerateApplicationSecret.
     *
     * @var string|null
     */
    protected $clientSecret;
    /**
     * RFC 9449 s5.2: when true, every token request from this client must carry
     * a DPoP proof, and every token it gets is bound to the proof's key.
     *
     * @var bool|null
     */
    protected $dpopBoundAccessTokens;
    /**
     * @return string|null
     */
    public function getClientId(): ?string
    {
        return $this->clientId;
    }
    /**
     * @param string|null $clientId
     *
     * @return self
     */
    public function setClientId(?string $clientId): self
    {
        $this->initialized['clientId'] = true;
        $this->clientId = $clientId;
        return $this;
    }
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
     * @return string|null
     */
    public function getCreatedAt(): ?string
    {
        return $this->createdAt;
    }
    /**
     * @param string|null $createdAt
     *
     * @return self
     */
    public function setCreatedAt(?string $createdAt): self
    {
        $this->initialized['createdAt'] = true;
        $this->createdAt = $createdAt;
        return $this;
    }
    /**
     * @return bool|null
     */
    public function getIsConfidential(): ?bool
    {
        return $this->isConfidential;
    }
    /**
     * @param bool|null $isConfidential
     *
     * @return self
     */
    public function setIsConfidential(?bool $isConfidential): self
    {
        $this->initialized['isConfidential'] = true;
        $this->isConfidential = $isConfidential;
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
     * The algorithm this client's ID tokens are signed with: "RS256" or "EdDSA".
     *
     * @return string|null
     */
    public function getIdTokenSignedResponseAlg(): ?string
    {
        return $this->idTokenSignedResponseAlg;
    }
    /**
     * The algorithm this client's ID tokens are signed with: "RS256" or "EdDSA".
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
    /**
     * The client secret Hearth generated for a confidential client. Present
     * only in the response that created the client (token_endpoint_auth_method
     * "client_secret_basic" or "client_secret_post"); never returned again.
     * Store it on receipt: Hearth keeps only its hash. Also set, once, by
     * RegenerateApplicationSecret.
     *
     * @return string|null
     */
    public function getClientSecret(): ?string
    {
        return $this->clientSecret;
    }
    /**
    * The client secret Hearth generated for a confidential client. Present
    only in the response that created the client (token_endpoint_auth_method
    "client_secret_basic" or "client_secret_post"); never returned again.
    Store it on receipt: Hearth keeps only its hash. Also set, once, by
    RegenerateApplicationSecret.
    *
    * @param string|null $clientSecret
    *
    * @return self
    */
    public function setClientSecret(?string $clientSecret): self
    {
        $this->initialized['clientSecret'] = true;
        $this->clientSecret = $clientSecret;
        return $this;
    }
    /**
     * RFC 9449 s5.2: when true, every token request from this client must carry
     * a DPoP proof, and every token it gets is bound to the proof's key.
     *
     * @return bool|null
     */
    public function getDpopBoundAccessTokens(): ?bool
    {
        return $this->dpopBoundAccessTokens;
    }
    /**
    * RFC 9449 s5.2: when true, every token request from this client must carry
    a DPoP proof, and every token it gets is bound to the proof's key.
    *
    * @param bool|null $dpopBoundAccessTokens
    *
    * @return self
    */
    public function setDpopBoundAccessTokens(?bool $dpopBoundAccessTokens): self
    {
        $this->initialized['dpopBoundAccessTokens'] = true;
        $this->dpopBoundAccessTokens = $dpopBoundAccessTokens;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['clientId' => ['clientId', 'getClientId', 'setClientId'], 'clientName' => ['clientName', 'getClientName', 'setClientName'], 'redirectUris' => ['redirectUris', 'getRedirectUris', 'setRedirectUris'], 'createdAt' => ['createdAt', 'getCreatedAt', 'setCreatedAt'], 'isConfidential' => ['isConfidential', 'getIsConfidential', 'setIsConfidential'], 'grantTypes' => ['grantTypes', 'getGrantTypes', 'setGrantTypes'], 'accessTokenAuthorization' => ['accessTokenAuthorization', 'getAccessTokenAuthorization', 'setAccessTokenAuthorization'], 'idTokenSignedResponseAlg' => ['id_token_signed_response_alg', 'getIdTokenSignedResponseAlg', 'setIdTokenSignedResponseAlg'], 'clientSecret' => ['client_secret', 'getClientSecret', 'setClientSecret'], 'dpopBoundAccessTokens' => ['dpop_bound_access_tokens', 'getDpopBoundAccessTokens', 'setDpopBoundAccessTokens']];
    }
}