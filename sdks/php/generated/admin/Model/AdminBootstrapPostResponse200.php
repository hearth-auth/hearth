<?php

namespace Hearth\Generated\Admin\Model;

use Hearth\Generated\Admin\Runtime\AdditionalAndPatternProperties;
use Hearth\Generated\Admin\Runtime\AdditionalPropertiesInterface;
class AdminBootstrapPostResponse200 implements AdditionalPropertiesInterface
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
     * UUID of the created dev realm.
     *
     * @var string|null
     */
    protected $realmId;
    /**
     * UUID of the admin user in the dev realm.
     *
     * @var string|null
     */
    protected $userId;
    /**
     * Long-lived Bearer token for the dev-realm admin. Scoped to the dev
     * realm only — cannot manage other realms. Use for REST API calls in
     * dev/test scripts and as the `Authorization` header on re-bootstrap.
     * 
     *
     * @var string|null
     */
    protected $accessToken;
    /**
     * Refresh token for the dev-realm admin session.
     *
     * @var string|null
     */
    protected $refreshToken;
    /**
     * Randomly generated admin password. Non-empty **only** on the **first**
     * bootstrap call. Empty on all subsequent re-bootstrap calls — store this
     * value securely; it is never returned again. Use for browser login at
     * `/ui/admin/login`.
     * 
     *
     * @var string|null
     */
    protected $adminPassword;
    /**
     * Ready-to-copy shell commands with the actual realm ID and token
     * interpolated for convenience. Only populated in --dev mode.
     * 
     *
     * @var string|null
     */
    protected $quickstart;
    /**
     * Bearer token for the **system-realm** admin (`admin@hearth.test` in the
     * nil-UUID system realm). Unlike `access_token`, this token can manage
     * **any** realm cross-realm (e.g. rotate another realm's signing key) — the
     * BOLA guard only permits cross-realm operations for a nil-UUID system-realm
     * token. Use with `X-Realm-ID: <system_realm_id>` for cross-realm admin API
     * calls. Populated on every bootstrap and re-bootstrap (HEA-2087).
     * 
     *
     * @var string|null
     */
    protected $systemAccessToken;
    /**
     * The reserved system realm ID (the nil UUID,
     * `00000000-0000-0000-0000-000000000000`). Send as the `X-Realm-ID` header
     * alongside `system_access_token` for cross-realm admin API calls.
     * 
     *
     * @var string|null
     */
    protected $systemRealmId;
    /**
     * UUID of the created dev realm.
     *
     * @return string|null
     */
    public function getRealmId(): ?string
    {
        return $this->realmId;
    }
    /**
     * UUID of the created dev realm.
     *
     * @param string|null $realmId
     *
     * @return self
     */
    public function setRealmId(?string $realmId): self
    {
        $this->initialized['realmId'] = true;
        $this->realmId = $realmId;
        return $this;
    }
    /**
     * UUID of the admin user in the dev realm.
     *
     * @return string|null
     */
    public function getUserId(): ?string
    {
        return $this->userId;
    }
    /**
     * UUID of the admin user in the dev realm.
     *
     * @param string|null $userId
     *
     * @return self
     */
    public function setUserId(?string $userId): self
    {
        $this->initialized['userId'] = true;
        $this->userId = $userId;
        return $this;
    }
    /**
     * Long-lived Bearer token for the dev-realm admin. Scoped to the dev
     * realm only — cannot manage other realms. Use for REST API calls in
     * dev/test scripts and as the `Authorization` header on re-bootstrap.
     * 
     *
     * @return string|null
     */
    public function getAccessToken(): ?string
    {
        return $this->accessToken;
    }
    /**
    * Long-lived Bearer token for the dev-realm admin. Scoped to the dev
    realm only — cannot manage other realms. Use for REST API calls in
    dev/test scripts and as the `Authorization` header on re-bootstrap.
    
    *
    * @param string|null $accessToken
    *
    * @return self
    */
    public function setAccessToken(?string $accessToken): self
    {
        $this->initialized['accessToken'] = true;
        $this->accessToken = $accessToken;
        return $this;
    }
    /**
     * Refresh token for the dev-realm admin session.
     *
     * @return string|null
     */
    public function getRefreshToken(): ?string
    {
        return $this->refreshToken;
    }
    /**
     * Refresh token for the dev-realm admin session.
     *
     * @param string|null $refreshToken
     *
     * @return self
     */
    public function setRefreshToken(?string $refreshToken): self
    {
        $this->initialized['refreshToken'] = true;
        $this->refreshToken = $refreshToken;
        return $this;
    }
    /**
     * Randomly generated admin password. Non-empty **only** on the **first**
     * bootstrap call. Empty on all subsequent re-bootstrap calls — store this
     * value securely; it is never returned again. Use for browser login at
     * `/ui/admin/login`.
     * 
     *
     * @return string|null
     */
    public function getAdminPassword(): ?string
    {
        return $this->adminPassword;
    }
    /**
    * Randomly generated admin password. Non-empty **only** on the **first**
    bootstrap call. Empty on all subsequent re-bootstrap calls — store this
    value securely; it is never returned again. Use for browser login at
    `/ui/admin/login`.
    
    *
    * @param string|null $adminPassword
    *
    * @return self
    */
    public function setAdminPassword(?string $adminPassword): self
    {
        $this->initialized['adminPassword'] = true;
        $this->adminPassword = $adminPassword;
        return $this;
    }
    /**
     * Ready-to-copy shell commands with the actual realm ID and token
     * interpolated for convenience. Only populated in --dev mode.
     * 
     *
     * @return string|null
     */
    public function getQuickstart(): ?string
    {
        return $this->quickstart;
    }
    /**
    * Ready-to-copy shell commands with the actual realm ID and token
    interpolated for convenience. Only populated in --dev mode.
    
    *
    * @param string|null $quickstart
    *
    * @return self
    */
    public function setQuickstart(?string $quickstart): self
    {
        $this->initialized['quickstart'] = true;
        $this->quickstart = $quickstart;
        return $this;
    }
    /**
     * Bearer token for the **system-realm** admin (`admin@hearth.test` in the
     * nil-UUID system realm). Unlike `access_token`, this token can manage
     * **any** realm cross-realm (e.g. rotate another realm's signing key) — the
     * BOLA guard only permits cross-realm operations for a nil-UUID system-realm
     * token. Use with `X-Realm-ID: <system_realm_id>` for cross-realm admin API
     * calls. Populated on every bootstrap and re-bootstrap (HEA-2087).
     * 
     *
     * @return string|null
     */
    public function getSystemAccessToken(): ?string
    {
        return $this->systemAccessToken;
    }
    /**
    * Bearer token for the **system-realm** admin (`admin@hearth.test` in the
    nil-UUID system realm). Unlike `access_token`, this token can manage
    **any** realm cross-realm (e.g. rotate another realm's signing key) — the
    BOLA guard only permits cross-realm operations for a nil-UUID system-realm
    token. Use with `X-Realm-ID: <system_realm_id>` for cross-realm admin API
    calls. Populated on every bootstrap and re-bootstrap (HEA-2087).
    
    *
    * @param string|null $systemAccessToken
    *
    * @return self
    */
    public function setSystemAccessToken(?string $systemAccessToken): self
    {
        $this->initialized['systemAccessToken'] = true;
        $this->systemAccessToken = $systemAccessToken;
        return $this;
    }
    /**
     * The reserved system realm ID (the nil UUID,
     * `00000000-0000-0000-0000-000000000000`). Send as the `X-Realm-ID` header
     * alongside `system_access_token` for cross-realm admin API calls.
     * 
     *
     * @return string|null
     */
    public function getSystemRealmId(): ?string
    {
        return $this->systemRealmId;
    }
    /**
    * The reserved system realm ID (the nil UUID,
    `00000000-0000-0000-0000-000000000000`). Send as the `X-Realm-ID` header
    alongside `system_access_token` for cross-realm admin API calls.
    
    *
    * @param string|null $systemRealmId
    *
    * @return self
    */
    public function setSystemRealmId(?string $systemRealmId): self
    {
        $this->initialized['systemRealmId'] = true;
        $this->systemRealmId = $systemRealmId;
        return $this;
    }
    public function definedProperties(): array
    {
        return ['realmId' => ['realm_id', 'getRealmId', 'setRealmId'], 'userId' => ['user_id', 'getUserId', 'setUserId'], 'accessToken' => ['access_token', 'getAccessToken', 'setAccessToken'], 'refreshToken' => ['refresh_token', 'getRefreshToken', 'setRefreshToken'], 'adminPassword' => ['admin_password', 'getAdminPassword', 'setAdminPassword'], 'quickstart' => ['quickstart', 'getQuickstart', 'setQuickstart'], 'systemAccessToken' => ['system_access_token', 'getSystemAccessToken', 'setSystemAccessToken'], 'systemRealmId' => ['system_realm_id', 'getSystemRealmId', 'setSystemRealmId']];
    }
}