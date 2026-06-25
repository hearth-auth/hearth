package io.hearth.sdk

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

// ── OAuth / Token types ──────────────────────────────────────────────────────

@Serializable
data class BootstrapResponse(
    @SerialName("realm_id") val realmId: String,
    @SerialName("user_id") val userId: String,
    @SerialName("access_token") val accessToken: String,
    @SerialName("refresh_token") val refreshToken: String,
)

@Serializable
data class AuthorizeRequest(
    @SerialName("client_id") val clientId: String,
    @SerialName("redirect_uri") val redirectUri: String,
    val scope: String,
    val state: String,
    @SerialName("response_type") val responseType: String = "code",
    @SerialName("user_id") val userId: String? = null,
    @SerialName("code_challenge") val codeChallenge: String? = null,
    @SerialName("code_challenge_method") val codeChallengeMethod: String? = null,
    val nonce: String? = null,
)

@Serializable
data class AuthorizeResponse(
    val code: String,
    val state: String,
)

@Serializable
data class TokenRequest(
    @SerialName("client_id") val clientId: String,
    @SerialName("grant_type") val grantType: String? = null,
    val code: String? = null,
    @SerialName("redirect_uri") val redirectUri: String? = null,
    @SerialName("code_verifier") val codeVerifier: String? = null,
    @SerialName("refresh_token") val refreshToken: String? = null,
    @SerialName("client_secret") val clientSecret: String? = null,
    // Device flow
    @SerialName("device_code") val deviceCode: String? = null,
    // Client credentials
    val scope: String? = null,
    // Magic link
    val token: String? = null,
)

@Serializable
data class TokenResponse(
    @SerialName("access_token") val accessToken: String,
    @SerialName("id_token") val idToken: String? = null,
    @SerialName("token_type") val tokenType: String,
    @SerialName("expires_in") val expiresIn: Int? = null,
    @SerialName("refresh_token") val refreshToken: String? = null,
)

@Serializable
data class DeviceAuthorizationRequest(
    @SerialName("client_id") val clientId: String,
    val scope: String? = null,
)

/** Body for the magic-link send (initiation) request — `POST /v1/{realm}/auth/magic-link`. */
@Serializable
data class MagicLinkRequest(
    val email: String,
)

@Serializable
data class DeviceAuthorizationResponse(
    @SerialName("device_code") val deviceCode: String,
    @SerialName("user_code") val userCode: String,
    @SerialName("verification_uri") val verificationUri: String,
    @SerialName("verification_uri_complete") val verificationUriComplete: String? = null,
    @SerialName("expires_in") val expiresIn: Int,
    val interval: Int = 5,
)

@Serializable
data class UserInfoResponse(
    val sub: String,
    val name: String? = null,
    val email: String? = null,
    @SerialName("email_verified") val emailVerified: Boolean? = null,
)

@Serializable
data class MePermissionsResponse(
    val roles: List<String>,
    val groups: List<String>,
    val permissions: List<String>,
    val scope: String,
)

// ── OAuth Client registration ─────────────────────────────────────────────────

@Serializable
data class RegisterClientRequest(
    @SerialName("client_name") val clientName: String,
    @SerialName("redirect_uris") val redirectUris: List<String>,
)

@Serializable
data class OAuthClient(
    @SerialName("client_id") val clientId: String,
    @SerialName("client_name") val clientName: String,
    @SerialName("redirect_uris") val redirectUris: List<String>,
    @SerialName("grant_types") val grantTypes: List<String>,
    @SerialName("created_at") val createdAt: Long? = null,
)

// ── Admin — Users ─────────────────────────────────────────────────────────────

@Serializable
data class CreateUserRequest(
    val email: String,
    @SerialName("display_name") val displayName: String,
)

@Serializable
data class User(
    val id: String,
    val email: String,
    @SerialName("display_name") val displayName: String,
    val status: String,
    @SerialName("created_at") val createdAt: Long? = null,
    @SerialName("updated_at") val updatedAt: Long? = null,
)

@Serializable
data class UpdateUserRequest(
    val email: String? = null,
    @SerialName("display_name") val displayName: String? = null,
    val status: String? = null,
)

// ── Admin — Realms ────────────────────────────────────────────────────────────

@Serializable
data class CreateRealmRequest(
    val name: String,
    val config: JsonObject? = null,
)

@Serializable
data class Realm(
    val id: String,
    val name: String,
    val status: String,
    val config: JsonObject? = null,
    @SerialName("created_at") val createdAt: Long? = null,
    @SerialName("updated_at") val updatedAt: Long? = null,
)

@Serializable
data class UpdateRealmRequest(
    val name: String? = null,
    val status: String? = null,
    val config: JsonObject? = null,
)

// ── Pagination ────────────────────────────────────────────────────────────────

@Serializable
data class PageResponse<T>(
    val items: List<T>,
    @SerialName("next_cursor") val nextCursor: String? = null,
)

// ── Introspection ─────────────────────────────────────────────────────────────

@Serializable
data class IntrospectionResult(
    val active: Boolean,
    val sub: String? = null,
    val exp: Long? = null,
    val iat: Long? = null,
    val iss: String? = null,
    val aud: kotlinx.serialization.json.JsonElement? = null,
    val scope: String? = null,
    @SerialName("client_id") val clientId: String? = null,
    /** Access-token authorization mode echoed from the server (HEA-922). */
    val mode: String? = null,
    /** Live-resolved permission set returned in Introspection/Decision modes (HEA-922). */
    val permissions: List<String> = emptyList(),
    /** All non-standard claims captured from the server response. */
    val extra: Map<String, kotlinx.serialization.json.JsonElement> = emptyMap(),
)

// ── Admin — OAuth Clients ─────────────────────────────────────────────────────

@Serializable
data class UpdateClientRequest(
    @SerialName("client_name") val clientName: String? = null,
    @SerialName("redirect_uris") val redirectUris: List<String>? = null,
    @SerialName("grant_types") val grantTypes: List<String>? = null,
)

// ── Admin — Roles ─────────────────────────────────────────────────────────────

@Serializable
data class Role(
    val id: String,
    val name: String,
    val description: String? = null,
    @SerialName("created_at") val createdAt: Long? = null,
    @SerialName("updated_at") val updatedAt: Long? = null,
)

@Serializable
data class CreateRoleRequest(
    val name: String,
    val description: String? = null,
)

@Serializable
data class UpdateRoleRequest(
    val name: String? = null,
    val description: String? = null,
)

// ── Admin — Groups ────────────────────────────────────────────────────────────

@Serializable
data class Group(
    val id: String,
    val name: String,
    val description: String? = null,
    @SerialName("created_at") val createdAt: Long? = null,
    @SerialName("updated_at") val updatedAt: Long? = null,
)

@Serializable
data class CreateGroupRequest(
    val name: String,
    val description: String? = null,
)

@Serializable
data class UpdateGroupRequest(
    val name: String? = null,
    val description: String? = null,
)

// ── Admin — Organization Memberships ──────────────────────────────────────────

@Serializable
data class OrgMember(
    @SerialName("user_id") val userId: String,
    val role: String,
    @SerialName("joined_at") val joinedAt: Long? = null,
)

@Serializable
data class AddOrgMemberRequest(
    @SerialName("user_id") val userId: String,
    val role: String = "member",
)

// ── Permission delivery modes (HEA-922) ───────────────────────────────────────

/**
 * Controls how the SDK and middleware evaluate permissions on incoming requests.
 *
 * The mode is explicit — the SDK NEVER silently falls back from one mode to another
 * based on what claims happen to be present in the token.
 */
enum class AccessTokenAuthorizationMode(val value: String) {
    /** Decode JWT claims locally; no network call. */
    EMBEDDED("embedded"),
    /** Call POST /introspect on each request; server re-resolves live RBAC. */
    INTROSPECTION("introspection"),
    /** Call POST /oauth/authorize on each request. Fail-closed on network errors. */
    DECISION("decision"),
}

/** Request body for POST /oauth/authorize (decision endpoint, HEA-922). */
@Serializable
data class CheckPermissionRequest(
    val permission: String,
    @SerialName("organization_id") val organizationId: String? = null,
    val resource: String? = null,
)

/** Response from POST /oauth/authorize. */
@Serializable
data class CheckPermissionResponse(
    val allowed: Boolean,
)

// ── WebAuthn ──────────────────────────────────────────────────────────────────

/** Server-issued `PublicKeyCredentialCreationOptions` for passkey registration. */
@Serializable
data class WebAuthnRegistrationBeginResponse(
    val challenge: String,
    @SerialName("rp_id") val rpId: String,
    @SerialName("rp_name") val rpName: String,
    @SerialName("user_id") val userId: String,
    @SerialName("user_name") val userName: String,
    @SerialName("user_display_name") val userDisplayName: String,
    val attestation: String,
    val timeout: Long,
)

/** Browser attestation result sent to `POST /webauthn/register/complete`. */
@Serializable
data class WebAuthnRegistrationCompleteRequest(
    @SerialName("client_data_json") val clientDataJson: String,
    @SerialName("attestation_object") val attestationObject: String,
    val origin: String,
    val discoverable: Boolean = false,
)

/** Returned after a successful passkey registration. */
@Serializable
data class WebAuthnRegistrationCompleteResponse(
    @SerialName("credential_id") val credentialId: String,
    val algorithm: Long,
    val discoverable: Boolean,
)

/** An entry in the `allow_credentials` list during a WebAuthn authentication ceremony. */
@Serializable
data class WebAuthnAllowCredential(
    val id: String,
    val type: String,
)

/** Server-issued `PublicKeyCredentialRequestOptions` for passkey authentication. */
@Serializable
data class WebAuthnAuthenticationBeginResponse(
    val challenge: String,
    @SerialName("rp_id") val rpId: String,
    @SerialName("allow_credentials") val allowCredentials: List<WebAuthnAllowCredential>,
    @SerialName("user_verification") val userVerification: String,
    val timeout: Long,
)

/** Browser-signed assertion sent to `POST /webauthn/auth/complete`. */
@Serializable
data class WebAuthnAuthenticationCompleteRequest(
    @SerialName("credential_id") val credentialId: String,
    @SerialName("client_data_json") val clientDataJson: String,
    @SerialName("authenticator_data") val authenticatorData: String,
    val signature: String,
    @SerialName("user_handle") val userHandle: String? = null,
    val origin: String,
)
