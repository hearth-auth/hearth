export type AuthenticatorTransport = "ble" | "hybrid" | "internal" | "nfc" | "usb";

export interface PublicKeyCredentialDescriptorJSON {
  id: string;
  type: PublicKeyCredentialType;
  transports?: AuthenticatorTransport[];
}

export interface PublicKeyCredentialUserEntityJSON {
  id: string;
  name: string;
  displayName: string;
}

export interface PublicKeyCredentialCreationOptionsJSON {
  challenge: string;
  rp: PublicKeyCredentialRpEntity;
  user: PublicKeyCredentialUserEntityJSON;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  excludeCredentials?: PublicKeyCredentialDescriptorJSON[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
  extensions?: AuthenticationExtensionsClientInputs;
}

export interface PublicKeyCredentialRequestOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: PublicKeyCredentialDescriptorJSON[];
  userVerification?: UserVerificationRequirement;
  extensions?: AuthenticationExtensionsClientInputs;
}

export interface RegistrationCredentialJSON {
  id: string;
  rawId: string;
  type: PublicKeyCredentialType;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports?: AuthenticatorTransport[];
    publicKeyAlgorithm?: number;
  };
  clientExtensionResults?: AuthenticationExtensionsClientOutputs;
  authenticatorAttachment?: AuthenticatorAttachment | null;
}

export interface AuthenticationCredentialJSON {
  id: string;
  rawId: string;
  type: PublicKeyCredentialType;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle: string | null;
  };
  clientExtensionResults?: AuthenticationExtensionsClientOutputs;
  authenticatorAttachment?: AuthenticatorAttachment | null;
}

export function parseCreationOptions(
  options: PublicKeyCredentialCreationOptionsJSON
): PublicKeyCredentialCreationOptions {
  return {
    ...options,
    challenge: base64urlToArrayBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64urlToArrayBuffer(options.user.id),
    },
    excludeCredentials: options.excludeCredentials?.map((credential) => ({
      ...credential,
      id: base64urlToArrayBuffer(credential.id),
    })),
  };
}

export function parseRequestOptions(
  options: PublicKeyCredentialRequestOptionsJSON
): PublicKeyCredentialRequestOptions {
  return {
    ...options,
    challenge: base64urlToArrayBuffer(options.challenge),
    allowCredentials: options.allowCredentials?.map((credential) => ({
      ...credential,
      id: base64urlToArrayBuffer(credential.id),
    })),
  };
}

export async function startRegistration(
  options: PublicKeyCredentialCreationOptionsJSON,
  signal?: AbortSignal
): Promise<RegistrationCredentialJSON> {
  ensureWebAuthnAvailable();

  const credential = await navigator.credentials.create({
    publicKey: parseCreationOptions(options),
    signal,
  });

  if (!credential) {
    throw new Error("WebAuthn registration failed: no credential returned");
  }

  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error("WebAuthn registration failed: unexpected credential type");
  }

  const response = credential.response;
  if (!(response instanceof AuthenticatorAttestationResponse)) {
    throw new Error("WebAuthn registration failed: unexpected attestation response");
  }

  return {
    id: credential.id,
    rawId: arrayBufferToBase64url(credential.rawId),
    type: credential.type as PublicKeyCredentialType,
    response: {
      clientDataJSON: arrayBufferToBase64url(response.clientDataJSON),
      attestationObject: arrayBufferToBase64url(response.attestationObject),
      transports: typeof response.getTransports === "function" ? response.getTransports() as AuthenticatorTransport[] : undefined,
      publicKeyAlgorithm:
        typeof response.getPublicKeyAlgorithm === "function" ? response.getPublicKeyAlgorithm() : undefined,
    },
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: credential.authenticatorAttachment as AuthenticatorAttachment | null,
  };
}

export async function startAuthentication(
  options: PublicKeyCredentialRequestOptionsJSON,
  signal?: AbortSignal
): Promise<AuthenticationCredentialJSON> {
  ensureWebAuthnAvailable();

  const credential = await navigator.credentials.get({
    publicKey: parseRequestOptions(options),
    signal,
  });

  if (!credential) {
    throw new Error("WebAuthn authentication failed: no credential returned");
  }

  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error("WebAuthn authentication failed: unexpected credential type");
  }

  const response = credential.response;
  if (!(response instanceof AuthenticatorAssertionResponse)) {
    throw new Error("WebAuthn authentication failed: unexpected assertion response");
  }

  return {
    id: credential.id,
    rawId: arrayBufferToBase64url(credential.rawId),
    type: credential.type as PublicKeyCredentialType,
    response: {
      clientDataJSON: arrayBufferToBase64url(response.clientDataJSON),
      authenticatorData: arrayBufferToBase64url(response.authenticatorData),
      signature: arrayBufferToBase64url(response.signature),
      userHandle: response.userHandle ? arrayBufferToBase64url(response.userHandle) : null,
    },
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: credential.authenticatorAttachment as AuthenticatorAttachment | null,
  };
}

function ensureWebAuthnAvailable(): void {
  if (typeof window === "undefined" || !window.PublicKeyCredential || !navigator?.credentials) {
    throw new Error("WebAuthn is not supported in this environment");
  }
}

function base64urlToArrayBuffer(input: string): ArrayBuffer {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = decodeBase64(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function arrayBufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return encodeBase64(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64(value: string): string {
  if (typeof atob === "function") return atob(value);

  const BufferCtor = (globalThis as { Buffer?: { from: (input: string, encoding: string) => { toString: (encoding: string) => string } } }).Buffer;
  if (BufferCtor) return BufferCtor.from(value, "base64").toString("binary");

  throw new Error("No base64 decoder available in this environment");
}

function encodeBase64(value: string): string {
  if (typeof btoa === "function") return btoa(value);

  const BufferCtor = (globalThis as { Buffer?: { from: (input: string, encoding: string) => { toString: (encoding: string) => string } } }).Buffer;
  if (BufferCtor) return BufferCtor.from(value, "binary").toString("base64");

  throw new Error("No base64 encoder available in this environment");
}
