import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  parseCreationOptions,
  parseRequestOptions,
  startAuthentication,
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "./webauthn.js";

class MockPublicKeyCredential {
  id: string;
  rawId: ArrayBuffer;
  type: PublicKeyCredentialType = "public-key";
  response: unknown;
  authenticatorAttachment: AuthenticatorAttachment | null = "platform";

  constructor(id: string, rawId: ArrayBuffer, response: unknown) {
    this.id = id;
    this.rawId = rawId;
    this.response = response;
  }

  getClientExtensionResults(): AuthenticationExtensionsClientOutputs {
    return {};
  }
}

class MockAuthenticatorAttestationResponse {
  clientDataJSON: ArrayBuffer;
  attestationObject: ArrayBuffer;

  constructor(clientDataJSON: ArrayBuffer, attestationObject: ArrayBuffer) {
    this.clientDataJSON = clientDataJSON;
    this.attestationObject = attestationObject;
  }

  getTransports(): AuthenticatorTransport[] {
    return ["internal"];
  }

  getPublicKeyAlgorithm(): number {
    return -7;
  }
}

class MockAuthenticatorAssertionResponse {
  clientDataJSON: ArrayBuffer;
  authenticatorData: ArrayBuffer;
  signature: ArrayBuffer;
  userHandle: ArrayBuffer | null;

  constructor(
    clientDataJSON: ArrayBuffer,
    authenticatorData: ArrayBuffer,
    signature: ArrayBuffer,
    userHandle: ArrayBuffer | null
  ) {
    this.clientDataJSON = clientDataJSON;
    this.authenticatorData = authenticatorData;
    this.signature = signature;
    this.userHandle = userHandle;
  }
}

describe("webauthn", () => {
  const createMock = vi.fn();
  const getMock = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("PublicKeyCredential", MockPublicKeyCredential);
    vi.stubGlobal("AuthenticatorAttestationResponse", MockAuthenticatorAttestationResponse);
    vi.stubGlobal("AuthenticatorAssertionResponse", MockAuthenticatorAssertionResponse);
    vi.stubGlobal("window", { PublicKeyCredential: MockPublicKeyCredential });
    vi.stubGlobal("navigator", {
      credentials: {
        create: createMock,
        get: getMock,
      },
    });
    createMock.mockReset();
    getMock.mockReset();
  });

  it("parses creation options from base64url JSON", () => {
    const input: PublicKeyCredentialCreationOptionsJSON = {
      challenge: base64urlFromUtf8("challenge"),
      rp: { id: "example.com", name: "Example" },
      user: {
        id: base64urlFromUtf8("user-id"),
        name: "user@example.com",
        displayName: "User",
      },
      pubKeyCredParams: [{ alg: -7, type: "public-key" }],
      excludeCredentials: [
        {
          id: base64urlFromUtf8("exclude-1"),
          type: "public-key",
          transports: ["internal"],
        },
      ],
    };

    const parsed = parseCreationOptions(input);

    expect(utf8FromBuffer(parsed.challenge)).toBe("challenge");
    expect(utf8FromBuffer(parsed.user.id as ArrayBuffer)).toBe("user-id");
    expect(utf8FromBuffer(parsed.excludeCredentials?.[0].id as ArrayBuffer)).toBe("exclude-1");
  });

  it("parses request options from base64url JSON", () => {
    const input: PublicKeyCredentialRequestOptionsJSON = {
      challenge: base64urlFromUtf8("assertion-challenge"),
      allowCredentials: [
        {
          id: base64urlFromUtf8("cred-id"),
          type: "public-key",
        },
      ],
    };

    const parsed = parseRequestOptions(input);

    expect(utf8FromBuffer(parsed.challenge)).toBe("assertion-challenge");
    expect(utf8FromBuffer(parsed.allowCredentials?.[0].id as ArrayBuffer)).toBe("cred-id");
  });

  it("starts registration and serializes credential response", async () => {
    const response = new MockAuthenticatorAttestationResponse(
      toBuffer("client-data"),
      toBuffer("attestation")
    );
    const credential = new MockPublicKeyCredential("cred-1", toBuffer("raw-id"), response);
    createMock.mockResolvedValueOnce(credential);

    const output = await startRegistration({
      challenge: base64urlFromUtf8("reg-challenge"),
      rp: { id: "example.com", name: "Example" },
      user: {
        id: base64urlFromUtf8("user-1"),
        name: "user@example.com",
        displayName: "User",
      },
      pubKeyCredParams: [{ alg: -7, type: "public-key" }],
    });

    expect(output.id).toBe("cred-1");
    expect(output.rawId).toBe(base64urlFromUtf8("raw-id"));
    expect(output.response.clientDataJSON).toBe(base64urlFromUtf8("client-data"));
    expect(output.response.attestationObject).toBe(base64urlFromUtf8("attestation"));
    expect(output.response.publicKeyAlgorithm).toBe(-7);

    const createArg = createMock.mock.calls[0][0];
    expect(utf8FromBuffer(createArg.publicKey.challenge)).toBe("reg-challenge");
  });

  it("starts authentication and serializes assertion response", async () => {
    const response = new MockAuthenticatorAssertionResponse(
      toBuffer("client-data"),
      toBuffer("auth-data"),
      toBuffer("signature"),
      toBuffer("user-handle")
    );
    const credential = new MockPublicKeyCredential("cred-2", toBuffer("raw-id-2"), response);
    getMock.mockResolvedValueOnce(credential);

    const output = await startAuthentication({
      challenge: base64urlFromUtf8("auth-challenge"),
      allowCredentials: [{ id: base64urlFromUtf8("cred-2"), type: "public-key" }],
    });

    expect(output.id).toBe("cred-2");
    expect(output.rawId).toBe(base64urlFromUtf8("raw-id-2"));
    expect(output.response.authenticatorData).toBe(base64urlFromUtf8("auth-data"));
    expect(output.response.signature).toBe(base64urlFromUtf8("signature"));
    expect(output.response.userHandle).toBe(base64urlFromUtf8("user-handle"));

    const getArg = getMock.mock.calls[0][0];
    expect(utf8FromBuffer(getArg.publicKey.challenge)).toBe("auth-challenge");
  });
});

function toBuffer(value: string): ArrayBuffer {
  return new TextEncoder().encode(value).buffer;
}

function utf8FromBuffer(buffer: BufferSource): string {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : new Uint8Array(buffer.buffer);
  return new TextDecoder().decode(bytes);
}

function base64urlFromUtf8(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
