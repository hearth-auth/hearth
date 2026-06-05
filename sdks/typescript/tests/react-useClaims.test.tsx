// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import * as React from "react";
import { createHearth } from "../src/hearth.js";
import { HearthProvider, useClaims, useUser } from "../src/react.js";

function forgeJwt(claims: Record<string, unknown>): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "EdDSA", typ: "JWT" }),
    "utf8",
  ).toString("base64url");
  const body = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  const sig = Buffer.from("fake-sig").toString("base64url");
  return `${header}.${body}.${sig}`;
}

function ClaimsProbe(): React.ReactElement {
  const claims = useClaims();
  return (
    <div>
      <span data-testid="sub">{claims?.subject() ?? "null"}</span>
      <span data-testid="email">{String(claims?.get("email") ?? "null")}</span>
      <span data-testid="loaded">{claims !== null ? "yes" : "no"}</span>
    </div>
  );
}

function UserProbe(): React.ReactElement {
  const user = useUser();
  return (
    <div>
      <span data-testid="sub">{user?.sub ?? "null"}</span>
      <span data-testid="name">{user?.name ?? "null"}</span>
      <span data-testid="email">{user?.email ?? "null"}</span>
      <span data-testid="verified">{String(user?.emailVerified ?? "null")}</span>
      <span data-testid="picture">{user?.picture ?? "null"}</span>
      <span data-testid="loaded">{user !== null ? "yes" : "no"}</span>
    </div>
  );
}

describe("useClaims", () => {
  afterEach(() => {
    cleanup();
  });

  it("returns typed claims from the current token", () => {
    const token = forgeJwt({ sub: "user_1", email: "alice@example.com" });
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => token,
    });
    render(
      <HearthProvider client={hearth}>
        <ClaimsProbe />
      </HearthProvider>,
    );
    expect(screen.getByTestId("sub").textContent).toBe("user_1");
    expect(screen.getByTestId("email").textContent).toBe("alice@example.com");
    expect(screen.getByTestId("loaded").textContent).toBe("yes");
  });

  it("returns null when no HearthProvider is mounted", () => {
    render(<ClaimsProbe />);
    expect(screen.getByTestId("loaded").textContent).toBe("no");
  });

  it("returns null when getToken returns null", () => {
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => null,
    });
    render(
      <HearthProvider client={hearth}>
        <ClaimsProbe />
      </HearthProvider>,
    );
    expect(screen.getByTestId("loaded").textContent).toBe("no");
  });

  it("re-renders with fresh claims when the token changes via subscribe", async () => {
    let storedCallback: (() => void) | null = null;
    let currentToken = forgeJwt({ sub: "user_1", email: "alice@example.com" });

    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => currentToken,
      subscribe: (cb) => {
        storedCallback = cb;
        return () => {
          storedCallback = null;
        };
      },
    });

    render(
      <HearthProvider client={hearth}>
        <ClaimsProbe />
      </HearthProvider>,
    );

    expect(screen.getByTestId("sub").textContent).toBe("user_1");
    expect(screen.getByTestId("email").textContent).toBe("alice@example.com");

    // Simulate silent token refresh — swap the token then fire the event bus
    currentToken = forgeJwt({ sub: "user_1", email: "alice-new@example.com" });
    await act(async () => {
      storedCallback?.();
    });

    expect(screen.getByTestId("email").textContent).toBe("alice-new@example.com");
  });

  it("unsubscribes on unmount", () => {
    const unsubscribe = vi.fn();
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => forgeJwt({ sub: "u1" }),
      subscribe: () => unsubscribe,
    });
    const { unmount } = render(
      <HearthProvider client={hearth}>
        <ClaimsProbe />
      </HearthProvider>,
    );
    expect(unsubscribe).not.toHaveBeenCalled();
    unmount();
    expect(unsubscribe).toHaveBeenCalledOnce();
  });
});

describe("useUser", () => {
  afterEach(() => {
    cleanup();
  });

  it("extracts standard profile fields from the JWT", () => {
    const token = forgeJwt({
      sub: "user_42",
      name: "Alice Smith",
      email: "alice@example.com",
      email_verified: true,
      picture: "https://example.com/avatar.png",
    });
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => token,
    });
    render(
      <HearthProvider client={hearth}>
        <UserProbe />
      </HearthProvider>,
    );
    expect(screen.getByTestId("sub").textContent).toBe("user_42");
    expect(screen.getByTestId("name").textContent).toBe("Alice Smith");
    expect(screen.getByTestId("email").textContent).toBe("alice@example.com");
    expect(screen.getByTestId("verified").textContent).toBe("true");
    expect(screen.getByTestId("picture").textContent).toBe(
      "https://example.com/avatar.png",
    );
    expect(screen.getByTestId("loaded").textContent).toBe("yes");
  });

  it("returns null when unauthenticated", () => {
    render(<UserProbe />);
    expect(screen.getByTestId("loaded").textContent).toBe("no");
  });

  it("defaults optional fields to empty string / false / null", () => {
    const token = forgeJwt({ sub: "user_1" });
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => token,
    });
    render(
      <HearthProvider client={hearth}>
        <UserProbe />
      </HearthProvider>,
    );
    expect(screen.getByTestId("name").textContent).toBe("");
    expect(screen.getByTestId("email").textContent).toBe("");
    expect(screen.getByTestId("verified").textContent).toBe("false");
    expect(screen.getByTestId("picture").textContent).toBe("null");
  });

  it("re-renders when the token changes via subscribe", async () => {
    let storedCallback: (() => void) | null = null;
    let currentToken = forgeJwt({ sub: "user_1", name: "Alice" });

    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => currentToken,
      subscribe: (cb) => {
        storedCallback = cb;
        return () => {
          storedCallback = null;
        };
      },
    });

    render(
      <HearthProvider client={hearth}>
        <UserProbe />
      </HearthProvider>,
    );
    expect(screen.getByTestId("name").textContent).toBe("Alice");

    currentToken = forgeJwt({ sub: "user_1", name: "Alice Smith" });
    await act(async () => {
      storedCallback?.();
    });

    expect(screen.getByTestId("name").textContent).toBe("Alice Smith");
  });
});
