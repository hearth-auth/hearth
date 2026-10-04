// @vitest-environment jsdom
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import * as React from "react";
import type { HearthFacade } from "../src/hearth.js";
import {
  HearthProvider,
  useHasPermission,
  useHasRole,
  useInGroup,
  useInOrg,
} from "../src/react.js";

/**
 * A facade whose checks resolve from a fixed claim set. The facade's own
 * verification is covered in hasPermission.test.ts; here the hooks only need
 * the async predicates.
 */
function stubFacade(claims: {
  permissions?: string[];
  roles?: string[];
  groups?: string[];
  oid?: string;
}): HearthFacade {
  return {
    hasPermission: async (p) => (claims.permissions ?? []).includes(p),
    hasRole: async (r) => (claims.roles ?? []).includes(r),
    inGroup: async (g) => (claims.groups ?? []).includes(g),
    inOrg: async (o) => claims.oid === o,
    sessionVersionCacheAge: () => Number.POSITIVE_INFINITY,
    stop: () => undefined,
    client: { permissions: () => Promise.reject(new Error("not used")) },
  };
}

function Probe(): React.ReactElement {
  const canEdit = useHasPermission("docs.edit");
  const isAdmin = useHasRole("admin");
  const inEng = useInGroup("engineering");
  const inOrg42 = useInOrg("org_42");
  return (
    <div>
      <span data-testid="perm">{String(canEdit)}</span>
      <span data-testid="role">{String(isAdmin)}</span>
      <span data-testid="group">{String(inEng)}</span>
      <span data-testid="org">{String(inOrg42)}</span>
    </div>
  );
}

describe("react hooks", () => {
  afterEach(() => {
    cleanup();
  });

  it("reads RBAC claims from the provider client once the check resolves", async () => {
    const hearth = stubFacade({
      permissions: ["docs.edit"],
      roles: ["admin"],
      groups: ["engineering"],
      oid: "org_42",
    });
    render(
      <HearthProvider client={hearth}>
        <Probe />
      </HearthProvider>,
    );
    await waitFor(() => expect(screen.getByTestId("perm").textContent).toBe("true"));
    expect(screen.getByTestId("role").textContent).toBe("true");
    expect(screen.getByTestId("group").textContent).toBe("true");
    expect(screen.getByTestId("org").textContent).toBe("true");
  });

  it("returns false until the check resolves", () => {
    const pending = new Promise<boolean>(() => undefined);
    const hearth: HearthFacade = {
      ...stubFacade({}),
      hasPermission: () => pending,
    };
    render(
      <HearthProvider client={hearth}>
        <Probe />
      </HearthProvider>,
    );
    expect(screen.getByTestId("perm").textContent).toBe("false");
  });

  it("returns false when the check rejects", async () => {
    let settled = false;
    const hearth: HearthFacade = {
      ...stubFacade({ permissions: ["docs.edit"] }),
      hasPermission: () => {
        settled = true;
        return Promise.reject(new Error("revoked"));
      },
    };
    render(
      <HearthProvider client={hearth}>
        <Probe />
      </HearthProvider>,
    );
    await waitFor(() => expect(settled).toBe(true));
    expect(screen.getByTestId("perm").textContent).toBe("false");
  });

  it("returns false when the token lacks the requested claims", async () => {
    render(
      <HearthProvider client={stubFacade({})}>
        <Probe />
      </HearthProvider>,
    );
    await new Promise((r) => setTimeout(r, 0));
    expect(screen.getByTestId("perm").textContent).toBe("false");
    expect(screen.getByTestId("role").textContent).toBe("false");
    expect(screen.getByTestId("group").textContent).toBe("false");
    expect(screen.getByTestId("org").textContent).toBe("false");
  });

  it("returns false when no HearthProvider is mounted", () => {
    render(<Probe />);
    expect(screen.getByTestId("perm").textContent).toBe("false");
    expect(screen.getByTestId("role").textContent).toBe("false");
    expect(screen.getByTestId("group").textContent).toBe("false");
    expect(screen.getByTestId("org").textContent).toBe("false");
  });
});
