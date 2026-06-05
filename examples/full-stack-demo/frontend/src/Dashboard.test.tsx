/**
 * S8: Unit tests for Dashboard using @hearth/sdk/testing utilities (HEA-1309).
 *
 * MockHearthProvider eliminates the real Hearth server dependency — tests run
 * entirely in-memory with forged claim sets. No token exchange, no network.
 *
 * Key point: Dashboard no longer accepts a displayName prop. Identity comes
 * from useUser() reading the HearthContext. MockHearthProvider's default sub
 * is "mock-user", so that's what the heading shows.
 *
 * Run with: vitest (configured alongside the SPA build toolchain).
 */

// @vitest-environment jsdom
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import * as React from "react";
import { MockHearthProvider } from "@hearth/sdk/testing";
import { ClaimProbe, Dashboard } from "./App.js";

describe("Dashboard", () => {
  afterEach(() => cleanup());

  it("renders a welcome heading for the current user from SDK context", () => {
    // No displayName prop — useUser() reads identity from MockHearthProvider.
    // Default sub is "mock-user"; name claim is absent so sub is the fallback.
    render(
      <MockHearthProvider>
        <Dashboard />
      </MockHearthProvider>,
    );
    expect(screen.getByRole("heading").textContent).toBe("Welcome, mock-user");
  });

  it("hides the edit button when user lacks docs.edit permission", () => {
    render(
      <MockHearthProvider permissions={[]}>
        <Dashboard />
      </MockHearthProvider>,
    );
    expect(screen.queryByRole("button", { name: /edit document/i })).toBeNull();
  });

  it("shows the edit button when user has docs.edit permission", () => {
    render(
      <MockHearthProvider permissions={["docs.edit"]}>
        <Dashboard />
      </MockHearthProvider>,
    );
    expect(
      screen.getByRole("button", { name: /edit document/i }),
    ).toBeTruthy();
  });

  it("hides the admin panel when user lacks admin role", () => {
    render(
      <MockHearthProvider roles={[]}>
        <Dashboard />
      </MockHearthProvider>,
    );
    expect(screen.queryByRole("button", { name: /admin panel/i })).toBeNull();
  });

  it("shows the admin panel when user has admin role", () => {
    render(
      <MockHearthProvider roles={["admin"]}>
        <Dashboard />
      </MockHearthProvider>,
    );
    expect(screen.getByRole("button", { name: /admin panel/i })).toBeTruthy();
  });
});

// ─── C4: ClaimProbe tests ─────────────────────────────────────────────────────
//
// Verify that useInGroup / useInOrg return `true` when MockHearthProvider is
// seeded with the demo-team group and acme org — the same values declared in
// hearth.yaml (HEA-1300). These tests prove the hooks wire correctly before the
// live server is set up.

describe("ClaimProbe", () => {
  afterEach(() => cleanup());

  it("shows false for both claims when user has no group or org", () => {
    render(
      <MockHearthProvider>
        <ClaimProbe />
      </MockHearthProvider>,
    );
    expect(screen.getByLabelText("in-demo-team").textContent).toBe("false");
    expect(screen.getByLabelText("in-acme").textContent).toBe("false");
  });

  it("shows true for demo-team when user is in the demo-team group", () => {
    render(
      <MockHearthProvider groups={["demo-team"]}>
        <ClaimProbe />
      </MockHearthProvider>,
    );
    expect(screen.getByLabelText("in-demo-team").textContent).toBe("true");
    expect(screen.getByLabelText("in-acme").textContent).toBe("false");
  });

  it("shows true for acme when user is in the acme org", () => {
    render(
      <MockHearthProvider org="acme">
        <ClaimProbe />
      </MockHearthProvider>,
    );
    expect(screen.getByLabelText("in-demo-team").textContent).toBe("false");
    expect(screen.getByLabelText("in-acme").textContent).toBe("true");
  });

  it("shows true for both when admin@hearth.test is seeded into demo-team and acme", () => {
    // This is the acceptance case: once admin@hearth.test has been added to
    // the demo-team group and acme org (via Admin UI after bootstrap), the JWT
    // will carry groups:["demo-team"] and oid:"acme" and both probes go true.
    render(
      <MockHearthProvider groups={["demo-team"]} org="acme">
        <ClaimProbe />
      </MockHearthProvider>,
    );
    expect(screen.getByLabelText("in-demo-team").textContent).toBe("true");
    expect(screen.getByLabelText("in-acme").textContent).toBe("true");
  });
});
