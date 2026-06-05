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
import { Dashboard } from "./App.js";

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
