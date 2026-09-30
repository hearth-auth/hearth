// ESLint flat config for @hearth-auth/node. Run with `npm run lint`.
import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import tseslint from "typescript-eslint";

export default defineConfig(
  {
    // Build and test output.
    ignores: ["dist/", "coverage/"],
  },
  js.configs.recommended,
  tseslint.configs.recommended,
  {
    rules: {
      // A leading underscore marks a parameter kept for its position in a
      // callback signature (e.g. a fetch mock's `_url`), not dead code.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
);
