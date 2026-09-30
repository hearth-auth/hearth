// ESLint flat config for @hearth-auth/sdk. Run with `npm run lint`.
import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import tseslint from "typescript-eslint";

export default defineConfig(
  {
    // dist/coverage are build output; src/generated is buf output (see .prettierignore).
    ignores: ["dist/", "coverage/", "src/generated/"],
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
