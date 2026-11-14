import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["{scripts,packages,apps}/**/*.{test,spec}.{ts,tsx,mts,cts,js,jsx,mjs,cjs}"],
    exclude: ["**/node_modules/**", "**/dist/**"],
  },
});
