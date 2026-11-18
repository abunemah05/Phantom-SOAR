import { defineConfig } from "vitest/config";
import path from "node:path";

// Pure-helper tests only (error parsing, role gating, status labels, config validation); no DOM needed.
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
  resolve: {
    alias: { "@": path.resolve(__dirname, "src") },
  },
});
