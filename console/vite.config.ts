import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  base: "/console/",
  build: {
    rolldownOptions: {
      input: {
        index: fileURLToPath(new URL("./index.html", import.meta.url)),
        explorer: fileURLToPath(new URL("./explorer.html", import.meta.url)),
        command: fileURLToPath(new URL("./command.html", import.meta.url)),
      },
    },
  },
  test: { environment: "jsdom", include: ["src/**/*.test.ts", "tools/**/*.test.ts"] },
});
