// app.config.ts
import { defineConfig } from "@tanstack/start/config";
import tsConfigPaths from "vite-tsconfig-paths";
import { TanStackRouterVite } from "@tanstack/router-plugin/vite";
var app_config_default = defineConfig({
  vite: {
    plugins: [
      tsConfigPaths(),
      TanStackRouterVite()
    ]
  },
  server: {
    prerender: {
      routes: [
        "/"
      ],
      crawlLinks: true
    }
  }
});
export {
  app_config_default as default
};
