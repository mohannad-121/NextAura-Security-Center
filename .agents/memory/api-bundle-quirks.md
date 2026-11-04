---
name: API server bundling quirks
description: Runtime/bundling pitfalls hit when running the Express API and one-off DB scripts in this workspace.
---
- The api-server dev command esbuild-bundles to ESM. pdfkit→fontkit imports `@swc/helpers`, which pnpm does not hoist; it must be a direct dependency of api-server or the bundle fails at startup with ERR_MODULE_NOT_FOUND.
- There is no tsx in the workspace. For a one-off script against the DB: write a .mts in api-server/src, bundle with `pnpm exec esbuild --bundle --platform=node --format=esm --packages=bundle --external:pg-native --banner:js='import { createRequire } from "node:module"; const require = createRequire(import.meta.url);'`, run with node, then delete it.
- Typecheck order matters: `pnpm run typecheck:libs` (tsc --build) must run before artifact typechecks or `@workspace/db` exports appear missing.
