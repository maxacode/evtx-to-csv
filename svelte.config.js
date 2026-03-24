// svelte.config.js — Svelte compiler configuration.
//
// vitePreprocess() delegates preprocessing to Vite's own transform pipeline,
// which means:
//   - <script lang="ts"> blocks are compiled by esbuild (fast TypeScript strip)
//   - <style> blocks support PostCSS, CSS Modules, or any Vite-registered
//     CSS preprocessor without extra configuration here.
//
// A separate preprocessor section is not needed for this project because all
// bundling concerns are handled in vite.config.ts. If SCSS or other per-file
// transforms are required in the future, add them to the `preprocess` array.

import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

export default {
  // Use Vite's transform pipeline for TypeScript and CSS inside .svelte files
  preprocess: vitePreprocess(),
};
