/**
 * vite.config.ts — Vite configuration for a Tauri v1 + Svelte 4 + TypeScript project.
 *
 * Key decisions explained:
 *
 * PORT 1420
 *   Tauri v1's default tauri.conf.json sets `build.devPath` to
 *   "http://localhost:1420". The port must match exactly or the Tauri
 *   webview will fail to connect to the dev server. `strictPort: true`
 *   makes Vite exit instead of silently picking the next free port.
 *
 * envPrefix
 *   By default Vite only exposes variables prefixed with "VITE_" to the
 *   browser bundle. Adding "TAURI_" lets the build pipeline read the
 *   environment variables that the Tauri CLI injects (e.g. TAURI_PLATFORM,
 *   TAURI_DEBUG, TAURI_ARCH) without leaking arbitrary shell variables.
 *
 * build.target
 *   Tauri v1 embeds different WebView engines depending on the OS:
 *     - Windows  → WebView2  (Chromium-based, JS feature parity with Chrome 105)
 *     - macOS/Linux → WebKit (Safari 13 baseline for Tauri v1 support window)
 *   Targeting the correct engine avoids shipping unnecessary polyfills and
 *   prevents esbuild from down-transpiling modern syntax that the host
 *   WebView already supports natively.
 *
 * build.minify / build.sourcemap
 *   When TAURI_DEBUG is set (i.e. `tauri dev --debug` or `tauri build --debug`):
 *     - minification is disabled so DevTools shows readable source.
 *     - source maps are generated so Rust-side panics and JS errors point
 *       back to the original TypeScript/Svelte lines.
 *   In release builds minification is handled by esbuild (faster than
 *   terser and produces comparable output sizes for this use-case).
 */

import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    // Compile .svelte files, enable Svelte HMR in dev, and run svelte-check
    // diagnostics. vitePreprocess is configured via svelte.config.js.
    svelte(),
  ],

  // Expose both VITE_* and TAURI_* env vars to the compiled bundle.
  // Never expose secrets — only build-time values set by the Tauri CLI.
  envPrefix: ['VITE_', 'TAURI_'],

  server: {
    // Must match tauri.conf.json > build > devPath: "http://localhost:1421"
    port: 1421,
    // Exit immediately if port 1421 is already occupied rather than silently
    // binding to a different port and causing a confusing Tauri connection error.
    strictPort: true,
  },

  build: {
    // Target the WebView engine that Tauri v1 ships on each platform:
    //   Windows  → WebView2 (Chromium 105)
    //   macOS/Linux → WebKit (Safari 13 baseline)
    target: process.env.TAURI_PLATFORM === 'windows' ? 'chrome105' : 'safari13',

    // Use esbuild minification for release builds; disable entirely for debug
    // builds so that DevTools shows human-readable source.
    minify: !process.env.TAURI_DEBUG ? 'esbuild' : false,

    // Emit source maps only in debug builds. Including them in release builds
    // would expose original source to anyone who inspects the app bundle.
    sourcemap: !!process.env.TAURI_DEBUG,
  },
});
