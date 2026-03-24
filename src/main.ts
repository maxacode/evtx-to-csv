/**
 * main.ts
 * -------
 * Entry point for the EventViewer → CSV Svelte application.
 *
 * This file is the webpack/Vite module entry specified in index.html.
 * It mounts the root Svelte App component into the #app DOM element
 * and imports global CSS styles.
 *
 * Import order matters:
 *   1. app.css must be imported before App to ensure global styles are
 *      processed before component-scoped styles (which take precedence).
 *   2. App.svelte is the root Svelte component containing all UI.
 *
 * The `target` must exist in index.html:
 *   <div id="app"></div>
 *
 * The non-null assertion (!) is safe here because the element is guaranteed
 * to exist in the Tauri WebView's index.html template.
 */

// Import global CSS design tokens and resets before any components
import './app.css';

// Import the root Svelte component
import App from './App.svelte';

// Mount the Svelte application into the #app div
// The App component manages all further rendering from here
const app = new App({
  target: document.getElementById('app')!,
});

// Export the app instance (required by some Svelte tooling and HMR setups)
export default app;
