// =============================================================================
// build.rs — Tauri Build Script
//
// This file is executed by Cargo *before* compiling the main crate. Its sole
// job is to invoke `tauri_build::build()`, which performs several tasks needed
// for Tauri v1 to function correctly:
//
//   1. On Windows: embeds a manifest that sets the application's requested
//      execution level and declares DPI-awareness, preventing blurry rendering.
//   2. On macOS/Linux: no-ops (safe to call on all platforms).
//   3. Emits `cargo:rerun-if-changed` directives so Cargo only re-runs this
//      script when Tauri-related config files actually change, keeping
//      incremental builds fast.
//
// This must stay as-is; removing or altering it will break the Tauri build.
// =============================================================================

fn main() {
    // Delegate everything to the tauri-build helper crate. Any errors here
    // (e.g. missing tauri.conf.json) will surface as a clear compile-time panic.
    tauri_build::build()
}
