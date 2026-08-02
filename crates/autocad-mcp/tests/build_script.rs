// Exercise the build-input hashing helpers as ordinary test code. Cargo does
// not otherwise compile `build.rs` with its `#[cfg(test)]` module enabled.
#[allow(dead_code)]
#[path = "../build.rs"]
mod build_script;
