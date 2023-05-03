/* SPDX-License-Identifier: MIT */

extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo to invalidate the built crate whenever these
    // files are changed.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=include/bindings.h");

    // Bindgen uses clang to parse the header files. Define clang arguments
    // for bindgen to properly generate the bindings.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let libcrt_prefix: String = format!("{manifest_dir}/external/libcrt");
    let openssl_prefix: String = format!("{manifest_dir}/external/openssl");
    let bindgen_clang_args: String = format!(
        "-DOPENSSL_RAND_SEED_NONE \
        -I{libcrt_prefix}/include \
        -I{openssl_prefix}/include"
    );

    // The bindgen Builder is the main entry point to bindgen,
    // it configures and generate bindings.
    let bindings = bindgen::Builder::default()
        .use_core()
        .ctypes_prefix("cty")
        .clang_args(bindgen_clang_args.split(" ").collect::<Vec<&str>>())
        .header("include/bindings.h")
        .generate()
        .expect("ERR: Unable to generate bindings");

    let out_dir = env::var_os("OUT_DIR").expect("ERR: Environment variable OUT_DIR not defined\n");

    // Write the generated bindings to '<OUT_DIR>/bindings.rs'. If you check
    // the 'src/bindings.rs', you will notice that we dump the generate bindings
    // into it and set some built-in attributes.
    bindings
        .write_to_file(PathBuf::from(out_dir).join("bindings.rs"))
        .expect("ERR: Couldn't write bindings!");
}
