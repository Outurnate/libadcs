#![allow(clippy::suspicious_command_arg_space)]

use std::env;
use std::path::PathBuf;
use std::process::Command;
use filetime::{set_file_mtime, FileTime};

fn main()
{
  let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
  let build_path = out_dir.join("build");
  let install_path = out_dir.join("install");
  let dceidl_path = install_path.join("dceidl");

  println!("cargo:rustc-link-lib=dcerpc");
  println!("cargo:rustc-link-search=native={}", install_path.to_string_lossy());
  println!("cargo:rerun-if-changed=src/wrapper.h");
  println!("cargo:rerun-if-changed=src/ms-icpr.idl");
  Command::new("meson")
    .arg("setup")
    .arg(&build_path)
    .arg("--debug")
    .current_dir("dcerpc")
    .output().unwrap();
  Command::new("meson")
    .arg("compile")
    .arg("-C")
    .arg(&build_path)
    .output().unwrap();
  Command::new("meson")
    .arg("install")
    .arg("-C")
    .arg(&build_path)
    .env("DESTDIR", &install_path)
    .output().unwrap();

  let cstub = install_path.join("ms-icpr_cstub.c");
  Command::new(dceidl_path)
    .arg("-cc_cmd").arg("cc")
    .arg("-cc_opt").arg("-c -D_GNU_SOURCE -D_REENTRANT -D_POSIX_C_SOURCE=3")
    .arg("-cpp_cmd").arg("cc")
    .arg("-cpp_opt").arg("-E -x c-header")
    .arg("-I").arg(&install_path)
    .arg("src/ms-icpr.idl")
    .arg("-keep").arg("c_source")
    .arg("-header").arg(install_path.join("ms-icpr.h"))
    .arg("-cstub").arg(cstub.clone())
    .arg("-cepv")
    .arg("-server")
    .arg("none")
    .arg("-no_mepv")
    .output().unwrap();

  cc::Build::new()
    .file(cstub)
    .include(&install_path)
    .emit_rerun_if_env_changed(false)
    .compile("libmsicpr.a");

  let bindings = bindgen::Builder::default()
    .header("src/wrapper.h")
    .clang_arg(format!("-I{}", install_path.to_string_lossy()))
    /*.allowlist_function("rpc_.*")
    .allowlist_function("dce_.*")
    .allowlist_var("rpc_.*")
    .allowlist_var("error_status_ok")*/
    .parse_callbacks(Box::new(bindgen::CargoCallbacks))
    .generate()
    .unwrap();

  bindings
    .write_to_file(out_dir.join("bindings.rs"))
    .unwrap();

  set_file_mtime(install_path.join("dce/rpc.h"), FileTime::from_unix_time(0, 0)).unwrap();
  set_file_mtime(install_path.join("ms-icpr.h"), FileTime::from_unix_time(0, 0)).unwrap();
}
