//! Seeded tests for `xtask check-boundaries`: fixture workspaces are written to a tempdir
//! at test time and run through the real `cargo metadata --offline`.

mod boundaries {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use tempfile::TempDir;
    use xtask::boundaries::{Violation, check, check_workspace, load_manifests, metadata_json};

    const ROOT: &str = r#"[workspace]
resolver = "3"
members = ["crates/*"]
exclude = ["probes"]

[workspace.lints.rust]
unsafe_code = "forbid"
unsafe_op_in_unsafe_fn = "deny"

[workspace.lints.clippy]
dbg_macro = "deny"
todo = "deny"
"#;

    const OVERRIDE_LINTS: &str = r#"[lints.rust]
unsafe_code = "deny"
unsafe_op_in_unsafe_fn = "deny"

[lints.clippy]
dbg_macro = "deny"
todo = "deny"
undocumented_unsafe_blocks = "deny"
"#;

    const INHERIT: &str = "[lints]\nworkspace = true\n";

    fn manifest(name: &str, lints: &str, deps: &str) -> String {
        format!(
            "[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\
             rust-version = \"1.88\"\nlicense = \"MIT OR Apache-2.0\"\npublish = false\n\n\
             {lints}\n[dependencies]\n{deps}"
        )
    }

    /// A workspace written to disk; the tempdir lives as long as this value.
    struct Ws {
        _tmp: TempDir,
        root: std::path::PathBuf,
    }

    impl Ws {
        fn path(&self) -> &Path {
            &self.root
        }
    }

    /// An in-memory workspace: root manifest plus `crates/<name>/Cargo.toml` texts.
    struct Fx {
        root: String,
        crates: BTreeMap<String, String>,
        /// Extra `[[package]]` tables for the fixture's `Cargo.lock`; `None` writes no lock file.
        lock_extra: Option<String>,
    }

    impl Fx {
        fn clean() -> Fx {
            let core = r#"lunepack-core = { path = "../lunepack-core" }"#;
            let mut crates = BTreeMap::new();
            crates.insert(
                "lunepack-core".into(),
                manifest("lunepack-core", INHERIT, ""),
            );
            crates.insert(
                "lunepack-testkit".into(),
                manifest("lunepack-testkit", INHERIT, core),
            );
            crates.insert(
                "lunepack-http".into(),
                manifest("lunepack-http", INHERIT, core),
            );
            crates.insert(
                "lunepack-fs".into(),
                manifest("lunepack-fs", OVERRIDE_LINTS, core),
            );
            crates.insert(
                "lunepack".into(),
                manifest(
                    "lunepack",
                    INHERIT,
                    &format!("{core}\nlunepack-http = {{ path = \"../lunepack-http\" }}"),
                ),
            );
            crates.insert(
                "lunepack-cli".into(),
                manifest("lunepack-cli", INHERIT, core),
            );
            Fx {
                root: ROOT.to_string(),
                crates,
                lock_extra: Some(String::new()),
            }
        }

        fn edit(&mut self, name: &str, f: impl FnOnce(&mut String)) {
            f(self
                .crates
                .get_mut(name)
                .unwrap_or_else(|| panic!("no fixture crate {name}")));
        }

        /// Add a line to the `[dependencies]` table of a fixture crate.
        fn add_dep(&mut self, name: &str, line: &str) {
            self.edit(name, |m| {
                *m = m.replacen("[dependencies]\n", &format!("[dependencies]\n{line}\n"), 1)
            });
        }

        /// Append a whole extra table to a fixture crate's manifest.
        fn append(&mut self, name: &str, text: &str) {
            self.edit(name, |m| m.push_str(&format!("\n{text}\n")));
        }

        fn write(&self) -> Ws {
            let tmp = tempfile::tempdir().expect("tempdir");
            let root = tmp.path().join("ws");
            // A sibling crate outside the workspace, for the "path dependency outside" case.
            let outside = tmp.path().join("outside");
            fs::create_dir_all(outside.join("src")).unwrap();
            fs::write(outside.join("Cargo.toml"), manifest("outside", "", "")).unwrap();
            fs::write(outside.join("src/lib.rs"), "").unwrap();
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join("Cargo.toml"), &self.root).unwrap();
            if let Some(extra) = &self.lock_extra {
                let mut lock = String::from("version = 4\n");
                for name in self.crates.keys() {
                    lock.push_str(&format!(
                        "\n[[package]]\nname = \"{name}\"\nversion = \"0.0.0\"\n"
                    ));
                }
                lock.push_str(extra);
                fs::write(root.join("Cargo.lock"), lock).unwrap();
            }
            for (name, text) in &self.crates {
                let c = root.join("crates").join(name);
                fs::create_dir_all(c.join("src")).unwrap();
                fs::write(c.join("Cargo.toml"), text).unwrap();
                let file = if name == "lunepack-cli" {
                    "main.rs"
                } else {
                    "lib.rs"
                };
                fs::write(c.join("src").join(file), "").unwrap();
            }
            Ws { _tmp: tmp, root }
        }

        fn run(&self) -> (usize, Vec<Violation>) {
            let dir = self.write();
            check_workspace(dir.path()).expect("check_workspace should not fail")
        }
    }

    fn has(vs: &[Violation], package: &str, rule: &str) -> bool {
        vs.iter().any(|x| x.package == package && x.rule == rule)
    }

    fn assert_has(vs: &[Violation], package: &str, rule: &str) {
        assert!(
            has(vs, package, rule),
            "expected {package}: {rule}, got:\n{}",
            render(vs)
        );
    }

    fn render(vs: &[Violation]) -> String {
        vs.iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn assert_clean(vs: &[Violation]) {
        assert!(
            vs.is_empty(),
            "expected no violations, got:\n{}",
            render(vs)
        );
    }

    fn xtask_in(dir: &Path, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(args)
            .current_dir(dir)
            .output()
            .expect("run xtask binary")
    }

    #[test]
    fn a_clean_fixture_is_ok() {
        let (n, vs) = Fx::clean().run();
        assert_eq!(n, 6);
        assert_clean(&vs);
    }

    #[test]
    fn b_core_to_adapter_is_rejected() {
        let mut fx = Fx::clean();
        fx.add_dep(
            "lunepack-core",
            r#"lunepack-http = { path = "../lunepack-http" }"#,
        );
        assert_has(&fx.run().1, "lunepack-core", "edge");
    }

    #[test]
    fn c_adapter_to_adapter_is_rejected() {
        let mut fx = Fx::clean();
        fx.add_dep(
            "lunepack-http",
            r#"lunepack-fs = { path = "../lunepack-fs" }"#,
        );
        assert_has(&fx.run().1, "lunepack-http", "edge");
    }

    #[test]
    fn d_non_allowlisted_crate_with_full_lints_is_rejected() {
        let mut fx = Fx::clean();
        fx.edit("lunepack-http", |m| *m = m.replace(INHERIT, OVERRIDE_LINTS));
        assert_has(&fx.run().1, "lunepack-http", "lints");
    }

    #[test]
    fn e_allowlisted_override_ok_and_other_changes_rejected() {
        // Valid override is part of the clean fixture (lunepack-fs).
        assert_clean(&Fx::clean().run().1);
        for (from, to) in [
            ("dbg_macro = \"deny\"", "dbg_macro = \"warn\""),
            (
                "unsafe_op_in_unsafe_fn = \"deny\"",
                "unsafe_op_in_unsafe_fn = \"warn\"",
            ),
            ("undocumented_unsafe_blocks = \"deny\"\n", ""),
        ] {
            let mut fx = Fx::clean();
            fx.edit("lunepack-fs", |m| *m = m.replace(from, to));
            assert_has(&fx.run().1, "lunepack-fs", "lints");
        }
        // Extra tool table, and `workspace = true` mixed with explicit lints.
        let mut fx = Fx::clean();
        fx.append(
            "lunepack-fs",
            "[lints.rustdoc]\nbroken_intra_doc_links = \"deny\"",
        );
        assert_has(&fx.run().1, "lunepack-fs", "lints");
        // `workspace = true` mixed with explicit lint tables.
        let mut fx = Fx::clean();
        fx.edit("lunepack-fs", |m| {
            *m = m.replacen(
                "[lints.rust]",
                "[lints]\nworkspace = true\n\n[lints.rust]",
                1,
            );
        });
        let dir = fx.write();
        // Cargo itself rejects this mix, so the check must fail loudly (exit 2), not pass.
        assert!(check_workspace(dir.path()).is_err());
    }

    #[test]
    fn f_member_without_lints_is_rejected() {
        let mut fx = Fx::clean();
        fx.edit("lunepack-http", |m| *m = m.replace(INHERIT, ""));
        assert_has(&fx.run().1, "lunepack-http", "lints");
    }

    #[test]
    fn g_unknown_member_is_rejected() {
        let mut fx = Fx::clean();
        fx.crates
            .insert("mystery".into(), manifest("mystery", INHERIT, ""));
        assert_has(&fx.run().1, "mystery", "unknown-member");
    }

    #[test]
    fn h_git_and_outside_path_deps_are_rejected() {
        let mut fx = Fx::clean();
        fx.add_dep(
            "lunepack-http",
            r#"gitdep = { git = "https://example.invalid/gitdep.git" }"#,
        );
        assert_has(&fx.run().1, "lunepack-http", "source");

        let mut fx = Fx::clean();
        fx.add_dep(
            "lunepack-http",
            r#"outside = { path = "../../../outside" }"#,
        );
        assert_has(&fx.run().1, "lunepack-http", "source");

        let mut fx = Fx::clean();
        fx.add_dep(
            "lunepack-http",
            r#"other = { version = "1", registry = "elsewhere" }"#,
        );
        let dir = fx.write();
        // Cargo refuses an unknown registry in metadata: an error (exit 2), never a clean pass.
        assert!(check_workspace(dir.path()).is_err());
    }

    #[test]
    fn i_renamed_dep_is_identified_by_package_name() {
        let mut fx = Fx::clean();
        fx.add_dep(
            "lunepack-core",
            r#"x = { package = "lunepack-http", path = "../lunepack-http" }"#,
        );
        assert_has(&fx.run().1, "lunepack-core", "edge");
    }

    #[test]
    fn j_target_specific_dep_is_checked() {
        let mut fx = Fx::clean();
        fx.append(
            "lunepack-core",
            "[target.'cfg(windows)'.dependencies]\nlunepack-http = { path = \"../lunepack-http\" }",
        );
        assert_has(&fx.run().1, "lunepack-core", "edge");
    }

    #[test]
    fn k_optional_dep_is_checked() {
        let mut fx = Fx::clean();
        fx.add_dep(
            "lunepack-core",
            r#"lunepack-http = { path = "../lunepack-http", optional = true }"#,
        );
        assert_has(&fx.run().1, "lunepack-core", "edge");
    }

    #[test]
    fn l_core_external_dep_must_be_allowlisted() {
        let mut fx = Fx::clean();
        fx.add_dep("lunepack-core", r#"serde = "1""#);
        assert_has(&fx.run().1, "lunepack-core", "core-external");
        // The same crates.io dependency is fine elsewhere.
        let mut fx = Fx::clean();
        fx.add_dep("lunepack-http", r#"serde = "1""#);
        assert_clean(&fx.run().1);
    }

    #[test]
    fn m_unknown_dependency_kind_is_nonzero() {
        let fx = Fx::clean();
        let dir = fx.write();
        let json = metadata_json(dir.path()).unwrap();
        let manifests = load_manifests(&json).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let mut injected = 0;
        for pkg in value["packages"].as_array_mut().unwrap() {
            if pkg["name"] == "lunepack-http" {
                for dep in pkg["dependencies"].as_array_mut().unwrap() {
                    dep["kind"] = serde_json::Value::String("bogus".into());
                    injected += 1;
                }
            }
        }
        assert_eq!(
            injected, 1,
            "fixture should have one lunepack-http dependency"
        );
        let edited = serde_json::to_string(&value).unwrap();
        match check(&edited, &manifests) {
            Err(_) => {}
            Ok(vs) => assert_has(&vs, "lunepack-http", "dep-kind"),
        }
    }

    #[test]
    fn n_root_unsafe_code_must_be_forbid() {
        let mut fx = Fx::clean();
        fx.root = fx
            .root
            .replace("unsafe_code = \"forbid\"", "unsafe_code = \"deny\"");
        assert_has(&fx.run().1, "<workspace>", "root-lints");
    }

    #[test]
    fn o_unparseable_manifest_exits_2() {
        let mut fx = Fx::clean();
        fx.edit("lunepack-http", |m| m.push_str("\nthis is = = not toml\n"));
        let dir = fx.write();
        let out = xtask_in(dir.path(), &["check-boundaries"]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn o2_binary_exit_codes_for_violation_and_clean() {
        let dir = Fx::clean().write();
        let out = xtask_in(dir.path(), &["check-boundaries"]);
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "boundaries: ok (6 packages)"
        );

        let mut fx = Fx::clean();
        fx.add_dep(
            "lunepack-core",
            r#"lunepack-http = { path = "../lunepack-http" }"#,
        );
        let dir = fx.write();
        let out = xtask_in(dir.path(), &["check-boundaries"]);
        assert_eq!(out.status.code(), Some(1));
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("boundaries: lunepack-core: edge: "),
            "stdout: {text}"
        );

        let out = xtask_in(dir.path(), &["no-such-task"]);
        assert_eq!(out.status.code(), Some(2));
    }

    // F3: sources come from Cargo.lock, so [patch] / [replace] cannot hide a git dependency ----
    const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

    #[test]
    fn t_lock_with_crates_io_packages_is_clean() {
        let mut fx = Fx::clean();
        fx.lock_extra = Some(format!(
            "\n[[package]]\nname = \"anyhow\"\nversion = \"1.0.0\"\nsource = \"{CRATES_IO}\"\nchecksum = \"00\"\n"
        ));
        assert_clean(&fx.run().1);
    }

    #[test]
    fn t_patch_to_git_is_rejected_by_the_lock_and_the_patch_rule() {
        let mut fx = Fx::clean();
        fx.root.push_str(
            "\n[patch.crates-io]\nanyhow = { git = \"https://example.invalid/anyhow.git\" }\n",
        );
        fx.lock_extra = Some(
            "\n[[package]]\nname = \"anyhow\"\nversion = \"1.0.0\"\n\
             source = \"git+https://example.invalid/anyhow.git#0123456789abcdef0123456789abcdef01234567\"\n"
                .to_string(),
        );
        let (_, vs) = fx.run();
        assert_has(&vs, "anyhow", "lock-source");
        assert_has(&vs, "<workspace>", "patch");
    }

    #[test]
    fn t_replace_section_is_rejected() {
        let mut fx = Fx::clean();
        fx.root
            .push_str("\n[replace]\n\"anyhow:1.0.0\" = { path = \"../elsewhere\" }\n");
        assert_has(&fx.run().1, "<workspace>", "patch");
    }

    #[test]
    fn t_lock_source_that_is_not_crates_io_is_rejected_without_a_patch_section() {
        // e.g. a config-level `[patch]` in .cargo/config.toml, which leaves the manifests clean
        let mut fx = Fx::clean();
        fx.lock_extra = Some(
            "\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n\
             source = \"registry+https://example.invalid/index\"\n"
                .to_string(),
        );
        assert_has(&fx.run().1, "serde", "lock-source");
    }

    #[test]
    fn t_probe_crates_are_held_to_the_same_source_rule() {
        let fx = Fx::clean();
        let dir = fx.write();
        let probe = dir.path().join("probes").join("demo");
        fs::create_dir_all(probe.join("src")).unwrap();
        fs::write(probe.join("Cargo.toml"), manifest("demo", "", "")).unwrap();
        fs::write(probe.join("src/lib.rs"), "").unwrap();
        // no lock file: a violation
        let (_, vs) = check_workspace(dir.path()).expect("check");
        assert_has(&vs, "probes/demo", "lockfile");
        // a lock with a git source, and a [patch] in the probe manifest
        fs::write(
            probe.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"ring\"\nversion = \"0.17.0\"\n\
             source = \"git+https://example.invalid/ring.git#0123456789abcdef0123456789abcdef01234567\"\n",
        )
        .unwrap();
        fs::write(
            probe.join("Cargo.toml"),
            format!(
                "{}\n[patch.crates-io]\nring = {{ git = \"https://example.invalid/ring.git\" }}\n",
                manifest("demo", "", "")
            ),
        )
        .unwrap();
        let (_, vs) = check_workspace(dir.path()).expect("check");
        assert_has(&vs, "ring", "lock-source");
        assert_has(&vs, "probes/demo", "patch");
        // a clean probe lock passes
        fs::write(probe.join("Cargo.toml"), manifest("demo", "", "")).unwrap();
        fs::write(
            probe.join("Cargo.lock"),
            format!("version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"0.0.0\"\n\n[[package]]\nname = \"ring\"\nversion = \"0.17.0\"\nsource = \"{CRATES_IO}\"\n"),
        )
        .unwrap();
        let (_, vs) = check_workspace(dir.path()).expect("check");
        assert_clean(&vs);
    }

    // F7: a source-less lock entry must be a member of that lock's own workspace ---------------

    /// Run the real `cargo generate-lockfile --offline` in `dir` (cargo from `CARGO`).
    fn generate_lock(dir: &Path) {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let out = Command::new(cargo)
            .args(["generate-lockfile", "--offline"])
            .current_dir(dir)
            .output()
            .expect("run cargo generate-lockfile");
        assert!(
            out.status.success(),
            "cargo generate-lockfile failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn t_config_patch_to_a_path_is_rejected() {
        let mut fx = Fx::clean();
        fx.add_dep("lunepack-cli", "anyhow = \"1\"");
        fx.lock_extra = None;
        let dir = fx.write();
        let vendor = dir.path().join("vendor/anyhow");
        fs::create_dir_all(vendor.join("src")).unwrap();
        fs::write(
            vendor.join("Cargo.toml"),
            "[package]\nname = \"anyhow\"\nversion = \"1.0.999\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(vendor.join("src/lib.rs"), "").unwrap();
        fs::create_dir_all(dir.path().join(".cargo")).unwrap();
        fs::write(
            dir.path().join(".cargo/config.toml"),
            "[patch.crates-io]\nanyhow = { path = \"vendor/anyhow\" }\n",
        )
        .unwrap();
        generate_lock(dir.path());
        let lock = fs::read_to_string(dir.path().join("Cargo.lock")).unwrap();
        assert!(
            lock.contains("name = \"anyhow\"\nversion = \"1.0.999\"\n\n"),
            "fixture: cargo should lock the patched anyhow without a source:\n{lock}"
        );
        let (_, vs) = check_workspace(dir.path()).expect("check");
        // The members in the real lock all match; only the patched crate is flagged.
        assert_eq!(
            vs.iter()
                .map(|x| (x.package.as_str(), x.rule))
                .collect::<Vec<_>>(),
            vec![("anyhow", "lock-source")],
            "got:\n{}",
            render(&vs)
        );
    }

    #[test]
    fn t_source_less_entry_with_a_member_name_but_another_version_is_rejected() {
        let mut fx = Fx::clean();
        fx.lock_extra =
            Some("\n[[package]]\nname = \"lunepack-core\"\nversion = \"9.9.9\"\n".to_string());
        assert_has(&fx.run().1, "lunepack-core", "lock-source");
    }

    #[test]
    fn t_probe_path_dependency_is_rejected() {
        let fx = Fx::clean();
        let dir = fx.write();
        let probe = dir.path().join("probes").join("demo");
        fs::create_dir_all(probe.join("src")).unwrap();
        fs::write(probe.join("src/lib.rs"), "").unwrap();
        // a real lock for a clean standalone probe: only the probe itself, which passes
        fs::write(
            probe.join("Cargo.toml"),
            format!("{}\n[workspace]\n", manifest("demo", "", "")),
        )
        .unwrap();
        generate_lock(&probe);
        assert_clean(&check_workspace(dir.path()).expect("check").1);
        // a path dependency outside the probe (`<tmp>/outside`): its lock entry has no source
        fs::write(
            probe.join("Cargo.toml"),
            format!(
                "{}\n[workspace]\n",
                manifest("demo", "", "outside = { path = \"../../../outside\" }")
            ),
        )
        .unwrap();
        generate_lock(&probe);
        let (_, vs) = check_workspace(dir.path()).expect("check");
        assert_has(&vs, "outside", "lock-source");
        // a probe whose own name cannot be read accepts no source-less entry
        fs::write(
            probe.join("Cargo.toml"),
            format!("{}\n[workspace]\n", manifest("demo", "", ""))
                .replace("version = \"0.0.0\"", "version = { workspace = true }"),
        )
        .unwrap();
        let (_, vs) = check_workspace(dir.path()).expect("check");
        assert_has(&vs, "probes/demo", "lockfile");
        assert_has(&vs, "demo", "lock-source");
    }

    #[test]
    fn t_missing_lock_file_is_a_violation() {
        let mut fx = Fx::clean();
        fx.lock_extra = None;
        assert_has(&fx.run().1, "<workspace>", "lockfile");
    }

    #[test]
    fn p_real_workspace_passes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let out = xtask_in(root, &["check-boundaries"]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "boundaries: ok (13 packages)"
        );
    }

    #[test]
    fn q_package_fields_are_checked() {
        let mut fx = Fx::clean();
        fx.edit("lunepack-http", |m| {
            *m = m.replace("edition = \"2024\"", "edition = \"2021\"")
        });
        assert_has(&fx.run().1, "lunepack-http", "edition");
        let mut fx = Fx::clean();
        fx.edit("lunepack-http", |m| {
            *m = m.replace("rust-version = \"1.88\"", "rust-version = \"1.89\"")
        });
        assert_has(&fx.run().1, "lunepack-http", "rust-version");
        let mut fx = Fx::clean();
        fx.edit("lunepack-http", |m| {
            *m = m.replace("MIT OR Apache-2.0", "MIT")
        });
        assert_has(&fx.run().1, "lunepack-http", "license");
        let mut fx = Fx::clean();
        fx.edit("lunepack-testkit", |m| {
            *m = m.replace("publish = false", "publish = true")
        });
        assert_has(&fx.run().1, "lunepack-testkit", "publish");
    }

    #[test]
    fn r_dev_dependencies_may_name_testkit_only() {
        let mut fx = Fx::clean();
        fx.append(
            "lunepack-core",
            "[dev-dependencies]\nlunepack-testkit = { path = \"../lunepack-testkit\" }",
        );
        assert_clean(&fx.run().1);
        let mut fx = Fx::clean();
        fx.append(
            "lunepack-core",
            "[dev-dependencies]\nlunepack-http = { path = \"../lunepack-http\" }",
        );
        assert_has(&fx.run().1, "lunepack-core", "edge");
    }

    #[test]
    fn s_members_under_probes_and_missing_exclude_are_rejected() {
        let mut fx = Fx::clean();
        fx.root = fx.root.replace("exclude = [\"probes\"]\n", "");
        assert_has(&fx.run().1, "<workspace>", "root-exclude");
        let mut fx = Fx::clean();
        fx.root = fx.root.replace(
            "members = [\"crates/*\"]",
            "members = [\"crates/*\", \"probes/p1\"]",
        );
        let dir = fx.write();
        let p = dir.path().join("probes/p1");
        fs::create_dir_all(p.join("src")).unwrap();
        fs::write(p.join("Cargo.toml"), manifest("p1", INHERIT, "")).unwrap();
        fs::write(p.join("src/lib.rs"), "").unwrap();
        let (_, vs) = check_workspace(dir.path()).unwrap();
        assert_has(&vs, "p1", "probes");
    }
}
