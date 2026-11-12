//! Tests for `xtask denylist-scan`. Synthetic terms only: the real denylist is never read.
//!
//! Every scan runs the binary with a cleared environment plus an explicit PATH, a temp HOME,
//! a temp XDG_CONFIG_HOME, a temp LUNEPACK_DENYLIST and an isolated git config. Every
//! `scan` call also asserts that no term of the denylist under test (case-insensitively)
//! occurs in stdout or stderr.

mod denylist {
    use std::cell::RefCell;
    use std::ffi::OsStr;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use tempfile::TempDir;

    struct Out {
        code: i32,
        stdout: String,
        stderr: String,
    }

    #[derive(Clone)]
    struct Env {
        deny: Option<PathBuf>,
        xdg: Option<PathBuf>,
        home: Option<PathBuf>,
    }

    struct Fx {
        _tmp: TempDir,
        root: PathBuf,
        repo: PathBuf,
        home: PathBuf,
        xdg: PathBuf,
        deny: PathBuf,
        gitconfig: PathBuf,
        terms: RefCell<Vec<String>>,
    }

    /// Terms of a denylist text, derived independently of the code under test.
    fn terms_of(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        for line in text.split('\n') {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            for t in line.split("&&") {
                let t = t.trim().to_lowercase();
                if !t.is_empty() {
                    out.push(t);
                }
            }
        }
        out
    }

    fn base_command(program: impl AsRef<OsStr>, env: &Env, gitconfig: &Path) -> Command {
        let mut c = Command::new(program);
        c.env_clear();
        c.env("PATH", std::env::var_os("PATH").unwrap_or_default());
        #[cfg(windows)]
        for key in ["SystemRoot", "SYSTEMROOT", "TEMP", "TMP"] {
            if let Some(v) = std::env::var_os(key) {
                c.env(key, v);
            }
        }
        if let Some(h) = &env.home {
            c.env("HOME", h);
        }
        if let Some(x) = &env.xdg {
            c.env("XDG_CONFIG_HOME", x);
        }
        if let Some(d) = &env.deny {
            c.env("LUNEPACK_DENYLIST", d);
        }
        c.env("GIT_CONFIG_GLOBAL", gitconfig);
        c.env("GIT_CONFIG_NOSYSTEM", "1");
        c.env("GIT_AUTHOR_NAME", "Synth Author");
        c.env("GIT_AUTHOR_EMAIL", "author@example.invalid");
        c.env("GIT_COMMITTER_NAME", "Synth Committer");
        c.env("GIT_COMMITTER_EMAIL", "committer@example.invalid");
        c
    }

    impl Fx {
        fn new() -> Fx {
            let tmp = tempfile::tempdir().expect("tempdir");
            let root = tmp.path().canonicalize().unwrap();
            let fx = Fx {
                repo: root.join("repo"),
                home: root.join("home"),
                xdg: root.join("xdg"),
                deny: root.join("deny.txt"),
                gitconfig: root.join("gitconfig"),
                root,
                _tmp: tmp,
                terms: RefCell::new(Vec::new()),
            };
            for d in [&fx.repo, &fx.home, &fx.xdg] {
                fs::create_dir_all(d).unwrap();
            }
            fs::write(&fx.gitconfig, "").unwrap();
            fx.git(&["init", "-q", "-b", "main"]);
            fx
        }

        fn env(&self) -> Env {
            Env {
                deny: Some(self.deny.clone()),
                xdg: Some(self.xdg.clone()),
                home: Some(self.home.clone()),
            }
        }

        fn git_in(&self, dir: &Path, args: &[&str]) -> String {
            self.git_env_in(dir, &[], args)
        }

        fn git_env_in(&self, dir: &Path, envs: &[(&str, &str)], args: &[&str]) -> String {
            let mut c = base_command("git", &self.env(), &self.gitconfig);
            c.env("GIT_CEILING_DIRECTORIES", &self.root);
            for (k, v) in envs {
                c.env(k, v);
            }
            let out = c
                .args([
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    "core.hooksPath=",
                    "-c",
                    "core.autocrlf=false",
                ])
                .args(args)
                .current_dir(dir)
                .output()
                .expect("run git");
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        fn git(&self, args: &[&str]) -> String {
            self.git_in(&self.repo, args)
        }

        fn write(&self, rel: &str, bytes: impl AsRef<[u8]>) {
            let p = self.repo.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, bytes).unwrap();
        }

        fn commit(&self, msg: &str) -> String {
            self.commit_env(&[], msg)
        }

        fn commit_env(&self, envs: &[(&str, &str)], msg: &str) -> String {
            self.git(&["add", "-A"]);
            self.git_env_in(
                &self.repo,
                envs,
                &["commit", "-q", "--allow-empty", "-m", msg],
            );
            self.git(&["rev-parse", "HEAD"])
        }

        /// Write the denylist file (mode 0600 on Unix) and remember its terms.
        fn deny(&self, text: &str) {
            self.deny_bytes(text.as_bytes());
            self.terms.borrow_mut().extend(terms_of(text));
        }

        fn deny_bytes(&self, bytes: &[u8]) {
            fs::write(&self.deny, bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&self.deny, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }

        fn scan(&self, args: &[&str]) -> Out {
            self.scan_with(&self.env(), &self.repo, args)
        }

        fn scan_with(&self, env: &Env, cwd: &Path, args: &[&str]) -> Out {
            let mut c = base_command(env!("CARGO_BIN_EXE_xtask"), env, &self.gitconfig);
            c.env("GIT_CEILING_DIRECTORIES", &self.root);
            let out = c
                .arg("denylist-scan")
                .args(args)
                .current_dir(cwd)
                .output()
                .expect("run xtask");
            let out = Out {
                code: out.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            };
            let all = format!("{}\n{}", out.stdout, out.stderr).to_lowercase();
            for t in self.terms.borrow().iter() {
                assert!(
                    !all.contains(t.as_str()),
                    "a denylist term leaked into the output"
                );
            }
            out
        }
    }

    fn lines(s: &str) -> Vec<&str> {
        s.lines().collect()
    }

    // (1) ---------------------------------------------------------------------------------
    #[test]
    fn t01_plain_term_hit_with_path_line_and_rule() {
        let fx = Fx::new();
        fx.write("src/a.txt", "line one\nhas zqxalpha here\n");
        fx.write("src/b.txt", "clean\n");
        fx.commit("init");
        fx.deny("# header\nzqxalpha\n");
        let out = fx.scan(&[]);
        assert_eq!(out.code, 1, "{}", out.stderr);
        assert_eq!(lines(&out.stdout), ["denylist: src/a.txt:2: rule 2"]);
        assert!(
            out.stderr.contains("denylist: 1 rules, 1 hits"),
            "{}",
            out.stderr
        );

        // `--repo` from another working directory behaves the same.
        let out = fx.scan_with(&fx.env(), &fx.root, &["--repo", fx.repo.to_str().unwrap()]);
        assert_eq!(out.code, 1);
        assert_eq!(lines(&out.stdout), ["denylist: src/a.txt:2: rule 2"]);
    }

    // (2) ---------------------------------------------------------------------------------
    #[test]
    fn t02_case_insensitive_both_ways() {
        let fx = Fx::new();
        fx.write("up.txt", "has ZqxALPHA\n");
        fx.write("low.txt", "has zqxbeta\n");
        fx.commit("init");
        fx.deny("zqxalpha\nZQXBETA\n");
        let out = fx.scan(&[]);
        assert_eq!(out.code, 1);
        assert_eq!(
            lines(&out.stdout),
            ["denylist: low.txt:1: rule 2", "denylist: up.txt:1: rule 1"]
        );
    }

    // (3) ---------------------------------------------------------------------------------
    #[test]
    fn t03_slash_term_in_content_and_in_path_is_redacted() {
        let fx = Fx::new();
        fx.write("notes.txt", "see zqx/gamma/x\n");
        fx.write("zqx/gamma/file.txt", "innocent\n");
        fx.write("other/zqx/gamma/more.txt", "mentions zqx/gamma too\n");
        fx.commit("init");
        fx.deny("zqx/gamma\n");
        let out = fx.scan(&[]);
        assert_eq!(out.code, 1);
        let l = lines(&out.stdout);
        assert!(l.contains(&"denylist: notes.txt:1: rule 1"), "{l:?}");
        assert!(
            l.iter().any(
                |x| x.starts_with("denylist: path <redacted path #") && x.ends_with(": rule 1")
            ),
            "{l:?}"
        );
        assert!(
            l.iter()
                .any(|x| x.starts_with("denylist: <redacted path #") && x.ends_with(":1: rule 1")),
            "{l:?}"
        );
        assert!(
            !out.stdout.contains("file.txt") && !out.stdout.contains("more.txt"),
            "{l:?}"
        );
    }

    // (4) ---------------------------------------------------------------------------------
    #[test]
    fn t04_and_rules_need_every_term_on_one_line() {
        let fx = Fx::new();
        fx.write("f1.txt", "zqxaa and zqxbb together\n");
        fx.write("f2.txt", "zqxaa\nzqxbb\n");
        fx.write("zqxaa.txt", "zqxbb\n");
        fx.commit("init");
        for text in [
            "zqxaa && zqxbb\n",
            "zqxaa&&zqxbb\n",
            "  zqxaa  &&   zqxbb  \n",
            "zqxbb && zqxaa\n",
        ] {
            fx.deny(text);
            let out = fx.scan(&[]);
            assert_eq!(out.code, 1, "{text:?}: {}", out.stderr);
            assert_eq!(
                lines(&out.stdout),
                ["denylist: f1.txt:1: rule 1"],
                "{text:?}"
            );
        }
    }

    // (5) ---------------------------------------------------------------------------------
    #[test]
    fn t05_fixed_strings_not_regexes_and_dash_terms() {
        let fx = Fx::new();
        fx.write("abc.txt", "abc\n");
        fx.write("dot.txt", "a.c\n");
        fx.write("dash.txt", "x -zqxdash y\n");
        fx.commit("init");
        fx.deny("a.c\n");
        let out = fx.scan(&[]);
        assert_eq!(out.code, 1);
        assert_eq!(lines(&out.stdout), ["denylist: dot.txt:1: rule 1"]);
        fx.deny("-zqxdash\n");
        let out = fx.scan(&[]);
        assert_eq!(out.code, 1);
        assert_eq!(lines(&out.stdout), ["denylist: dash.txt:1: rule 1"]);
    }

    // (6) ---------------------------------------------------------------------------------
    #[test]
    fn t06_comments_blanks_and_crlf_keep_physical_line_numbers() {
        let fx = Fx::new();
        fx.write("a.txt", "zqxrule\r\nsecond zqxother\r\n");
        fx.commit("init");
        fx.deny("# comment\r\n\r\n   # indented comment\r\nzqxrule\r\n\r\nzqxother\r\n");
        let out = fx.scan(&[]);
        assert_eq!(out.code, 1);
        assert_eq!(
            lines(&out.stdout),
            ["denylist: a.txt:1: rule 4", "denylist: a.txt:2: rule 6"]
        );
    }

    // (7) ---------------------------------------------------------------------------------
    #[test]
    fn t07_malformed_denylists_exit_2() {
        let fx = Fx::new();
        fx.write("a.txt", "x\n");
        fx.commit("init");
        fx.deny("zqxok\nzqxfoo &&\n");
        let out = fx.scan(&[]);
        assert_eq!(out.code, 2);
        assert!(out.stderr.contains("line 2"), "{}", out.stderr);
        fx.deny("&& zqxfoo\n");
        assert_eq!(fx.scan(&[]).code, 2);
        fx.deny("zqxa && && zqxb\n");
        assert_eq!(fx.scan(&[]).code, 2);
        fx.deny_bytes(b"zqxok\n\xff\xfe zqxbad\n");
        let out = fx.scan(&[]);
        assert_eq!(out.code, 2);
        assert!(out.stderr.contains("line 2"), "{}", out.stderr);
    }

    // (8) ---------------------------------------------------------------------------------
    #[test]
    fn t08_range_scan_covers_messages_paths_added_lines_binary_merges_authors() {
        let fx = Fx::new();
        fx.write("keep.txt", "base\n");
        let _c1 = fx.commit("init");
        fx.write("other.txt", "x\n");
        let c2 = fx.commit("mentions zqxmsg in the message");
        fx.write("zqxpathdel.txt", "innocent\n");
        let c3 = fx.commit("add file");
        fs::remove_file(fx.repo.join("zqxpathdel.txt")).unwrap();
        let c4 = fx.commit("delete file");
        fx.write("keep.txt", "base\nadded zqxaddline\n");
        let c5 = fx.commit("add line");
        fx.write("keep.txt", "base\n");
        let _c6 = fx.commit("remove line");
        fx.write("bin.dat", b"\0\0zqxbinary\0".as_slice());
        let c7 = fx.commit("binary");
        fx.write("auth.txt", "a\n");
        let c8 = fx.commit_env(&[("GIT_AUTHOR_NAME", "Zqxauthor Person")], "by an author");
        fx.git(&["branch", "side"]);
        fx.git(&["checkout", "-q", "side"]);
        fx.write("side.txt", "s\n");
        fx.commit("side");
        fx.git(&["checkout", "-q", "main"]);
        fx.write("main.txt", "m\n");
        fx.commit("main");
        fx.git(&["merge", "--no-commit", "--no-ff", "-q", "side"]);
        fx.write("merged.txt", "zqxevil\n");
        let merge = fx.commit("merge");

        fx.deny("zqxmsg\nzqxpathdel\nzqxaddline\nzqxbinary\nzqxevil\nzqxauthor\n");
        let out = fx.scan(&["--range", "HEAD"]);
        assert_eq!(out.code, 1, "{}", out.stderr);
        let s = |sha: &str| sha[..12].to_string();
        let l = lines(&out.stdout);
        let has =
            |needle: String| assert!(l.contains(&needle.as_str()), "missing `{needle}` in {l:?}");
        has(format!("denylist: commit {} object line 6: rule 1", s(&c2)));
        let redacted = |sha: &str, rule: usize| {
            let pre = format!("denylist: commit {} path <redacted path #", s(sha));
            assert!(
                l.iter()
                    .any(|x| x.starts_with(&pre) && x.ends_with(&format!(": rule {rule}"))),
                "missing path hit for {} in {l:?}",
                s(sha)
            );
        };
        redacted(&c3, 2);
        redacted(&c4, 2);
        has(format!("denylist: commit {} keep.txt:2: rule 3", s(&c5)));
        has(format!("denylist: commit {} bin.dat:1: rule 4", s(&c7)));
        has(format!("denylist: commit {} object line 3: rule 6", s(&c8)));
        has(format!(
            "denylist: commit {} merged.txt:1: rule 5",
            s(&merge)
        ));
        // The added-then-removed line is gone from the tree: only history finds it.
        let tree_only = fx.scan(&[]);
        assert!(!tree_only.stdout.contains("rule 3"), "{}", tree_only.stdout);
        assert!(tree_only.stdout.contains("bin.dat:1: rule 4"));
    }

    // (9) ---------------------------------------------------------------------------------
    #[test]
    fn t09_bad_range_and_non_repo_exit_2() {
        let fx = Fx::new();
        fx.write("a.txt", "x\n");
        fx.commit("init");
        fx.deny("zqxterm\n");
        let out = fx.scan(&["--range", "no-such-ref..HEAD"]);
        assert_eq!(out.code, 2, "{}", out.stderr);
        assert!(out.stderr.contains("git rev-list failed"), "{}", out.stderr);
        let plain = fx.root.join("not-a-repo");
        fs::create_dir_all(&plain).unwrap();
        let out = fx.scan_with(&fx.env(), &plain, &[]);
        assert_eq!(out.code, 2, "{}", out.stderr);
        assert!(
            out.stderr.contains("git show-toplevel failed"),
            "{}",
            out.stderr
        );
        assert_eq!(fx.scan(&["--bogus"]).code, 2);
        assert_eq!(fx.scan(&["--range"]).code, 2);
    }

    // (10) --------------------------------------------------------------------------------
    #[test]
    fn t10_require_denylist_and_in_tree_denylist() {
        let fx = Fx::new();
        fx.write("a.txt", "x\n");
        fx.commit("init");

        // Missing (default path), comments-only: 2 with the flag.
        let default_env = Env {
            deny: None,
            ..fx.env()
        };
        assert_eq!(
            fx.scan_with(&default_env, &fx.repo, &["--require-denylist"])
                .code,
            2
        );
        fx.deny("# only a comment\n\n");
        assert_eq!(fx.scan(&["--require-denylist"]).code, 2);
        // ... and a notice plus 0 without the flag.
        let out = fx.scan(&[]);
        assert_eq!(out.code, 0);
        assert!(out.stderr.contains("no rules"), "{}", out.stderr);

        // Unreadable (Unix, not root).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fx.deny("zqxterm\n");
            fs::set_permissions(&fx.deny, fs::Permissions::from_mode(0o000)).unwrap();
            if fs::File::open(&fx.deny).is_err() {
                assert_eq!(fx.scan(&["--require-denylist"]).code, 2);
                assert_eq!(fx.scan(&[]).code, 2);
            }
            fs::set_permissions(&fx.deny, fs::Permissions::from_mode(0o600)).unwrap();
        }

        // A denylist inside the work tree fails with and without the flag.
        let inside = fx.repo.join("sub/deny.txt");
        fs::create_dir_all(inside.parent().unwrap()).unwrap();
        fs::write(&inside, "zqxinside\n").unwrap();
        fx.terms.borrow_mut().push("zqxinside".into());
        let env = Env {
            deny: Some(inside.clone()),
            ..fx.env()
        };
        let out = fx.scan_with(&env, &fx.repo, &[]);
        assert_eq!(out.code, 2);
        assert!(
            out.stderr.contains("inside the repository"),
            "{}",
            out.stderr
        );
        assert_eq!(
            fx.scan_with(&env, &fx.repo, &["--require-denylist"]).code,
            2
        );

        // A denylist inside the main checkout, scanned from a linked worktree, fails too.
        let wt = fx.root.join("linked");
        fx.git(&["worktree", "add", "-q", wt.to_str().unwrap(), "-b", "other"]);
        let env = Env {
            deny: Some(inside),
            ..fx.env()
        };
        let out = fx.scan_with(&env, &wt, &[]);
        assert_eq!(out.code, 2, "{}", out.stderr);
    }

    // (11) --------------------------------------------------------------------------------
    #[test]
    fn t11_absent_default_skips_explicit_missing_fails() {
        let fx = Fx::new();
        fx.write("a.txt", "x\n");
        fx.commit("init");
        let default_env = Env {
            deny: None,
            ..fx.env()
        };
        let out = fx.scan_with(&default_env, &fx.repo, &[]);
        assert_eq!(out.code, 0);
        assert!(
            out.stderr.contains("denylist not found; scan skipped"),
            "{}",
            out.stderr
        );

        let missing = Env {
            deny: Some(fx.root.join("nope.txt")),
            ..fx.env()
        };
        assert_eq!(fx.scan_with(&missing, &fx.repo, &[]).code, 2);

        // No HOME and no XDG_CONFIG_HOME: the location is absent, not an error.
        let bare = Env {
            deny: None,
            xdg: None,
            home: None,
        };
        let out = fx.scan_with(&bare, &fx.repo, &[]);
        assert_eq!(out.code, 0);
        assert!(out.stderr.contains("scan skipped"), "{}", out.stderr);
        assert_eq!(
            fx.scan_with(&bare, &fx.repo, &["--require-denylist"]).code,
            2
        );
    }

    // (12) --------------------------------------------------------------------------------
    #[test]
    fn t12_uncommitted_edits_and_work_tree_deletions_are_scanned() {
        let fx = Fx::new();
        fx.write("edited.txt", "clean\n");
        fx.write("gone.txt", "has zqxdeleted\n");
        fx.commit("init");
        fx.write("edited.txt", "clean\nnew zqxedit line\n");
        fs::remove_file(fx.repo.join("gone.txt")).unwrap();
        fx.deny("zqxedit\nzqxdeleted\n");
        let out = fx.scan(&[]);
        assert_eq!(out.code, 1, "{}", out.stderr);
        assert_eq!(
            lines(&out.stdout),
            [
                "denylist: edited.txt:2: rule 1",
                "denylist: gone.txt:1: rule 2"
            ]
        );
    }

    // (13) --------------------------------------------------------------------------------
    #[test]
    fn t13_default_path_resolution() {
        let fx = Fx::new();
        fx.write("a.txt", "has zqxxdg\nhas zqxhome\n");
        fx.commit("init");
        let xdg_file = fx.xdg.join("lunepack-rs/denylist.txt");
        let home_file = fx.home.join(".config/lunepack-rs/denylist.txt");
        fs::create_dir_all(xdg_file.parent().unwrap()).unwrap();
        fs::create_dir_all(home_file.parent().unwrap()).unwrap();
        fs::write(&xdg_file, "zqxxdg\n").unwrap();
        fs::write(&home_file, "zqxhome\n").unwrap();
        fx.terms
            .borrow_mut()
            .extend(["zqxxdg".to_string(), "zqxhome".to_string()]);
        let none = Env {
            deny: None,
            ..fx.env()
        };

        // XDG_CONFIG_HOME wins over HOME.
        let out = fx.scan_with(&none, &fx.repo, &[]);
        assert_eq!(
            lines(&out.stdout),
            ["denylist: a.txt:1: rule 1"],
            "{}",
            out.stderr
        );
        // An empty XDG_CONFIG_HOME falls through to HOME.
        let empty_xdg = Env {
            xdg: Some(PathBuf::new()),
            ..none.clone()
        };
        let out = fx.scan_with(&empty_xdg, &fx.repo, &[]);
        assert_eq!(
            lines(&out.stdout),
            ["denylist: a.txt:2: rule 1"],
            "{}",
            out.stderr
        );
        // Unset XDG_CONFIG_HOME: HOME/.config.
        let no_xdg = Env {
            xdg: None,
            ..none.clone()
        };
        let out = fx.scan_with(&no_xdg, &fx.repo, &[]);
        assert_eq!(
            lines(&out.stdout),
            ["denylist: a.txt:2: rule 1"],
            "{}",
            out.stderr
        );
        // LUNEPACK_DENYLIST beats both, and an empty one is ignored.
        let other = fx.root.join("explicit.txt");
        fs::write(&other, "nothing-here-zqxnone\n").unwrap();
        fx.terms.borrow_mut().push("nothing-here-zqxnone".into());
        let explicit = Env {
            deny: Some(other),
            ..fx.env()
        };
        let out = fx.scan_with(&explicit, &fx.repo, &[]);
        assert_eq!(out.code, 0, "{}", out.stderr);
        let empty_deny = Env {
            deny: Some(PathBuf::new()),
            ..fx.env()
        };
        let out = fx.scan_with(&empty_deny, &fx.repo, &[]);
        assert_eq!(
            lines(&out.stdout),
            ["denylist: a.txt:1: rule 1"],
            "{}",
            out.stderr
        );
    }

    // Extra coverage of tree-scan rules ---------------------------------------------------
    #[test]
    fn t14_lossy_non_utf8_content_and_gitlink() {
        let fx = Fx::new();
        fx.write("latin.txt", b"\xff\xfe has zqxlossy\n".as_slice());
        fx.commit("init");
        fx.deny("zqxlossy\n");
        let out = fx.scan(&[]);
        assert_eq!(
            lines(&out.stdout),
            ["denylist: latin.txt:1: rule 1"],
            "{}",
            out.stderr
        );

        // A gitlink (submodule) entry cannot be scanned: exit 2.
        let sha = fx.git(&["rev-parse", "HEAD"]);
        fx.git(&[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{sha},sub"),
        ]);
        let out = fx.scan(&[]);
        assert_eq!(out.code, 2, "{}", out.stderr);
        assert!(out.stderr.contains("gitlink"), "{}", out.stderr);
    }

    #[cfg(unix)]
    #[test]
    fn t15_symlink_text_is_scanned_not_followed() {
        let fx = Fx::new();
        fx.write("target.txt", "innocent\n");
        std::os::unix::fs::symlink("zqxlink-target-text", fx.repo.join("link")).unwrap();
        fx.commit("init");
        fx.deny("zqxlink\n");
        let out = fx.scan(&[]);
        assert_eq!(
            lines(&out.stdout),
            ["denylist: link:1: rule 1"],
            "{}",
            out.stderr
        );
    }

    #[test]
    fn t16_clean_repo_exits_0_with_summary() {
        let fx = Fx::new();
        fx.write("a.txt", "nothing to see\n");
        fx.commit("init");
        fx.deny("zqxnever\n");
        let out = fx.scan(&["--range", "HEAD"]);
        assert_eq!(out.code, 0, "{}", out.stderr);
        assert_eq!(out.stdout, "");
        assert!(
            out.stderr.contains("denylist: 1 rules, 0 hits"),
            "{}",
            out.stderr
        );
    }
}
