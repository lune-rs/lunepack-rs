//! Tests for `xtask key-files`: temp repos with an isolated git config, synthetic file names.

mod keyfiles {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use tempfile::TempDir;
    use xtask::keyfiles::{key_extension, parse_args};

    struct Fx {
        _tmp: TempDir,
        repo: PathBuf,
        gitconfig: PathBuf,
    }

    struct Out {
        code: i32,
        stdout: String,
        stderr: String,
    }

    impl Fx {
        fn new() -> Fx {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().canonicalize().unwrap();
            let fx = Fx {
                repo: root.join("repo"),
                gitconfig: root.join("gitconfig"),
                _tmp: tmp,
            };
            fs::create_dir_all(&fx.repo).unwrap();
            fs::write(&fx.gitconfig, "").unwrap();
            fx.git(&["init", "-q", "-b", "main"]);
            fx
        }

        fn command(&self, program: &str) -> Command {
            let mut c = Command::new(program);
            c.env_clear();
            c.env("PATH", std::env::var_os("PATH").unwrap_or_default());
            c.env("GIT_CONFIG_GLOBAL", &self.gitconfig);
            c.env("GIT_CONFIG_NOSYSTEM", "1");
            c.env("GIT_AUTHOR_NAME", "Synth Author");
            c.env("GIT_AUTHOR_EMAIL", "author@example.invalid");
            c.env("GIT_COMMITTER_NAME", "Synth Committer");
            c.env("GIT_COMMITTER_EMAIL", "committer@example.invalid");
            c
        }

        fn git(&self, args: &[&str]) -> String {
            let out = self
                .command("git")
                .args(["-c", "commit.gpgsign=false", "-c", "core.hooksPath="])
                .args(args)
                .current_dir(&self.repo)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        fn write(&self, rel: &str, bytes: &[u8]) {
            let p = self.repo.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, bytes).unwrap();
        }

        fn commit(&self, msg: &str) -> String {
            self.git(&["add", "-A"]);
            self.git(&["commit", "-q", "--allow-empty", "-m", msg]);
            self.git(&["rev-parse", "HEAD"])
        }

        fn scan(&self, args: &[&str]) -> Out {
            self.scan_in(&self.repo, args)
        }

        fn scan_in(&self, cwd: &Path, args: &[&str]) -> Out {
            let mut c = self.command(env!("CARGO_BIN_EXE_xtask"));
            c.env("GIT_CEILING_DIRECTORIES", cwd.parent().unwrap_or(cwd));
            let out = c
                .arg("key-files")
                .args(args)
                .current_dir(cwd)
                .output()
                .unwrap();
            Out {
                code: out.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            }
        }
    }

    #[test]
    fn clean_repo_is_ok() {
        let fx = Fx::new();
        fx.write("src/lib.rs", b"fn main() {}\n");
        fx.write("keys/README.md", b"notes\n");
        fx.commit("init");
        let out = fx.scan(&["--all"]);
        assert_eq!(out.code, 0, "{}", out.stderr);
        assert_eq!(out.stdout, "");
    }

    #[test]
    fn tracked_key_containers_fail_whatever_the_case_and_no_path_is_printed() {
        for name in [
            "certs/zqxsynth.pfx",
            "a/b/Server.P12",
            "x.KEY",
            "deep/dir/AuthKey_ABC.p8",
            "j.jks",
            "c.der",
            "t.keystore",
            "p.pem",
        ] {
            let fx = Fx::new();
            fx.write("ok.txt", b"fine\n");
            fx.write(name, b"\0\x01binary\0");
            fx.commit("init");
            let out = fx.scan(&[]);
            assert_eq!(out.code, 1, "{name}: {}", out.stderr);
            assert!(
                out.stdout.contains("tracked path #"),
                "{name}: {}",
                out.stdout
            );
            let all = format!("{}{}", out.stdout, out.stderr).to_lowercase();
            assert!(
                !all.contains("zqxsynth") && !all.contains("authkey"),
                "{name}: a path leaked into the output"
            );
        }
    }

    #[test]
    fn a_staged_but_uncommitted_key_container_fails() {
        let fx = Fx::new();
        fx.write("ok.txt", b"fine\n");
        fx.commit("init");
        fx.write("new/secret.p12", b"\0\x01");
        fx.git(&["add", "new/secret.p12"]);
        assert_eq!(fx.scan(&[]).code, 1);
    }

    #[test]
    fn history_finds_a_container_added_and_later_deleted_but_the_tip_does_not() {
        let fx = Fx::new();
        fx.write("ok.txt", b"fine\n");
        let c0 = fx.commit("init");
        fx.write("tmp/leaked.pfx", b"\0\x01");
        let c1 = fx.commit("add");
        fs::remove_file(fx.repo.join("tmp/leaked.pfx")).unwrap();
        fx.commit("remove");
        assert_eq!(fx.scan(&[]).code, 0, "tip is clean");
        let range = fx.scan(&["--range", &format!("{c0}..HEAD")]);
        assert_eq!(range.code, 1, "{}", range.stderr);
        assert!(
            range.stdout.contains(&format!("commit {}", &c1[..12])),
            "{}",
            range.stdout
        );
        assert_eq!(
            fx.scan(&["--range", &format!("{c1}..HEAD")]).code,
            1,
            "the deleting commit changes the path too"
        );
        assert_eq!(fx.scan(&["--all"]).code, 1);
    }

    #[test]
    fn evil_merge_adding_a_container_is_found() {
        let fx = Fx::new();
        fx.write("ok.txt", b"fine\n");
        let base = fx.commit("init");
        fx.git(&["branch", "side"]);
        fx.git(&["checkout", "-q", "side"]);
        fx.write("side.txt", b"s\n");
        fx.commit("side");
        fx.git(&["checkout", "-q", "main"]);
        fx.write("main.txt", b"m\n");
        fx.commit("main");
        fx.git(&["merge", "--no-commit", "--no-ff", "-q", "side"]);
        fx.write("merged/evil.pfx", b"\0\x01");
        fx.commit("merge");
        fx.git(&["rm", "-q", "-f", "merged/evil.pfx"]);
        fx.commit("remove again");
        assert_eq!(fx.scan(&["--range", &format!("{base}..HEAD")]).code, 1);
    }

    #[test]
    fn bad_arguments_and_non_repos_exit_2() {
        let fx = Fx::new();
        fx.commit("init");
        assert_eq!(fx.scan(&["--bogus"]).code, 2);
        assert_eq!(fx.scan(&["--all", "--range", "HEAD"]).code, 2);
        assert_eq!(fx.scan(&["--range", "no-such-ref..HEAD"]).code, 2);
        let plain = tempfile::tempdir().unwrap();
        let cwd = plain.path().canonicalize().unwrap();
        assert_eq!(fx.scan_in(&cwd, &[]).code, 2);
    }

    #[test]
    fn extension_matching_and_the_allowlist() {
        assert_eq!(key_extension(b"a/b.PEM", &[]), Some(".pem"));
        assert_eq!(key_extension(b"a/b.pem.txt", &[]), None);
        assert_eq!(key_extension(b"a/keys.md", &[]), None);
        assert_eq!(key_extension(b"noext", &[]), None);
        // exact entry and directory prefix
        assert_eq!(
            key_extension(b"t/fixtures/ca.pem", &["t/fixtures/ca.pem"]),
            None
        );
        assert_eq!(
            key_extension(b"t/fixtures/sub/ca.pem", &["t/fixtures/"]),
            None
        );
        assert_eq!(
            key_extension(b"t/other/ca.pem", &["t/fixtures/"]),
            Some(".pem")
        );
        assert_eq!(
            key_extension(b"t/fixturesx/ca.pem", &["t/fixtures/"]),
            Some(".pem")
        );
        // the shipped allowlist is empty: test keys are generated at test time
        assert!(xtask::keyfiles::ALLOWLIST.is_empty());
        assert!(parse_args(["--all".to_string()]).unwrap().all);
    }
}
