import subprocess

from demo.nimbus_cli import calls, install, ledger, main, shell_of


def test_deploy_and_migrate_are_recorded_status_reads(tmp_path, capsys):
    assert main(["deploy", "api-v2", "prod-eu"], tmp_path) == 0
    assert main(["migrate", "migration-0017", "prod-eu"], tmp_path) == 0
    assert main(["status", "prod-eu"], tmp_path) == 0
    assert main(["status", "prod-us"], tmp_path) == 0
    assert capsys.readouterr().out.splitlines() == [
        "Released api-v2 to prod-eu (simulated target)",
        "Migrated prod-eu with migration-0017 (simulated target)",
        "prod-eu: api-v2",
        "prod-us: nothing released",
    ]
    assert ledger(tmp_path) == [
        {"env": "prod-eu", "op": "deploy", "target": "api-v2"},
        {"env": "prod-eu", "op": "migrate", "target": "migration-0017"},
    ]


def test_unknown_shapes_are_usage_errors_and_record_nothing(tmp_path, capsys):
    for argv in ([], ["deploy", "api-v2"], ["rollback", "api-v2", "prod-eu"]):
        assert main(argv, tmp_path) == 2
    assert capsys.readouterr().err.count("usage: nimbus") == 3
    assert ledger(tmp_path) == []


def test_every_invocation_is_traced_even_when_it_records_nothing(tmp_path):
    assert ledger(tmp_path) == []
    assert calls(tmp_path) == []
    main(["status", "prod-eu"], tmp_path)
    main(["rollback"], tmp_path)
    assert [c["argv"] for c in calls(tmp_path)] == [["status", "prod-eu"], ["rollback"]]
    assert ledger(tmp_path) == []
    for call in calls(tmp_path):
        assert set(call) == {"argv", "parent", "exec_path"}
        assert isinstance(call["parent"], str)
        assert isinstance(call["exec_path"], str)


def test_launcher_runs_from_a_shell_on_path(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    work = tmp_path / "work tree"
    work.mkdir()
    install(bin_dir)
    run = subprocess.run(  # noqa: S603
        ["/bin/sh", "-c", "nimbus deploy api-v2 prod-eu"],  # noqa: S607
        cwd=work,
        env={"PATH": f"{bin_dir}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=True,
    )
    assert run.stdout == "Released api-v2 to prod-eu (simulated target)\n"
    assert ledger(work) == [{"env": "prod-eu", "op": "deploy", "target": "api-v2"}]


def test_launcher_is_exact(tmp_path):
    launcher = install(tmp_path)
    assert launcher == tmp_path / "nimbus"
    assert launcher.stat().st_mode & 0o777 == 0o755
    first, second, end = launcher.read_text().split("\n")
    assert first == "#!/bin/sh"
    assert second.startswith("exec ") and second.endswith(' "$@"')
    assert " -I " in second and second.split()[-2].endswith("/demo/nimbus_cli.py")
    assert end == ""


def test_the_trace_names_the_shell_that_ran_the_launcher(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    launcher = install(bin_dir)
    subprocess.run(  # noqa: S603
        ["/bin/sh", "-c", "nimbus status prod-eu; true"],  # noqa: S607
        cwd=tmp_path,
        env={"PATH": f"{bin_dir}:/usr/bin:/bin"},
        check=True,
        capture_output=True,
    )
    [call] = calls(tmp_path)
    assert call["argv"] == ["status", "prod-eu"]
    assert shell_of(call, launcher) == "sh"


def test_shell_of_reads_the_parent_or_the_path_a_shell_exports(tmp_path):
    launcher = tmp_path / "bin" / "nimbus"
    exported = {"exec_path": str(launcher)}
    assert shell_of({"parent": "/bin/zsh", "exec_path": ""}, launcher) == "zsh"
    assert shell_of({"parent": "-bash", "exec_path": ""}, launcher) == "bash"
    assert shell_of({"parent": "dash", "exec_path": ""}, launcher) == "dash"
    assert shell_of({"parent": "muse", **exported}, launcher) == "bash, zsh or sh"
    assert shell_of({"parent": "muse", "exec_path": ""}, launcher) is None
    assert shell_of({"parent": "fish", "exec_path": "/usr/bin/x"}, launcher) is None
    assert shell_of({"parent": "", "exec_path": ""}, launcher) is None
