import base64
import unittest
from urllib.parse import urlparse

from repoguard.errors import RepoGuardError
from repoguard.github_client import GitHubClient
from repoguard.limits import MAX_FILE_BYTES, MAX_FILES
from repoguard.scanner import is_risk_file, scan, select_risk_files
from support import NOW, blob, load_fixture, load_json, scripted


def _file(text: str) -> dict:
    raw = text.encode("utf-8")
    return {
        "type": "file",
        "encoding": "base64",
        "size": len(raw),
        "content": base64.b64encode(raw).decode("ascii"),
    }


def _client(routes: dict, calls: list[str] | None = None) -> GitHubClient:
    return GitHubClient(transport=scripted(routes, calls))


def _base_routes(tree: dict, files: dict[str, str] | None = None, ref: str = "main") -> dict:
    repo = load_json("repo.json")
    routes = {
        "/repos/acme/widget": (200, repo),
        "/users/acme": (200, load_json("owner.json")),
        "/repos/acme/widget/commits": (200, [{}, {}, {}, {}, {}]),
        "/repos/acme/widget/releases": (200, []),
        f"/repos/acme/widget/git/trees/{ref}": (200, tree),
    }
    for path, text in (files or {}).items():
        quoted = urlparse("http://local/" + path).path
        routes[f"/repos/acme/widget/contents{quoted}"] = (200, _file(text))
    return routes


class SelectionTests(unittest.TestCase):
    def test_priority_and_cap(self) -> None:
        entries = [blob("README.md"), blob("package.json"), blob(".github/workflows/ci.yml")]
        chosen, skipped = select_risk_files(entries, limit=1)
        self.assertEqual(chosen, [".github/workflows/ci.yml"])
        self.assertEqual(skipped, [])

        workflows = [blob(f".github/workflows/wf-{index:02d}.yml") for index in range(40)]
        huge = blob(".github/workflows/huge.yml", size=MAX_FILE_BYTES + 1)
        exact = blob(".github/workflows/exact.yml", size=MAX_FILE_BYTES)
        chosen, skipped = select_risk_files([*workflows, huge, exact, blob("README.md")])
        self.assertEqual(len(chosen), MAX_FILES)
        self.assertEqual(skipped, [".github/workflows/huge.yml"])
        self.assertIn(".github/workflows/exact.yml", chosen)
        self.assertNotIn("README.md", chosen)
        self.assertNotIn(".github/workflows/huge.yml", chosen)

    def test_risk_paths(self) -> None:
        self.assertTrue(is_risk_file("README"))
        self.assertTrue(is_risk_file("scripts/setup.ps1"))
        self.assertTrue(is_risk_file("setup.sh"))
        self.assertTrue(is_risk_file("requirements-dev.txt"))
        self.assertTrue(is_risk_file("docker/Dockerfile"))
        self.assertTrue(is_risk_file("id_rsa"))
        self.assertTrue(is_risk_file("server.pem"))
        self.assertTrue(is_risk_file(".env"))
        self.assertFalse(is_risk_file(".env.example"))
        self.assertTrue(is_risk_file("install.js"))
        self.assertTrue(is_risk_file("scripts/app.js"))
        self.assertFalse(is_risk_file("lib/app.js"))
        self.assertFalse(is_risk_file("lib/setup.sh"))
        self.assertFalse(is_risk_file("src/app.py"))
        self.assertFalse(is_risk_file("notreadme.txt"))


class ScanTests(unittest.TestCase):
    def test_clean_repository_is_apto(self) -> None:
        routes = _base_routes(
            {"truncated": False, "tree": [{"path": "README.md", "type": "blob", "size": 20}]},
            {"README.md": "Projeto de exemplo.\n"},
        )
        report = scan("https://github.com/acme/widget", client=_client(routes), now=NOW)
        self.assertEqual(report.verdict, "apto")
        self.assertEqual(report.risk_score, 0)
        self.assertEqual(report.findings, ())
        self.assertEqual(report.stats["files_read"], 1)
        self.assertEqual(report.stats["license"], "MIT")
        self.assertGreater(report.stats["age_days"], 180)
        payload = report.to_dict()
        self.assertEqual(set(payload), {"repo", "html_url", "ref", "verdict", "risk_score", "findings", "stats"})

    def test_versioned_executable_needs_review(self) -> None:
        routes = _base_routes(
            {
                "truncated": False,
                "tree": [
                    {"path": "README.md", "type": "blob", "size": 20},
                    {"path": "bin/tool.exe", "type": "blob", "size": 20},
                ],
            },
            {"README.md": "Projeto de exemplo.\n"},
        )
        report = scan("acme/widget", client=_client(routes), now=NOW)
        self.assertEqual(report.verdict, "revisar")
        self.assertEqual(report.risk_score, 25)
        self.assertEqual(report.findings[0].rule_id, "tree.binario_executavel")

    def test_remote_install_hook_blocks_clone(self) -> None:
        package = load_fixture("package_hook.json")
        routes = _base_routes(
            {"truncated": False, "tree": [{"path": "package.json", "type": "blob", "size": len(package)}]},
            {"package.json": package},
        )
        report = scan("acme/widget", client=_client(routes), now=NOW)
        self.assertEqual(report.verdict, "nao_clonar")
        self.assertEqual(report.risk_score, 40)
        self.assertEqual(report.findings[0].rule_id, "install.hook_rede")
        self.assertLessEqual(len(report.findings[0].evidence or ""), 160)

    def test_content_cap_and_large_file(self) -> None:
        calls: list[str] = []
        tree = [
            {"path": f".github/workflows/wf-{index:02d}.yml", "type": "blob", "size": 30}
            for index in range(40)
        ]
        tree.append({"path": ".github/workflows/huge.yml", "type": "blob", "size": MAX_FILE_BYTES + 1})
        routes = _base_routes({"truncated": False, "tree": tree})
        report = scan("acme/widget", client=_client(routes, calls), now=NOW)
        content_calls = [path for path in calls if "/contents/" in path]
        self.assertEqual(len(content_calls), MAX_FILES)
        self.assertFalse(any(path.endswith("huge.yml") for path in content_calls))
        self.assertEqual(report.stats["files_skipped_large"], [".github/workflows/huge.yml"])
        self.assertEqual(report.verdict, "apto")

    def test_truncated_tree_does_not_block_by_itself(self) -> None:
        routes = _base_routes({"truncated": True, "tree": []})
        report = scan("acme/widget", client=_client(routes), now=NOW)
        self.assertEqual(report.findings[0].rule_id, "tree.truncada")
        self.assertEqual(report.verdict, "apto")

    def test_ref_flag_overrides_the_url(self) -> None:
        calls: list[str] = []
        routes = _base_routes({"truncated": False, "tree": []}, ref="release")
        scan(
            "https://github.com/acme/widget/tree/feature",
            ref="release",
            client=_client(routes, calls),
            now=NOW,
        )
        self.assertIn("/repos/acme/widget/git/trees/release", calls)
        self.assertNotIn("/repos/acme/widget/git/trees/feature", calls)

    def test_blank_ref_and_missing_repository(self) -> None:
        with self.assertRaises(RepoGuardError) as caught:
            scan("acme/widget", ref=" ", client=_client({"/repos/acme/widget": (200, load_json("repo.json"))}), now=NOW)
        self.assertIn("vazia", str(caught.exception))

        with self.assertRaises(RepoGuardError) as caught:
            scan("acme/missing", client=_client({}), now=NOW)
        self.assertIn("acme/missing", str(caught.exception))

    def test_organization_owner_uses_the_org_endpoint(self) -> None:
        calls: list[str] = []
        repo = load_json("repo.json")
        repo["owner"] = {"login": "acme", "type": "Organization"}
        routes = _base_routes({"truncated": False, "tree": []})
        routes["/repos/acme/widget"] = (200, repo)
        routes["/orgs/acme"] = routes.pop("/users/acme")
        scan("acme/widget", client=_client(routes, calls), now=NOW)
        self.assertIn("/orgs/acme", calls)
        self.assertNotIn("/users/acme", calls)


if __name__ == "__main__":
    unittest.main()
