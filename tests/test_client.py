import base64
import json
import unittest

from repoguard.errors import RepoGuardError
from repoguard.github_client import GitHubClient, _GitHubRedirect, urllib_transport

TOKEN = "super-secret-token-xyz"


class ClientTests(unittest.TestCase):
    def test_headers_and_tree_url(self) -> None:
        seen: list[tuple[str, dict[str, str]]] = []

        def transport(url: str, headers: dict[str, str]):
            seen.append((url, headers))
            return 200, {}, json.dumps({"tree": [], "truncated": False}).encode()

        client = GitHubClient(token=TOKEN, transport=transport)
        tree, truncated = client.get_tree("acme", "widget", "feature/foo")
        self.assertEqual(tree, [])
        self.assertFalse(truncated)
        url, headers = seen[0]
        self.assertIn("/repos/acme/widget/git/trees/feature%2Ffoo?", url)
        self.assertIn("recursive=1", url)
        self.assertNotIn(TOKEN, url)
        self.assertEqual(headers["Authorization"], f"Bearer {TOKEN}")
        self.assertEqual(headers["Accept"], "application/vnd.github+json")
        self.assertEqual(headers["User-Agent"], "RepoGuard")
        self.assertEqual(headers["X-GitHub-Api-Version"], "2022-11-28")

    def test_anonymous_request_has_no_authorization(self) -> None:
        seen: list[dict[str, str]] = []

        def transport(url: str, headers: dict[str, str]):
            seen.append(headers)
            return 200, {}, b'{"stargazers_count": 1, "owner": {"type": "User"}}'

        GitHubClient(transport=transport).get_repo("acme", "widget")
        self.assertNotIn("Authorization", seen[0])

    def test_missing_repo_and_rejected_token_hide_the_secret(self) -> None:
        def missing(url: str, headers: dict[str, str]):
            self.assertNotIn(TOKEN, url)
            return 404, {}, b'{"message":"Not Found"}'

        with self.assertRaises(RepoGuardError) as caught:
            GitHubClient(token=TOKEN, transport=missing).get_repo("acme", "widget")
        self.assertIn("acme/widget", str(caught.exception))
        self.assertNotIn(TOKEN, str(caught.exception))

        def rejected(url: str, headers: dict[str, str]):
            return 401, {}, b'{"message":"Bad credentials"}'

        with self.assertRaises(RepoGuardError) as caught:
            GitHubClient(token=TOKEN, transport=rejected).get_repo("acme", "widget")
        self.assertIn("Token do GitHub rejeitado", str(caught.exception))
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_rate_limit_message_is_generic(self) -> None:
        def transport(url: str, headers: dict[str, str]):
            return (
                403,
                {"X-RateLimit-Remaining": "0"},
                b'{"message":"API rate limit exceeded for 203.0.113.5."}',
            )

        with self.assertRaises(RepoGuardError) as caught:
            GitHubClient(transport=transport).get_repo("acme", "widget")
        self.assertIn("Limite de requisições", str(caught.exception))
        self.assertNotIn("203.0.113.5", str(caught.exception))

    def test_owner_kind_selects_the_endpoint(self) -> None:
        seen: list[str] = []

        def transport(url: str, headers: dict[str, str]):
            seen.append(url)
            return 200, {}, b'{"created_at":"2020-01-01T00:00:00Z"}'

        client = GitHubClient(transport=transport)
        self.assertIsNotNone(client.get_owner("acme", "Organization"))
        self.assertIsNotNone(client.get_owner("acme", "User"))
        self.assertIn("/orgs/acme", seen[0])
        self.assertIn("/users/acme", seen[1])

    def test_decodes_text_and_skips_large_or_binary_files(self) -> None:
        hello = base64.b64encode(b"hello").decode()
        binary = base64.b64encode(b"a\x00b").decode()
        payloads = {
            "/repos/acme/widget/contents/README.md": {
                "type": "file",
                "encoding": "base64",
                "size": 5,
                "content": hello + "\n",
            },
            "/repos/acme/widget/contents/big.txt": {
                "type": "file",
                "encoding": "base64",
                "size": 200_000,
                "content": hello,
            },
            "/repos/acme/widget/contents/bin.sh": {
                "type": "file",
                "encoding": "base64",
                "size": 3,
                "content": binary,
            },
        }

        def transport(url: str, headers: dict[str, str]):
            path = url.split("?", 1)[0].replace("https://api.github.com", "")
            if path not in payloads:
                return 404, {}, b'{"message":"Not Found"}'
            return 200, {}, json.dumps(payloads[path]).encode()

        client = GitHubClient(transport=transport)
        self.assertEqual(client.get_text_file("acme", "widget", "README.md", "main"), "hello")
        self.assertIsNone(client.get_text_file("acme", "widget", "big.txt", "main"))
        self.assertIsNone(client.get_text_file("acme", "widget", "bin.sh", "main"))
        self.assertIsNone(client.get_text_file("acme", "widget", "ausente.md", "main"))

    def test_empty_repository_and_missing_ref(self) -> None:
        def empty(url: str, headers: dict[str, str]):
            return 409, {}, b'{"message":"Git Repository is empty."}'

        client = GitHubClient(transport=empty)
        self.assertEqual(client.get_commits("acme", "widget", "main"), [])
        self.assertEqual(client.get_tree("acme", "widget", "main"), ([], False))

        def missing_ref(url: str, headers: dict[str, str]):
            return 404, {}, b'{"message":"Not Found"}'

        with self.assertRaises(RepoGuardError) as caught:
            GitHubClient(transport=missing_ref).get_commits("acme", "widget", "nope")
        self.assertIn("nope", str(caught.exception))

    def test_transport_refuses_foreign_hosts_without_connecting(self) -> None:
        with self.assertRaises(RepoGuardError):
            urllib_transport("https://evil.example/repos", {})
        with self.assertRaises(RepoGuardError):
            urllib_transport("http://api.github.com/repos", {})
        with self.assertRaises(RepoGuardError):
            _GitHubRedirect().redirect_request(
                None,
                None,
                302,
                "Found",
                {},
                "https://evil.example/steal",
            )


if __name__ == "__main__":
    unittest.main()
