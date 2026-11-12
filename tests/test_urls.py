import unittest

from repoguard.errors import RepoGuardError
from repoguard.urls import parse_target


class UrlTests(unittest.TestCase):
    def test_https_repository(self) -> None:
        target = parse_target("https://github.com/Acme/Widget/")
        self.assertEqual(target.owner, "Acme")
        self.assertEqual(target.repo, "Widget")
        self.assertIsNone(target.ref)
        self.assertEqual(target.full_name, "Acme/Widget")

    def test_git_suffix_and_www(self) -> None:
        target = parse_target("https://www.github.com/acme/widget.git")
        self.assertEqual((target.owner, target.repo, target.ref), ("acme", "widget", None))

    def test_shorthand_and_ssh(self) -> None:
        short = parse_target("acme/widget")
        ssh = parse_target("git@github.com:acme/widget.git")
        self.assertEqual(short, ssh)

    def test_tree_url_uses_only_the_branch_segment(self) -> None:
        target = parse_target("https://github.com/acme/widget/tree/main/docs")
        self.assertEqual(target.ref, "main")
        self.assertEqual(target.full_name, "acme/widget")

    def test_blob_url_keeps_the_ref(self) -> None:
        target = parse_target("https://github.com/acme/widget/blob/dev/README.md")
        self.assertEqual(target.ref, "dev")

    def test_host_without_scheme(self) -> None:
        target = parse_target("github.com/acme/widget")
        self.assertEqual(target.full_name, "acme/widget")

    def test_rejects_other_hosts(self) -> None:
        with self.assertRaises(RepoGuardError) as caught:
            parse_target("https://gitlab.com/acme/widget")
        self.assertIn("GitHub", str(caught.exception))
        self.assertNotIn("gitlab.com/acme", str(caught.exception))

    def test_rejects_ssh_to_other_hosts(self) -> None:
        with self.assertRaises(RepoGuardError):
            parse_target("git@gitlab.com:acme/widget.git")

    def test_rejects_userinfo_without_echoing_the_secret(self) -> None:
        with self.assertRaises(RepoGuardError) as caught:
            parse_target("https://super-secret-token-xyz@github.com/acme/widget")
        self.assertNotIn("super-secret-token-xyz", str(caught.exception))

    def test_rejects_incomplete_and_dotdot(self) -> None:
        with self.assertRaises(RepoGuardError):
            parse_target("https://github.com/acme")
        with self.assertRaises(RepoGuardError):
            parse_target("acme/foo..bar")
        with self.assertRaises(RepoGuardError):
            parse_target("   ")


if __name__ == "__main__":
    unittest.main()
