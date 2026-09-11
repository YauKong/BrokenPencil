import unittest

from tests.helpers import REPO_ROOT

from obsidian_agent_memory.proposal_review import (
    FactBlock,
    FactParseCode,
    FactParseError,
    extract_fact_blocks,
)


class ProposalReviewParserTests(unittest.TestCase):
    def test_paragraph_and_list_boundaries_preserve_inline_prose(self):
        raw = (
            "First   paragraph line\n"
            "continues\t here.\n"
            "\n"
            "- List fact\n"
            "  indented continuation\n"
            "ordinary continuation\n"
            "+ Next item\n"
            " next item tail\n"
            "\n"
            "Prose with [a link](https://example.invalid), C:\\vault\\item, and `code` stays.\n"
            "\n"
            "python tools/rebuild.py --root X\n"
        ).encode("utf-8")

        self.assertEqual(
            (
                FactBlock(b"First paragraph line continues here.", 1, 2),
                FactBlock(b"List fact indented continuation ordinary continuation", 4, 6),
                FactBlock(b"Next item next item tail", 7, 8),
                FactBlock(
                    b"Prose with [a link](https://example.invalid), C:\\vault\\item, and `code` stays.",
                    10,
                    10,
                ),
                FactBlock(b"python tools/rebuild.py --root X", 12, 12),
            ),
            extract_fact_blocks(raw),
        )

        blocks = extract_fact_blocks(
            b"The asset cache is enabled.\n\nPrefix: The asset cache is enabled. Suffix.\n"
        )
        self.assertEqual(2, len(blocks))
        self.assertEqual(b"The asset cache is enabled.", blocks[0].normalized_utf8)
        self.assertNotEqual(blocks[0].normalized_utf8, blocks[1].normalized_utf8)

    def test_structural_markdown_is_not_fact_evidence(self):
        structural_cases = (
            b"---\nconfidence: reviewed\n---\n# Heading\n",
            b"   #### Heading\n",
            b"***\n * * * \n___\n---\n",
            b"| :--- | ---: | :---: |\n",
            b"```python\nsecret = 1\n`````\n",
            b"  ~~~~ text\nignored\n   ~~~~~~   \n",
            b"<!-- ignored\nacross lines -->\n",
            b"%% ignored\nacross lines %%\n",
            b"Source: fixture-source\n",
            b"  sOuRcE: fixture-source\n",
            b"`python tools/rebuild.py --root X`\n",
            b"[label](https://example.invalid/path)\n",
            b"[[Project Note]]\n",
            b"https://example.invalid/path\n",
            b"C:\\vault\\memory.md\n",
            b"\\\\server\\share\\memory.md\n",
            b"/var/lib/memory.md\n",
            b"./relative/memory.md\n",
            b"../relative/memory.md\n",
        )
        for raw in structural_cases:
            with self.subTest(raw=raw):
                self.assertEqual((), extract_fact_blocks(raw))

        self.assertEqual(
            (
                FactBlock(b"before", 1, 1),
                FactBlock(b"after", 3, 3),
                FactBlock(b"####### prose", 5, 5),
            ),
            extract_fact_blocks(b"before\n---\nafter\n# heading\n####### prose\n"),
        )

    def test_utf8_bom_newlines_and_unicode_have_stable_blocks(self):
        expected = (
            FactBlock("短事实".encode("utf-8"), 1, 1),
            FactBlock("Emoji 😀".encode("utf-8"), 3, 3),
        )
        for raw in (
            "短事实\n\nEmoji 😀\n".encode("utf-8"),
            "\ufeff短事实\r\n\r\nEmoji 😀\r\n".encode("utf-8"),
            "短事实\r\rEmoji 😀\r".encode("utf-8"),
        ):
            with self.subTest(raw=raw):
                self.assertEqual(expected, extract_fact_blocks(raw))

        values = extract_fact_blocks(
            "Case\n\ncase\n\nFact.\n\nFact!\n\né\n\ne\u0301\n\ninside\ufeffvalue\n".encode(
                "utf-8"
            )
        )
        self.assertEqual(
            ("Case", "case", "Fact.", "Fact!", "é", "e\u0301", "inside\ufeffvalue"),
            tuple(block.normalized_utf8.decode("utf-8") for block in values),
        )

    def test_malformed_or_oversized_input_fails_closed(self):
        cases = (
            (b"\xff", FactParseCode.INVALID_UTF8),
            (b"---\nconfidence: reviewed\n", FactParseCode.UNCLOSED_FRONTMATTER),
            (b"```\nnot closed\n", FactParseCode.UNCLOSED_FENCE),
            (b"~~~\nnot closed\n", FactParseCode.UNCLOSED_FENCE),
            (b"before <!-- not closed\n", FactParseCode.UNCLOSED_COMMENT),
            (b"before %% not closed\n", FactParseCode.UNCLOSED_COMMENT),
            (b"x" * (8 * 1024 * 1024 + 1), FactParseCode.RESOURCE_LIMIT),
        )
        for raw, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(FactParseError) as caught:
                    extract_fact_blocks(raw)
                self.assertEqual(code, caught.exception.code)
                self.assertEqual(code.value, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
