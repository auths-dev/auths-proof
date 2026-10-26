from __future__ import annotations

import unittest

from employee_read_agent.run import HttpBroker, OpenAIModel, validate_model_base_url


class ModelContractTests(unittest.TestCase):
    def test_container_origins_are_closed(self) -> None:
        self.assertEqual(HttpBroker("http://agent-relay:8080").origin,
                         "http://agent-relay:8080")
        for origin in ("http://broker:8765", "http://agent-relay:8081",
                       "http://user@agent-relay:8080"):
            with self.assertRaises(ValueError):
                HttpBroker(origin)
        self.assertEqual(validate_model_base_url("http://model-relay:8080/v1"),
                         "http://model-relay:8080/v1")
        for origin in ("http://model-relay:8080/other", "http://broker:8080/v1",
                       "http://user@model-relay:8080/v1"):
            with self.assertRaises(ValueError):
                validate_model_base_url(origin)

    def test_model_cannot_choose_or_cite_an_unapproved_document(self) -> None:
        model = object.__new__(OpenAIModel)
        model._response = lambda *_: '{"file_ids":["outside"]}'
        with self.assertRaises(ValueError):
            model.select("Summarize Project A", ("file-A",))
        model._response = lambda *_: 'Unsupported claim [file-B]'
        with self.assertRaises(ValueError):
            model.summarize("Summarize Project A", {"file-A": "approved"})
        model._response = lambda *_: 'Approved claim [file-A]'
        self.assertEqual(model.summarize("Summarize Project A", {"file-A": "approved"}),
                         'Approved claim [file-A]')

    def test_draft_uses_one_source_and_stays_within_the_signed_envelope(self) -> None:
        model = object.__new__(OpenAIModel)
        model._response = lambda *_: "Project A is ready. [source-1]"
        self.assertEqual(
            model.draft("Prepare a handoff", {"source-1": "Ready for review"}),
            "Project A is ready. [source-1]",
        )
        with self.assertRaises(ValueError):
            model.draft("Prepare a handoff", {"source-1": "A", "source-2": "B"})
        model._response = lambda *_: "Uncited change"
        with self.assertRaises(ValueError):
            model.draft("Prepare a handoff", {"source-1": "Ready for review"})
        model._response = lambda *_: "Ready [source-1] [outside]"
        with self.assertRaises(ValueError):
            model.draft("Prepare a handoff", {"source-1": "Ready for review"})
        model._response = lambda *_: "A" * 193 + " [source-1]"
        with self.assertRaises(ValueError):
            model.draft("Prepare a handoff", {"source-1": "Ready for review"})


if __name__ == "__main__":
    unittest.main()
