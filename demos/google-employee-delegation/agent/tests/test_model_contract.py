from __future__ import annotations

import unittest

from employee_read_agent.run import OpenAIModel


class ModelContractTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
