"""Assess the terminal Burp outcome, including HTML character references."""
import base64
import unittest
from probe_k06_traffic import dropped


class AssessmentTests(unittest.TestCase):
    def test_drop_plain_and_numeric_html_references(self):
        for body in (b'Request was dropped by Burp extension.',
                     b'Request&#32;was&#32;dropped&#32;by&#32;Burp&#32;extension&#46;'):
            self.assertTrue(dropped(dict(body_base64=base64.b64encode(body).decode('ascii'))))

    def test_http_200_or_generic_error_is_not_drop_evidence(self):
        self.assertFalse(dropped(dict(status=200, body_base64=base64.b64encode(b'Error').decode('ascii'))))


if __name__ == '__main__':
    unittest.main(verbosity=2)
