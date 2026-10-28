"""Timestamp syntax must not depend on the supported Python minor version."""

from datetime import datetime, timezone
import unittest

from employee_read_demo.timestamps import parse_aware_timestamp


class TimestampTests(unittest.TestCase):
    def test_utc_designator_and_explicit_offsets_name_the_same_instant(self):
        expected = datetime(2026, 10, 25, 16, 45, tzinfo=timezone.utc)
        for value in ("2026-10-25T16:45:00Z", "2026-10-25T16:45:00+00:00",
                      "2026-10-25T17:45:00+01:00"):
            with self.subTest(value=value):
                self.assertEqual(parse_aware_timestamp(value), expected)

    def test_fractional_seconds_are_not_rounded_into_a_later_instant(self):
        self.assertEqual(parse_aware_timestamp("2026-10-25T16:45:00.999999Z"),
                         datetime(2026, 10, 25, 16, 45, 0, 999999, timezone.utc))

    def test_missing_timezone_malformed_and_unbounded_values_are_rejected(self):
        for value in (None, 7, [], {}, "", "2026-10-25", "2026-10-25T16:45:00",
                      "2026-10-25T16:45:00ZZ", "2026-10-25T16:45:00Z+00:00",
                      "2026-10-25T16:45:00+25:00", "x" * 129):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_aware_timestamp(value)
