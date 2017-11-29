#!/usr/bin/env python
import datetime
import unittest

from aws_session_credentials import aws_session_credentials


class TestIsExpired(unittest.TestCase):
    def test_past_expired(self):
        expiration = datetime.datetime.now() - datetime.timedelta(seconds=1)
        self.assertTrue(aws_session_credentials.is_expired(expiration))

    def test_tomorrow_not_expired(self):
        expiration = datetime.datetime.now() + datetime.timedelta(days=1)
        self.assertFalse(aws_session_credentials.is_expired(expiration))


if __name__ == '__main__':
    unittest.main()
