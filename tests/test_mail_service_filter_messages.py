from __future__ import annotations

import unittest

from gpt_account_manager.mail.service import filter_messages


class FilterMessagesScopeTest(unittest.TestCase):
    def test_accounts_scope_wins_over_single_account(self) -> None:
        messages = [
            {"account": "alpha@example.com", "source": "microsoft", "received_at": "2024-01-01T00:00:00Z"},
            {"account": "beta@example.com", "source": "microsoft", "received_at": "2024-01-02T00:00:00Z"},
            {"account": "gamma@example.com", "source": "microsoft", "received_at": "2024-01-03T00:00:00Z"},
        ]

        result = filter_messages(messages, {
            "accounts": "alpha@example.com,beta@example.com",
            "account": "gamma@example.com",
            "source": "all",
            "mail_type": "all",
            "category": "all",
        })

        self.assertEqual({message["account"] for message in result}, {"alpha@example.com", "beta@example.com"})

    def test_single_account_scope_is_used_without_accounts(self) -> None:
        messages = [
            {"account": "alpha@example.com", "source": "microsoft", "received_at": "2024-01-01T00:00:00Z"},
            {"account": "beta@example.com", "source": "microsoft", "received_at": "2024-01-02T00:00:00Z"},
        ]

        result = filter_messages(messages, {
            "account": "beta@example.com",
            "source": "all",
            "mail_type": "all",
            "category": "all",
        })

        self.assertEqual([message["account"] for message in result], ["beta@example.com"])

    def test_single_account_scope_is_exact_match(self) -> None:
        messages = [
            {"account": "beta@example.com", "source": "microsoft", "received_at": "2024-01-02T00:00:00Z"},
            {"account": "beta@example.com.cn", "source": "microsoft", "received_at": "2024-01-03T00:00:00Z"},
        ]

        result = filter_messages(messages, {
            "account": "beta@example.com",
            "source": "all",
            "mail_type": "all",
            "category": "all",
        })

        self.assertEqual([message["account"] for message in result], ["beta@example.com"])


if __name__ == "__main__":
    unittest.main()
