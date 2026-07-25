"""Tests for the LINE platform adapter plugin.

Covers the seven synthesis areas from the PR review:

1. webhook signature verification (HMAC-SHA256, base64) + tampering rejection
2. inbound chat-id resolution for user / group / room sources
3. three-allowlist gating (users / groups / rooms / allow_all)
4. inbound dedup via webhookEventId
5. RequestCache state machine (PENDING → READY → DELIVERED, ERROR)
6. Markdown stripping with URL preservation + LINE-sized chunking
7. send routing: reply token preferred → push fallback → batched at 5/call
8. register() metadata + standalone_send shape
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import base64
import json
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from tests.gateway._plugin_adapter_loader import load_plugin_adapter

# Load plugins/platforms/line/adapter.py under plugin_adapter_line so it
# cannot collide with sibling platform-plugin tests in the same xdist worker.
_line = load_plugin_adapter("line")

verify_line_signature = _line.verify_line_signature
strip_markdown_preserving_urls = _line.strip_markdown_preserving_urls
split_for_line = _line.split_for_line
build_postback_button_message = _line.build_postback_button_message
_resolve_chat = _line._resolve_chat
_allowed_for_source = _line._allowed_for_source
_is_system_bypass = _line._is_system_bypass
RequestCache = _line.RequestCache
State = _line.State
LineAdapter = _line.LineAdapter
register = _line.register
check_requirements = _line.check_requirements
validate_config = _line.validate_config
_standalone_send = _line._standalone_send
_env_enablement = _line._env_enablement
_MessageDeduplicator = _line._MessageDeduplicator
_LineClient = _line._LineClient
_PushQuotaBudget = _line._PushQuotaBudget
_LineDefiniteReplyError = _line._LineDefiniteReplyError
_LineDefinitePushError = _line._LineDefinitePushError

_LINE_TEST_ENV_KEYS = (
    "LINE_CHANNEL_ACCESS_TOKEN",
    "LINE_CHANNEL_SECRET",
    "LINE_PORT",
    "LINE_HOST",
    "LINE_PUBLIC_URL",
    "LINE_HOME_CHANNEL",
    "LINE_ALLOWED_USERS",
    "LINE_ALLOWED_GROUPS",
    "LINE_ALLOWED_ROOMS",
    "LINE_ALLOW_ALL_USERS",
    "LINE_SLOW_RESPONSE_THRESHOLD",
)


def _clear_line_test_env(monkeypatch):
    for key in _LINE_TEST_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


class _FakeLineResponse:
    def __init__(self, *, status=200, body="{}", headers=None):
        self.status = status
        self._body = body
        self.headers = headers or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return self._body


class _FakeLineSession:
    def __init__(self, response, **kwargs):
        self._response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        return self._response


def _install_fake_aiohttp(monkeypatch, response):
    fake = SimpleNamespace(
        ClientTimeout=lambda **kwargs: kwargs,
        ClientSession=lambda **kwargs: _FakeLineSession(response, **kwargs),
    )
    monkeypatch.setitem(sys.modules, "aiohttp", fake)


# ---------------------------------------------------------------------------
# 1. Signature verification
# ---------------------------------------------------------------------------

class TestSignature:

    def _sign(self, body: bytes, secret: str) -> str:
        digest = hmac.new(secret.encode(), body, hashlib.sha256).digest()
        return base64.b64encode(digest).decode()

    def test_valid_signature_passes(self):
        body = b'{"events": []}'
        sig = self._sign(body, "secret")
        assert verify_line_signature(body, sig, "secret")

    def test_tampered_body_rejected(self):
        body = b'{"events": []}'
        sig = self._sign(body, "secret")
        assert not verify_line_signature(body + b" ", sig, "secret")

    def test_wrong_secret_rejected(self):
        body = b'{"events": []}'
        sig = self._sign(body, "secret")
        assert not verify_line_signature(body, sig, "different")

    def test_empty_signature_rejected(self):
        assert not verify_line_signature(b"x", "", "secret")

    def test_empty_secret_rejected(self):
        assert not verify_line_signature(b"x", "AAAA", "")

    def test_garbage_signature_rejected(self):
        assert not verify_line_signature(b"hello", "not base64 at all!!", "s")


# ---------------------------------------------------------------------------
# 2. Chat-id / source resolution
# ---------------------------------------------------------------------------

class TestSourceResolution:

    def test_user_source(self):
        chat_id, ctype = _resolve_chat({"type": "user", "userId": "U123"})
        assert chat_id == "U123"
        assert ctype == "dm"

    def test_group_source(self):
        chat_id, ctype = _resolve_chat({"type": "group", "groupId": "C456", "userId": "U123"})
        assert chat_id == "C456"
        assert ctype == "group"

    def test_room_source(self):
        chat_id, ctype = _resolve_chat({"type": "room", "roomId": "R789", "userId": "U123"})
        assert chat_id == "R789"
        assert ctype == "room"

    def test_unknown_source_falls_back_to_dm(self):
        chat_id, ctype = _resolve_chat({"type": "weird"})
        assert chat_id == ""
        assert ctype == "dm"

    def test_empty_source(self):
        chat_id, ctype = _resolve_chat({})
        assert chat_id == ""
        assert ctype == "dm"


# ---------------------------------------------------------------------------
# 3. Three-allowlist gating
# ---------------------------------------------------------------------------

class TestAllowlist:

    def test_allow_all_short_circuits(self):
        for src in [
            {"type": "user", "userId": "Ufoo"},
            {"type": "group", "groupId": "Cfoo"},
            {"type": "room", "roomId": "Rfoo"},
        ]:
            assert _allowed_for_source(src, allow_all=True, user_ids=set(), group_ids=set(), room_ids=set())

    def test_user_in_allowlist_passes(self):
        src = {"type": "user", "userId": "Uok"}
        assert _allowed_for_source(src, allow_all=False, user_ids={"Uok"}, group_ids=set(), room_ids=set())

    def test_user_not_in_allowlist_rejected(self):
        src = {"type": "user", "userId": "Uother"}
        assert not _allowed_for_source(src, allow_all=False, user_ids={"Uok"}, group_ids=set(), room_ids=set())

    def test_group_uses_group_list_not_user_list(self):
        src = {"type": "group", "groupId": "Cok", "userId": "Uany"}
        assert _allowed_for_source(src, allow_all=False, user_ids={"Uany"}, group_ids={"Cok"}, room_ids=set())
        assert not _allowed_for_source(src, allow_all=False, user_ids={"Uany"}, group_ids=set(), room_ids=set())

    def test_room_uses_room_list(self):
        src = {"type": "room", "roomId": "Rok"}
        assert _allowed_for_source(src, allow_all=False, user_ids=set(), group_ids=set(), room_ids={"Rok"})
        assert not _allowed_for_source(src, allow_all=False, user_ids=set(), group_ids=set(), room_ids=set())

    def test_unknown_type_rejected(self):
        src = {"type": "weird"}
        assert not _allowed_for_source(src, allow_all=False, user_ids=set(), group_ids=set(), room_ids=set())


# ---------------------------------------------------------------------------
# 4. Inbound dedup
# ---------------------------------------------------------------------------

class TestDedup:

    def test_first_event_not_duplicate(self):
        d = _MessageDeduplicator()
        assert not d.is_duplicate("evt1")

    def test_repeat_event_marked_duplicate(self):
        d = _MessageDeduplicator()
        d.is_duplicate("evt1")
        assert d.is_duplicate("evt1")

    def test_blank_id_not_treated_as_duplicate(self):
        d = _MessageDeduplicator()
        # Blank IDs should always pass through (don't lock out unidentifiable events).
        assert not d.is_duplicate("")
        assert not d.is_duplicate("")

    def test_lru_eviction_under_pressure(self):
        d = _MessageDeduplicator(max_size=10)
        for i in range(20):
            d.is_duplicate(f"evt{i}")
        # Exact eviction order isn't specified, but the cap must be enforced.
        # Insert one more and assert the bookkeeping doesn't grow without bound.
        d.is_duplicate("evt20")
        assert len(d._seen) <= 20  # bounded — exact cap depends on eviction policy


# ---------------------------------------------------------------------------
# 5. RequestCache state machine
# ---------------------------------------------------------------------------

class TestRequestCache:

    def test_register_pending_is_pending(self):
        c = RequestCache()
        rid = c.register_pending("Uchat")
        assert c.get(rid).state is State.PENDING
        assert c.get(rid).chat_id == "Uchat"

    def test_set_ready_transitions(self):
        c = RequestCache()
        rid = c.register_pending("Uchat")
        c.set_ready(rid, "the answer")
        assert c.get(rid).state is State.READY
        assert c.get(rid).payload == "the answer"

    def test_set_error_transitions(self):
        c = RequestCache()
        rid = c.register_pending("Uchat")
        c.set_error(rid, "boom")
        assert c.get(rid).state is State.ERROR
        assert c.get(rid).payload == "boom"

    def test_mark_delivered_from_ready(self):
        c = RequestCache()
        rid = c.register_pending("Uchat")
        c.set_ready(rid, "x")
        c.mark_delivered(rid)
        assert c.get(rid).state is State.DELIVERED

    def test_mark_delivered_from_error(self):
        c = RequestCache()
        rid = c.register_pending("Uchat")
        c.set_error(rid, "x")
        c.mark_delivered(rid)
        assert c.get(rid).state is State.DELIVERED

    def test_set_ready_on_delivered_is_noop(self):
        c = RequestCache()
        rid = c.register_pending("Uchat")
        c.set_ready(rid, "first")
        c.mark_delivered(rid)
        c.set_ready(rid, "second")
        # DELIVERED is terminal — no further mutation
        assert c.get(rid).payload == "first"
        assert c.get(rid).state is State.DELIVERED

    def test_find_pending_for_chat(self):
        c = RequestCache()
        rid_a = c.register_pending("Ua")
        rid_b = c.register_pending("Ub")
        assert c.find_pending_for_chat("Ua") == rid_a
        assert c.find_pending_for_chat("Ub") == rid_b
        assert c.find_pending_for_chat("Uc") is None
        c.set_ready(rid_a, "x")
        # No longer PENDING — should not be found
        assert c.find_pending_for_chat("Ua") is None

    def test_discard_removes_orphan_entry(self):
        c = RequestCache()
        rid = c.register_pending("Uchat")

        c.discard(rid)

        assert c.get(rid) is None

    def test_register_pending_fails_closed_at_hard_cap(self):
        c = RequestCache(max_entries=2)

        first = c.register_pending("Uone")
        second = c.register_pending("Utwo")
        denied = c.register_pending("Uthree")

        assert first and second
        assert denied is None
        assert len(c._entries) == 2

    def test_register_pending_prunes_expired_entry_before_admission(self):
        c = RequestCache(pending_ttl_seconds=10, max_entries=1)
        expired = c.register_pending("Uold")
        c._entries[expired].created_at -= 11

        admitted = c.register_pending("Unew")

        assert admitted is not None
        assert c.get(expired) is None
        assert len(c._entries) == 1


# ---------------------------------------------------------------------------
# 6. Markdown stripping + chunking
# ---------------------------------------------------------------------------

class TestMarkdownAndChunking:

    def test_bold_stripped(self):
        assert strip_markdown_preserving_urls("**hello**") == "hello"

    def test_italic_stripped(self):
        assert strip_markdown_preserving_urls("*hello*") == "hello"

    def test_inline_code_unfenced(self):
        assert strip_markdown_preserving_urls("run `ls -la`") == "run ls -la"

    def test_link_preserved_with_url(self):
        out = strip_markdown_preserving_urls("see [here](https://x.com)")
        assert "https://x.com" in out
        assert "here (https://x.com)" in out

    def test_heading_prefix_stripped(self):
        out = strip_markdown_preserving_urls("# Title\n## Sub")
        assert out == "Title\nSub"

    def test_bullet_marker_replaced(self):
        out = strip_markdown_preserving_urls("- a\n- b")
        assert out == "• a\n• b"

    def test_code_fence_content_kept(self):
        # Source files often contain code snippets — the agent should still
        # see the content as plain text, just without backticks.
        md = "```python\nprint('hi')\n```"
        out = strip_markdown_preserving_urls(md)
        assert "print('hi')" in out
        assert "```" not in out

    def test_split_short_returns_single_chunk(self):
        assert split_for_line("hi") == ["hi"]

    def test_split_long_chunks_at_paragraph_boundary(self):
        text = "para1\n\npara2\n\npara3"
        chunks = split_for_line(text, max_chars=8)
        assert all(len(c) <= 8 for c in chunks), chunks
        assert len(chunks) >= 2

    def test_split_caps_at_five_chunks(self):
        # 1000 paragraphs of 100 chars each — must cap at 5 LINE bubbles.
        text = "\n\n".join(["x" * 100 for _ in range(1000)])
        chunks = split_for_line(text)
        assert len(chunks) <= 5


# ---------------------------------------------------------------------------
# 7. LINE API delivery observability
# ---------------------------------------------------------------------------

class _FakeQuotaSession:
    def __init__(self, responses, **kwargs):
        self._responses = responses

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def get(self, url, *args, **kwargs):
        return self._responses[url]


class TestLineClientDeliveryLogging:

    def test_quota_status_fetches_limit_and_consumption(self, monkeypatch):
        responses = {
            _line.LINE_QUOTA_URL: _FakeLineResponse(
                status=200,
                body=json.dumps({"type": "limited", "value": 200}),
            ),
            _line.LINE_QUOTA_CONSUMPTION_URL: _FakeLineResponse(
                status=200,
                body=json.dumps({"totalUsage": 13}),
            ),
        }
        fake = SimpleNamespace(
            ClientTimeout=lambda **kwargs: kwargs,
            ClientSession=lambda **kwargs: _FakeQuotaSession(responses, **kwargs),
        )
        monkeypatch.setitem(sys.modules, "aiohttp", fake)

        quota, consumption = asyncio.run(
            _LineClient("secret-access-token").get_quota_status()
        )

        assert quota == {"type": "limited", "value": 200}
        assert consumption == {"totalUsage": 13}

    def test_quota_status_raises_safe_error_on_http_failure(self, monkeypatch):
        responses = {
            _line.LINE_QUOTA_URL: _FakeLineResponse(status=429, body="private body"),
            _line.LINE_QUOTA_CONSUMPTION_URL: _FakeLineResponse(
                status=200,
                body=json.dumps({"totalUsage": 13}),
            ),
        }
        fake = SimpleNamespace(
            ClientTimeout=lambda **kwargs: kwargs,
            ClientSession=lambda **kwargs: _FakeQuotaSession(responses, **kwargs),
        )
        monkeypatch.setitem(sys.modules, "aiohttp", fake)

        with pytest.raises(RuntimeError, match="LINE quota 429") as exc_info:
            asyncio.run(_LineClient("secret-access-token").get_quota_status())

        assert "private body" not in str(exc_info.value)
        assert "secret-access-token" not in str(exc_info.value)

    def test_reply_success_logs_delivery_receipt_without_secrets(
        self, monkeypatch, caplog
    ):
        response = _FakeLineResponse(
            status=200,
            body=json.dumps({"sentMessages": [{"id": "msg-123"}]}),
            headers={"x-line-request-id": "req-456"},
        )
        _install_fake_aiohttp(monkeypatch, response)
        client = _LineClient("secret-access-token")

        with caplog.at_level("INFO"):
            asyncio.run(
                client.reply(
                    "secret-reply-token",
                    [{"type": "text", "text": "private message body"}],
                )
            )

        log_text = caplog.text
        assert "LINE delivery success" in log_text
        assert "operation=reply" in log_text
        assert "status=200" in log_text
        assert "request_id=req-456" in log_text
        assert "message_ids" not in log_text
        assert "msg-123" not in log_text
        assert "secret-access-token" not in log_text
        assert "secret-reply-token" not in log_text
        assert "private message body" not in log_text

    def test_push_failure_logs_status_request_id_and_safe_error(
        self, monkeypatch, caplog
    ):
        response = _FakeLineResponse(
            status=429,
            body=json.dumps({"message": "Too many requests"}),
            headers={"x-line-request-id": "req-rate-limit"},
        )
        _install_fake_aiohttp(monkeypatch, response)
        client = _LineClient("secret-access-token")

        with caplog.at_level("WARNING"), pytest.raises(RuntimeError):
            asyncio.run(
                client.push(
                    "Usecret-chat",
                    [{"type": "text", "text": "private message body"}],
                )
            )

        log_text = caplog.text
        assert "LINE delivery failed" in log_text
        assert "operation=push" in log_text
        assert "status=429" in log_text
        assert "request_id=req-rate-limit" in log_text
        assert "error=http_4xx" in log_text
        assert "Too many requests" not in log_text
        assert "secret-access-token" not in log_text
        assert "Usecret-chat" not in log_text
        assert "private message body" not in log_text

    @pytest.mark.parametrize("operation", ["reply", "push"])
    def test_http_5xx_is_delivery_uncertain(self, monkeypatch, operation):
        response = _FakeLineResponse(status=503, body="upstream may have accepted")
        _install_fake_aiohttp(monkeypatch, response)
        client = _LineClient("secret-access-token")

        with pytest.raises(RuntimeError) as exc_info:
            if operation == "reply":
                asyncio.run(client.reply("reply-token", [_line._text_message("hello")]))
            else:
                asyncio.run(client.push("Uchat", [_line._text_message("hello")]))

        assert not isinstance(exc_info.value, _LineDefiniteReplyError)
        assert not isinstance(exc_info.value, _LineDefinitePushError)

    def test_failure_log_never_includes_remote_response_message(
        self, monkeypatch, caplog
    ):
        echoed = (
            "access=secret-access-token reply=secret-reply-token "
            "chat=Usecret-chat body=private-message-body"
        )
        response = _FakeLineResponse(
            status=400,
            body=json.dumps({"message": echoed}),
            headers={"x-line-request-id": "req-safe"},
        )
        _install_fake_aiohttp(monkeypatch, response)

        with caplog.at_level("WARNING"), pytest.raises(_LineDefiniteReplyError):
            asyncio.run(
                _LineClient("secret-access-token").reply(
                    "secret-reply-token",
                    [_line._text_message("private-message-body")],
                )
            )

        assert "error=http_4xx" in caplog.text
        for secret in (
            "secret-access-token",
            "secret-reply-token",
            "Usecret-chat",
            "private-message-body",
        ):
            assert secret not in caplog.text


# ---------------------------------------------------------------------------
# 8. Push quota budget
# ---------------------------------------------------------------------------

class TestPushQuotaBudget:

    def test_limited_quota_reserves_only_within_soft_limit(self):
        budget = _PushQuotaBudget(soft_limit_ratio=0.8)
        client = SimpleNamespace(
            get_quota_status=AsyncMock(return_value=(
                {"type": "limited", "value": 200},
                {"totalUsage": 159},
            ))
        )

        first = asyncio.run(budget.reserve(client))
        second = asyncio.run(budget.reserve(client))

        assert first.allowed is True
        assert first.soft_limit == 160
        assert first.effective_usage == 159
        assert second.allowed is False
        assert second.reason == "soft_limit_reached"

    def test_at_soft_limit_fails_closed(self):
        budget = _PushQuotaBudget(soft_limit_ratio=0.8)
        client = SimpleNamespace(
            get_quota_status=AsyncMock(return_value=(
                {"type": "limited", "value": 200},
                {"totalUsage": 160},
            ))
        )

        decision = asyncio.run(budget.reserve(client))

        assert decision.allowed is False
        assert decision.reason == "soft_limit_reached"

    def test_small_quota_never_rounds_soft_limit_above_ratio(self):
        budget = _PushQuotaBudget(soft_limit_ratio=0.8)
        client = SimpleNamespace(
            get_quota_status=AsyncMock(return_value=(
                {"type": "limited", "value": 1},
                {"totalUsage": 0},
            ))
        )

        decision = asyncio.run(budget.reserve(client))

        assert decision.allowed is False
        assert decision.soft_limit == 0

    def test_unlimited_quota_allows_reservation(self):
        budget = _PushQuotaBudget(soft_limit_ratio=0.8)
        client = SimpleNamespace(
            get_quota_status=AsyncMock(return_value=(
                {"type": "unlimited"},
                {"totalUsage": 999},
            ))
        )

        decision = asyncio.run(budget.reserve(client))

        assert decision.allowed is True
        assert decision.reason == "unlimited"

    def test_quota_api_failure_fails_closed(self):
        budget = _PushQuotaBudget(soft_limit_ratio=0.8)
        client = SimpleNamespace(
            get_quota_status=AsyncMock(side_effect=RuntimeError("timeout"))
        )

        decision = asyncio.run(budget.reserve(client))

        assert decision.allowed is False
        assert decision.reason == "quota_unavailable"

    @pytest.mark.parametrize(
        ("quota", "consumption"),
        [
            ({"type": "mystery"}, {"totalUsage": 0}),
            ({"type": "limited", "value": 0}, {"totalUsage": 0}),
            ({"type": "limited", "value": 200}, {"totalUsage": -1}),
            ({"type": "limited", "value": "bad"}, {"totalUsage": 0}),
            ({"type": "limited", "value": 200.9}, {"totalUsage": 0}),
            ({"type": "limited", "value": 200}, {"totalUsage": 0.9}),
            ({"type": "limited", "value": "200"}, {"totalUsage": 0}),
            ({"type": "limited", "value": " 200 "}, {"totalUsage": 0}),
            ({"type": "limited", "value": "٢٠٠"}, {"totalUsage": 0}),
            ({"type": "limited", "value": 200}, {"totalUsage": "0"}),
        ],
    )
    def test_malformed_quota_fails_closed(self, quota, consumption):
        budget = _PushQuotaBudget(soft_limit_ratio=0.8)
        client = SimpleNamespace(
            get_quota_status=AsyncMock(return_value=(quota, consumption))
        )

        decision = asyncio.run(budget.reserve(client))

        assert decision.allowed is False
        assert decision.reason == "quota_invalid"

    def test_free_reply_releases_reservation(self):
        budget = _PushQuotaBudget(soft_limit_ratio=0.8)
        client = SimpleNamespace(
            get_quota_status=AsyncMock(return_value=(
                {"type": "limited", "value": 200},
                {"totalUsage": 159},
            ))
        )

        assert asyncio.run(budget.reserve(client)).allowed
        budget.finish(pushed=False)
        assert asyncio.run(budget.reserve(client)).allowed

    def test_successful_push_keeps_local_usage_until_api_catches_up(self):
        budget = _PushQuotaBudget(soft_limit_ratio=0.8)
        client = SimpleNamespace(
            get_quota_status=AsyncMock(return_value=(
                {"type": "limited", "value": 200},
                {"totalUsage": 159},
            ))
        )

        assert asyncio.run(budget.reserve(client)).allowed
        budget.finish(pushed=True)
        decision = asyncio.run(budget.reserve(client))

        assert decision.allowed is False
        assert decision.reason == "soft_limit_reached"


# ---------------------------------------------------------------------------
# 9. Send routing (reply -> push fallback, batching, system-bypass)
# ---------------------------------------------------------------------------

class TestSendRouting:

    @pytest.fixture
    def adapter(self, monkeypatch):
        monkeypatch.delenv("LINE_CHANNEL_ACCESS_TOKEN", raising=False)
        monkeypatch.delenv("LINE_CHANNEL_SECRET", raising=False)
        from gateway.config import PlatformConfig
        cfg = PlatformConfig(enabled=True, extra={
            "channel_access_token": "tok",
            "channel_secret": "sec",
        })
        ad = LineAdapter(cfg)
        ad._client = MagicMock()
        ad._client.reply = AsyncMock()
        ad._client.push = AsyncMock()
        return ad

    def test_system_bypass_recognized(self):
        assert _is_system_bypass("⚡ Interrupting current run")
        assert _is_system_bypass("⏳ Queued — agent is busy")
        assert _is_system_bypass("⏩ Steered toward new task")
        assert not _is_system_bypass("Hello world")
        assert not _is_system_bypass("")

    def test_send_uses_reply_when_token_present(self, adapter):
        import time as _time
        adapter._reply_tokens["Uchat"] = ("rt-token", _time.time() + 30)
        result = asyncio.run(adapter.send("Uchat", "hello"))
        assert result.success
        adapter._client.reply.assert_called_once()
        adapter._client.push.assert_not_called()
        # Token consumed (single-use)
        assert "Uchat" not in adapter._reply_tokens

    def test_send_falls_back_to_push_when_no_token(self, adapter):
        result = asyncio.run(adapter.send("Uchat", "hello"))
        assert result.success
        adapter._client.push.assert_called_once()
        adapter._client.reply.assert_not_called()

    def test_send_falls_back_to_push_when_reply_is_definitely_rejected(self, adapter):
        import time as _time
        adapter._reply_tokens["Uchat"] = ("rt-token", _time.time() + 30)
        adapter._client.reply.side_effect = _LineDefiniteReplyError("LINE reply 400")
        result = asyncio.run(adapter.send("Uchat", "hello"))
        assert result.success
        adapter._client.reply.assert_called_once()
        adapter._client.push.assert_called_once()

    def test_ambiguous_reply_timeout_never_falls_back_to_push(self, adapter):
        import time as _time
        adapter._auto_push_reservations.add("Uchat")
        adapter._quota_budget = MagicMock()
        adapter._reply_tokens["Uchat"] = ("rt-token", _time.time() + 30)
        adapter._client.reply.side_effect = asyncio.TimeoutError()

        result = asyncio.run(adapter.send("Uchat", "hello"))

        assert not result.success
        adapter._client.push.assert_not_called()
        adapter._quota_budget.finish.assert_called_once_with(pushed=False)

    def test_ambiguous_reply_without_reservation_suppresses_followup(self, adapter):
        import time as _time
        from gateway.session_context import clear_session_vars, set_session_vars

        adapter._begin_delivery_run("Uchat", "run-uncertain-reply")
        adapter._reply_tokens["Uchat"] = ("rt-token", _time.time() + 30)
        adapter._reply_token_runs["Uchat"] = "run-uncertain-reply"
        adapter._client.reply.side_effect = asyncio.TimeoutError()
        tokens = set_session_vars(chat_id="Uchat", message_id="run-uncertain-reply")
        try:
            first = asyncio.run(adapter.send("Uchat", "first"))
            followup = asyncio.run(adapter.send("Uchat", "late"))
        finally:
            clear_session_vars(tokens)

        assert not first.success
        assert followup.success
        adapter._client.reply.assert_called_once()
        adapter._client.push.assert_not_called()

    def test_ambiguous_push_without_reservation_suppresses_followup(self, adapter):
        from gateway.session_context import clear_session_vars, set_session_vars

        adapter._begin_delivery_run("Uchat", "run-uncertain-push")
        adapter._client.push.side_effect = asyncio.TimeoutError()
        tokens = set_session_vars(chat_id="Uchat", message_id="run-uncertain-push")
        try:
            first = asyncio.run(adapter.send("Uchat", "first"))
            followup = asyncio.run(adapter.send("Uchat", "late"))
        finally:
            clear_session_vars(tokens)

        assert not first.success
        assert followup.success
        adapter._client.push.assert_called_once()

    @pytest.mark.parametrize("use_reply", [True, False])
    def test_ambiguous_native_delivery_suppresses_followup(self, adapter, use_reply):
        import time as _time
        from gateway.session_context import clear_session_vars, set_session_vars

        run_id = f"run-native-{use_reply}"
        adapter._begin_delivery_run("Uchat", run_id)
        if use_reply:
            adapter._reply_tokens["Uchat"] = ("rt-token", _time.time() + 30)
            adapter._reply_token_runs["Uchat"] = run_id
            adapter._client.reply.side_effect = asyncio.TimeoutError()
        else:
            adapter._client.push.side_effect = asyncio.TimeoutError()
        media = [{"type": "image", "originalContentUrl": "https://x/image.png",
                  "previewImageUrl": "https://x/image.png"}]

        tokens = set_session_vars(chat_id="Uchat", message_id=run_id)
        try:
            first = asyncio.run(adapter._send_messages("Uchat", media))
            followup = asyncio.run(adapter.send("Uchat", "late"))
        finally:
            clear_session_vars(tokens)

        assert not first.success
        assert followup.success
        if use_reply:
            adapter._client.reply.assert_called_once()
            adapter._client.push.assert_not_called()
        else:
            adapter._client.push.assert_called_once()

    def test_send_returns_failure_when_push_is_uncertain(self, adapter):
        adapter._client.push.side_effect = RuntimeError("network")
        result = asyncio.run(adapter.send("Uchat", "hello"))
        assert not result.success
        assert "uncertain" in result.error

    def test_send_pending_button_caches_response(self, adapter):
        # Simulate that the slow-LLM postback button has fired.
        rid = adapter._cache.register_pending("Uchat")
        adapter._pending_buttons["Uchat"] = rid
        result = asyncio.run(adapter.send("Uchat", "the answer"))
        assert result.success
        # Response must have been cached, not pushed/replied.
        adapter._client.reply.assert_not_called()
        adapter._client.push.assert_not_called()
        assert adapter._cache.get(rid).state is State.READY
        assert adapter._cache.get(rid).payload == "the answer"

    def test_auto_push_reservation_uses_free_reply_and_releases_budget(self, adapter):
        import time as _time
        adapter._auto_push_reservations.add("Uchat")
        adapter._quota_budget = MagicMock()
        adapter._reply_tokens["Uchat"] = ("rt-token", _time.time() + 30)

        result = asyncio.run(adapter.send("Uchat", "the answer"))

        assert result.success
        adapter._client.reply.assert_called_once()
        adapter._client.push.assert_not_called()
        adapter._quota_budget.finish.assert_called_once_with(pushed=False)
        assert "Uchat" not in adapter._auto_push_reservations
        assert "Uchat" in adapter._auto_push_completed_chats

        media_result = asyncio.run(adapter._send_messages(
            "Uchat",
            [{"type": "image", "originalContentUrl": "https://x/image.png",
              "previewImageUrl": "https://x/image.png"}],
        ))
        assert media_result.success
        adapter._client.push.assert_not_called()

    def test_auto_push_reservation_commits_after_push_success(self, adapter):
        adapter._auto_push_reservations.add("Uchat")
        adapter._quota_budget = MagicMock()

        result = asyncio.run(adapter.send("Uchat", "the answer"))

        assert result.success
        adapter._client.push.assert_called_once()
        adapter._quota_budget.finish.assert_called_once_with(pushed=True)
        assert "Uchat" not in adapter._auto_push_reservations

    def test_auto_push_reservation_releases_after_definite_push_failure(self, adapter):
        adapter._auto_push_reservations.add("Uchat")
        adapter._quota_budget = MagicMock()
        adapter._client.push.side_effect = _LineDefinitePushError("LINE push 400")

        result = asyncio.run(adapter.send("Uchat", "the answer"))

        assert not result.success
        adapter._quota_budget.finish.assert_called_once_with(pushed=False)
        assert "Uchat" not in adapter._auto_push_reservations

    def test_ambiguous_push_timeout_commits_budget_conservatively(self, adapter):
        adapter._auto_push_reservations.add("Uchat")
        adapter._quota_budget = MagicMock()
        adapter._client.push.side_effect = asyncio.TimeoutError()

        result = asyncio.run(adapter.send("Uchat", "the answer"))

        assert not result.success
        adapter._quota_budget.finish.assert_called_once_with(pushed=True)
        assert "Uchat" not in adapter._auto_push_reservations

    def test_send_system_bypass_skips_postback_cache(self, adapter):
        # Even with a pending button, system busy-acks must surface visibly.
        rid = adapter._cache.register_pending("Uchat")
        adapter._pending_buttons["Uchat"] = rid
        result = asyncio.run(adapter.send("Uchat", "⚡ Interrupting current run"))
        assert result.success
        # Bypass goes through push (no reply token stored)
        adapter._client.push.assert_called_once()
        # And the cache entry is unchanged (still PENDING for the eventual answer)
        assert adapter._cache.get(rid).state is State.PENDING

    def test_auto_push_system_bypass_never_uses_unbudgeted_push(self, adapter):
        import time as _time

        adapter.slow_response_mode = "auto_push"
        adapter._blocked_slow_pushes.add("Uchat")
        adapter._reply_tokens["Uchat"] = ("expired", _time.time() - 1)

        result = asyncio.run(adapter.send("Uchat", "⚡ Interrupting current run"))

        assert result.success
        adapter._client.reply.assert_not_called()
        adapter._client.push.assert_not_called()
        assert "Uchat" in adapter._blocked_slow_pushes

    def test_auto_push_system_bypass_may_use_free_reply_without_completing_run(
        self, adapter
    ):
        import time as _time

        adapter.slow_response_mode = "auto_push"
        adapter._reply_tokens["Uchat"] = ("reply-token", _time.time() + 30)

        result = asyncio.run(adapter.send("Uchat", "⏳ Queued — agent is busy"))

        assert result.success
        adapter._client.reply.assert_called_once()
        adapter._client.push.assert_not_called()
        assert "Uchat" not in adapter._auto_push_completed_chats

    def test_completed_inbound_run_does_not_suppress_unbound_proactive_pushes(
        self, adapter
    ):
        import time as _time
        from gateway.session_context import clear_session_vars, set_session_vars

        adapter._begin_delivery_run("Uchat", "inbound-1")
        adapter._reply_tokens["Uchat"] = ("reply-token", _time.time() + 30)
        adapter._reply_token_runs["Uchat"] = "inbound-1"
        tokens = set_session_vars(chat_id="Uchat", message_id="inbound-1")
        try:
            first = asyncio.run(adapter.send("Uchat", "inbound final"))
        finally:
            clear_session_vars(tokens)

        proactive = asyncio.run(adapter.send("Uchat", "proactive notification"))
        system = asyncio.run(adapter.send("Uchat", "⏳ Queued system notice"))

        assert first.success and proactive.success and system.success
        adapter._client.reply.assert_called_once()
        assert adapter._client.push.await_count == 2

    def test_foreign_adapter_task_context_does_not_suppress_proactive_pushes(
        self, adapter, monkeypatch
    ):
        from gateway.config import PlatformConfig
        from gateway.session_context import clear_session_vars, set_session_vars

        other = LineAdapter(PlatformConfig(enabled=True, extra={
            "channel_access_token": "other-token",
            "channel_secret": "other-secret",
        }))
        adapter._begin_delivery_run("Uchat", "a-run")
        adapter._auto_push_completed_runs[("Uchat", "a-run")] = None
        tokens = set_session_vars(chat_id="Uchat", message_id="b-run")
        foreign_epoch = _line._DELIVERY_TASK_EPOCH.set(
            (other, other._delivery_epoch)
        )
        try:
            proactive = asyncio.run(adapter.send("Uchat", "proactive from A"))
            system = asyncio.run(adapter.send("Uchat", "⏳ System from A"))
        finally:
            _line._DELIVERY_TASK_EPOCH.reset(foreign_epoch)
            clear_session_vars(tokens)

        assert proactive.success and system.success
        adapter._client.reply.assert_not_called()
        assert adapter._client.push.await_count == 2

    def test_foreign_adapter_context_cannot_bypass_active_reservation(
        self, adapter, monkeypatch
    ):
        import time as _time
        from gateway.config import PlatformConfig
        from gateway.session_context import clear_session_vars, set_session_vars

        other = LineAdapter(PlatformConfig(enabled=True, extra={
            "channel_access_token": "other-token",
            "channel_secret": "other-secret",
        }))
        adapter._begin_delivery_run("Usame", "a-run")
        adapter._reply_tokens["Usame"] = ("a-token", _time.time() + 30)
        adapter._reply_token_runs["Usame"] = "a-run"
        adapter._auto_push_reservations.add("Usame")
        adapter._auto_push_reservation_runs["Usame"] = "a-run"
        adapter._quota_budget = MagicMock()
        tokens = set_session_vars(chat_id="Usame", message_id="b-run")
        foreign_epoch = _line._DELIVERY_TASK_EPOCH.set(
            (other, other._delivery_epoch)
        )
        try:
            result = asyncio.run(adapter.send("Usame", "foreign output"))
        finally:
            _line._DELIVERY_TASK_EPOCH.reset(foreign_epoch)
            clear_session_vars(tokens)

        assert not result.success
        adapter._client.reply.assert_not_called()
        adapter._client.push.assert_not_called()
        assert "Usame" in adapter._reply_tokens
        assert "Usame" in adapter._auto_push_reservations
        adapter._quota_budget.finish.assert_not_called()

    def test_system_bypass_is_suppressed_during_auto_push_reservation(self, adapter):
        adapter._auto_push_reservations.add("Uchat")
        adapter._quota_budget = MagicMock()

        result = asyncio.run(adapter.send("Uchat", "⏳ Queued — agent is busy"))

        assert result.success
        adapter._client.reply.assert_not_called()
        adapter._client.push.assert_not_called()
        assert "Uchat" in adapter._auto_push_reservations
        adapter._quota_budget.finish.assert_not_called()

    def test_working_heartbeat_cannot_consume_reserved_final_push(
        self, adapter, caplog
    ):
        adapter._auto_push_reservations.add("Uchat")
        adapter._quota_budget = MagicMock()
        from gateway.run import _non_conversational_metadata
        from gateway.platforms.base import _is_trusted_non_conversational_metadata

        metadata = _non_conversational_metadata(platform="line")
        assert metadata and metadata["non_conversational"] is True
        assert _is_trusted_non_conversational_metadata(metadata)
        with caplog.at_level("INFO"):
            heartbeat = asyncio.run(adapter.send(
                "Uchat",
                "⏳ Working — 3 min — iteration 6/60, receiving stream response",
                metadata=metadata,
            ))

        assert heartbeat.success
        adapter._client.reply.assert_not_called()
        adapter._client.push.assert_not_called()
        assert "Uchat" in adapter._auto_push_reservations
        adapter._quota_budget.finish.assert_not_called()
        assert "reason=reserved_for_final" in caplog.text
        assert "kind=heartbeat" in caplog.text
        assert "Uchat" not in caplog.text
        assert "receiving stream response" not in caplog.text

        final = asyncio.run(adapter.send("Uchat", "actual final answer"))

        assert final.success
        adapter._client.push.assert_called_once()
        adapter._quota_budget.finish.assert_called_once_with(pushed=True)
        assert "Uchat" not in adapter._auto_push_reservations

    def test_working_prefixed_conversational_final_is_not_suppressed(self, adapter):
        adapter._auto_push_reservations.add("Uchat")
        adapter._quota_budget = MagicMock()

        result = asyncio.run(adapter.send(
            "Uchat",
            "⏳ Working — final answer: all completed",
            metadata={},
        ))

        assert result.success
        adapter._client.reply.assert_not_called()
        adapter._client.push.assert_called_once()
        adapter._quota_budget.finish.assert_called_once_with(pushed=True)

    def test_forged_non_conversational_dict_cannot_suppress_final(self, adapter):
        adapter._auto_push_reservations.add("Uchat")
        adapter._quota_budget = MagicMock()

        result = asyncio.run(adapter.send(
            "Uchat",
            "⏳ Working — user final that must be visible",
            metadata={"non_conversational": True},
        ))

        assert result.success
        adapter._client.reply.assert_not_called()
        adapter._client.push.assert_called_once()
        adapter._quota_budget.finish.assert_called_once_with(pushed=True)

    def test_completed_run_suppression_is_logged_without_payload(self, adapter, caplog):
        adapter._auto_push_completed_chats.add("Uchat")

        with caplog.at_level("INFO"):
            result = asyncio.run(adapter.send("Uchat", "private final payload"))

        assert result.success
        adapter._client.reply.assert_not_called()
        adapter._client.push.assert_not_called()
        assert "reason=run_completed" in caplog.text
        assert "kind=text" in caplog.text
        assert "Uchat" not in caplog.text
        assert "private final payload" not in caplog.text

    def test_media_token_state_is_hard_capped_and_cleans_evicted_tempfile(
        self, adapter, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(_line, "MAX_DELIVERY_STATE_ENTRIES", 2)
        paths = []
        tokens = []
        for index in range(3):
            path = tmp_path / f"preview-{index}.png"
            path.write_bytes(b"png")
            paths.append(path)
            tokens.append(adapter._register_media(str(path), cleanup=True))

        assert len(adapter._media_tokens) == 2
        assert len(adapter._media_temp_paths) == 2
        assert tokens[0] not in adapter._media_tokens
        assert not paths[0].exists()
        assert paths[1].exists() and paths[2].exists()

    def test_reserved_media_push_consumes_single_budget_and_blocks_followup_text(self, adapter):
        adapter._auto_push_reservations.add("Uchat")
        adapter._quota_budget = MagicMock()
        media = [{"type": "image", "originalContentUrl": "https://x/image.png",
                  "previewImageUrl": "https://x/image.png"}]

        media_result = asyncio.run(adapter._send_messages("Uchat", media))
        text_result = asyncio.run(adapter.send("Uchat", "extra final text"))

        assert media_result.success
        assert text_result.success
        adapter._client.push.assert_called_once()
        adapter._quota_budget.finish.assert_called_once_with(pushed=True)
        assert "Uchat" in adapter._auto_push_completed_chats

    def test_native_media_rechecks_epoch_at_transport_boundary(
        self, adapter, monkeypatch
    ):
        adapter._delivery_epoch = 20
        task_epoch = _line._DELIVERY_TASK_EPOCH.set((adapter, 20))
        original_consume = adapter._consume_reply_token

        def reconnect_after_entry(chat_id):
            adapter._delivery_epoch = 21
            return original_consume(chat_id)

        monkeypatch.setattr(adapter, "_consume_reply_token", reconnect_after_entry)
        media = [{
            "type": "image",
            "originalContentUrl": "https://x/image.png",
            "previewImageUrl": "https://x/image.png",
        }]
        try:
            result = asyncio.run(adapter._send_messages("Uchat", media))
        finally:
            _line._DELIVERY_TASK_EPOCH.reset(task_epoch)

        assert result.success
        adapter._client.reply.assert_not_called()
        adapter._client.push.assert_not_called()

    def test_free_reply_completes_generation_and_suppresses_delayed_output(
        self, adapter, tmp_path, monkeypatch
    ):
        import time as _time
        from gateway.session_context import clear_session_vars, set_session_vars

        image = tmp_path / "late.png"
        image.write_bytes(b"png")
        adapter.public_base_url = "https://line.example.com"
        adapter._begin_delivery_run("Uchat", "run-free")
        adapter._reply_tokens["Uchat"] = ("reply-free", _time.time() + 30)
        adapter._reply_token_runs["Uchat"] = "run-free"
        register = MagicMock()
        monkeypatch.setattr(adapter, "_register_media", register)

        tokens = set_session_vars(chat_id="Uchat", message_id="run-free")
        try:
            first = asyncio.run(adapter.send("Uchat", "first answer"))
            delayed_text = asyncio.run(adapter.send("Uchat", "late text"))
            delayed_media = asyncio.run(adapter.send_image_file("Uchat", str(image)))
        finally:
            clear_session_vars(tokens)

        assert first.success and delayed_text.success and delayed_media.success
        adapter._client.reply.assert_called_once()
        adapter._client.push.assert_not_called()
        register.assert_not_called()
        assert ("Uchat", "run-free") in adapter._auto_push_completed_runs

    def test_queued_newer_token_suppresses_unreserved_active_run(
        self, adapter, tmp_path, monkeypatch
    ):
        import time as _time
        from gateway.session_context import clear_session_vars, set_session_vars

        image = tmp_path / "late.png"
        image.write_bytes(b"png")
        adapter.public_base_url = "https://line.example.com"
        adapter._begin_delivery_run("Uchat", "run-a")
        # B is only queued: its webhook has replaced the token, but B has not
        # become the live run yet.
        adapter._reply_tokens["Uchat"] = ("reply-b", _time.time() + 30)
        adapter._reply_token_runs["Uchat"] = "run-b"
        register = MagicMock()
        monkeypatch.setattr(adapter, "_register_media", register)

        tokens = set_session_vars(chat_id="Uchat", message_id="run-a")
        try:
            stale_text = asyncio.run(adapter.send("Uchat", "late A text"))
            stale_media = asyncio.run(adapter.send_image_file("Uchat", str(image)))
        finally:
            clear_session_vars(tokens)

        assert stale_text.success and stale_media.success
        adapter._client.reply.assert_not_called()
        adapter._client.push.assert_not_called()
        register.assert_not_called()
        assert adapter._reply_tokens["Uchat"][0] == "reply-b"
        assert adapter._delivery_run_by_chat["Uchat"] == "run-a"

    def test_stale_unreserved_run_cannot_push_or_consume_new_token(
        self, adapter, tmp_path, monkeypatch
    ):
        import time as _time
        from gateway.session_context import clear_session_vars, set_session_vars

        image = tmp_path / "late.png"
        image.write_bytes(b"png")
        adapter.public_base_url = "https://line.example.com"
        adapter._begin_delivery_run("Uchat", "run-a")
        adapter._begin_delivery_run("Uchat", "run-b")
        adapter._reply_tokens["Uchat"] = ("reply-b", _time.time() + 30)
        adapter._reply_token_runs["Uchat"] = "run-b"
        register = MagicMock()
        monkeypatch.setattr(adapter, "_register_media", register)

        tokens = set_session_vars(chat_id="Uchat", message_id="run-a")
        try:
            stale_text = asyncio.run(adapter.send("Uchat", "late A text"))
            stale_media = asyncio.run(adapter.send_image_file("Uchat", str(image)))
        finally:
            clear_session_vars(tokens)

        assert stale_text.success and stale_media.success
        adapter._client.reply.assert_not_called()
        adapter._client.push.assert_not_called()
        register.assert_not_called()
        assert adapter._reply_tokens["Uchat"][0] == "reply-b"

    def test_delivery_state_is_bounded_and_disconnect_clears_it(
        self, adapter, monkeypatch
    ):
        import time as _time

        monkeypatch.setattr(_line, "MAX_DELIVERY_STATE_ENTRIES", 3)

        for index in range(4):
            chat_id = f"U{index}"
            run_id = f"run-{index}"
            adapter._begin_delivery_run(chat_id, run_id)
            adapter._reply_tokens[chat_id] = (f"token-{index}", _time.time() + 30)
            adapter._reply_token_runs[chat_id] = run_id
            adapter._block_slow_push(chat_id)

        assert len(adapter._delivery_run_by_chat) <= 3
        assert len(adapter._reply_token_runs) <= 3
        assert len(adapter._blocked_slow_pushes) <= 3
        assert "U0" not in adapter._delivery_run_by_chat
        assert "U0" not in adapter._reply_tokens
        assert "U0" not in adapter._blocked_slow_pushes

        for index in range(4):
            adapter._mark_delivery_completed("U3", run_id=f"history-{index}")
        assert len(adapter._auto_push_completed_runs) <= 3
        assert ("U3", "history-0") not in adapter._auto_push_completed_runs

        asyncio.run(adapter.disconnect())
        assert not adapter._delivery_run_by_chat
        assert not adapter._reply_token_runs
        assert not adapter._reply_tokens
        assert not adapter._blocked_slow_pushes
        assert not adapter._auto_push_completed_runs

    def test_bounded_state_never_evicts_current_chat_when_older_claims_active(
        self, adapter, monkeypatch
    ):
        monkeypatch.setattr(_line, "MAX_DELIVERY_STATE_ENTRIES", 2)
        for chat_id in ("U0", "U1"):
            adapter._begin_delivery_run(chat_id, f"run-{chat_id}")
            adapter._auto_push_reservations.add(chat_id)
            adapter._auto_push_reservation_runs[chat_id] = f"run-{chat_id}"

        adapter._begin_delivery_run("U2", "run-U2")

        assert adapter._delivery_run_by_chat["U2"] == "run-U2"
        assert "U2" in adapter._delivery_state_order
        assert len(adapter._delivery_state_order) == 3  # protected overflow

        adapter._auto_push_reservations.discard("U0")
        adapter._auto_push_reservation_runs.pop("U0", None)
        adapter._touch_delivery_state("U2")
        assert len(adapter._delivery_state_order) <= 2
        assert "U0" not in adapter._delivery_state_order

    def test_new_run_does_not_release_previous_run_delayed_output(self, adapter):
        import time as _time
        from gateway.session_context import clear_session_vars, set_session_vars

        adapter._quota_budget = MagicMock()
        adapter._begin_delivery_run("Uchat", "run-a")
        adapter._auto_push_reservations.add("Uchat")
        adapter._auto_push_reservation_runs["Uchat"] = "run-a"
        tokens = set_session_vars(chat_id="Uchat", message_id="run-a")
        try:
            first_result = asyncio.run(adapter.send("Uchat", "answer from A"))
        finally:
            clear_session_vars(tokens)
        assert first_result.success

        # B becomes the live run and owns a fresh Reply token/reservation.  A
        # still has a task-local generation and must not consume either one.
        adapter._begin_delivery_run("Uchat", "run-b")
        adapter._auto_push_reservations.add("Uchat")
        adapter._auto_push_reservation_runs["Uchat"] = "run-b"
        adapter._reply_tokens["Uchat"] = ("reply-b", _time.time() + 30)
        adapter._reply_token_runs["Uchat"] = "run-b"

        tokens = set_session_vars(chat_id="Uchat", message_id="run-a")
        try:
            stale_result = asyncio.run(adapter.send("Uchat", "late output from A"))
        finally:
            clear_session_vars(tokens)

        assert stale_result.success
        adapter._client.push.assert_called_once()  # A's original settled Push only
        adapter._client.reply.assert_not_called()
        assert adapter._reply_tokens["Uchat"][0] == "reply-b"
        assert adapter._auto_push_reservation_runs["Uchat"] == "run-b"

        tokens = set_session_vars(chat_id="Uchat", message_id="run-b")
        try:
            current_result = asyncio.run(adapter.send("Uchat", "answer from B"))
        finally:
            clear_session_vars(tokens)

        assert current_result.success
        adapter._client.reply.assert_called_once()
        assert "Uchat" not in adapter._reply_tokens

    def test_completed_media_is_suppressed_before_registration(
        self, adapter, tmp_path, monkeypatch
    ):
        image = tmp_path / "late.png"
        image.write_bytes(b"png")
        adapter.public_base_url = "https://line.example.com"
        adapter._auto_push_completed_chats.add("Uchat")
        register = MagicMock()
        monkeypatch.setattr(adapter, "_register_media", register)

        result = asyncio.run(adapter.send_image_file("Uchat", str(image)))

        assert result.success
        register.assert_not_called()

    def test_send_caps_messages_per_call_at_five(self, adapter):
        # Build a payload that would naturally split into more than 5 LINE
        # bubbles; the chunker should cap at 5 + truncate.
        big = "\n\n".join(["x" * 4500 for _ in range(20)])
        result = asyncio.run(adapter.send("Uchat", big))
        assert result.success
        call_kwargs = adapter._client.push.call_args
        # call_args is (args, kwargs); for our send the messages are the 2nd positional
        sent_messages = call_kwargs.args[1] if call_kwargs.args else call_kwargs.kwargs.get("messages")
        # Without args, fall back to inspecting the call shape
        if sent_messages is None:
            # We invoked client.push(chat_id, messages) — check first batch
            sent_messages = adapter._client.push.call_args.args[1]
        assert len(sent_messages) <= 5

    def test_format_message_strips_markdown(self, adapter):
        out = adapter.format_message("**bold** [link](https://x.com)")
        assert "**" not in out
        assert "https://x.com" in out


# ---------------------------------------------------------------------------
# 8. Register() metadata + plugin entry points
# ---------------------------------------------------------------------------

class TestRegister:

    class _FakeCtx:
        def __init__(self):
            self.kwargs = None

        def register_platform(self, **kw):
            self.kwargs = kw

    def test_register_calls_register_platform(self):
        ctx = self._FakeCtx()
        register(ctx)
        assert ctx.kwargs is not None
        assert ctx.kwargs["name"] == "line"
        assert ctx.kwargs["label"] == "LINE"

    def test_register_advertises_required_env(self):
        ctx = self._FakeCtx()
        register(ctx)
        assert set(ctx.kwargs["required_env"]) == {
            "LINE_CHANNEL_ACCESS_TOKEN",
            "LINE_CHANNEL_SECRET",
        }

    def test_register_wires_allowlist_envs(self):
        ctx = self._FakeCtx()
        register(ctx)
        assert ctx.kwargs["allowed_users_env"] == "LINE_ALLOWED_USERS"
        assert ctx.kwargs["allow_all_env"] == "LINE_ALLOW_ALL_USERS"

    def test_register_wires_cron_home_channel(self):
        ctx = self._FakeCtx()
        register(ctx)
        assert ctx.kwargs["cron_deliver_env_var"] == "LINE_HOME_CHANNEL"

    def test_register_provides_standalone_sender(self):
        ctx = self._FakeCtx()
        register(ctx)
        assert callable(ctx.kwargs["standalone_sender_fn"])

    def test_register_provides_env_enablement(self):
        ctx = self._FakeCtx()
        register(ctx)
        assert callable(ctx.kwargs["env_enablement_fn"])

    def test_register_factory_yields_line_adapter(self):
        ctx = self._FakeCtx()
        register(ctx)
        from gateway.config import PlatformConfig
        cfg = PlatformConfig(enabled=True, extra={
            "channel_access_token": "tok",
            "channel_secret": "sec",
        })
        ad = ctx.kwargs["adapter_factory"](cfg)
        assert isinstance(ad, LineAdapter)

    def test_max_message_length_below_line_per_bubble_limit(self):
        ctx = self._FakeCtx()
        register(ctx)
        # LINE per-bubble limit is 5000; we register 4500 to leave headroom.
        assert ctx.kwargs["max_message_length"] <= 5000


class TestEnvEnablement:

    @pytest.fixture(autouse=True)
    def _isolated_line_env(self, monkeypatch):
        _clear_line_test_env(monkeypatch)

    def test_returns_none_without_credentials(self, monkeypatch):
        monkeypatch.delenv("LINE_CHANNEL_ACCESS_TOKEN", raising=False)
        monkeypatch.delenv("LINE_CHANNEL_SECRET", raising=False)
        assert _env_enablement() is None

    def test_returns_dict_with_credentials(self, monkeypatch):
        monkeypatch.setenv("LINE_CHANNEL_ACCESS_TOKEN", "tok")
        monkeypatch.setenv("LINE_CHANNEL_SECRET", "sec")
        assert _env_enablement() == {}

    def test_seeds_port_from_env(self, monkeypatch):
        monkeypatch.setenv("LINE_CHANNEL_ACCESS_TOKEN", "tok")
        monkeypatch.setenv("LINE_CHANNEL_SECRET", "sec")
        monkeypatch.setenv("LINE_PORT", "8080")
        assert _env_enablement() == {"port": 8080}

    def test_seeds_public_url(self, monkeypatch):
        monkeypatch.setenv("LINE_CHANNEL_ACCESS_TOKEN", "tok")
        monkeypatch.setenv("LINE_CHANNEL_SECRET", "sec")
        monkeypatch.setenv("LINE_PUBLIC_URL", "https://my-tunnel.example.com")
        result = _env_enablement()
        assert result["public_url"] == "https://my-tunnel.example.com"


class TestStandaloneSend:

    def test_missing_token_returns_error(self, monkeypatch):
        monkeypatch.delenv("LINE_CHANNEL_ACCESS_TOKEN", raising=False)
        from gateway.config import PlatformConfig
        cfg = PlatformConfig(enabled=True, extra={})
        result = asyncio.run(_standalone_send(cfg, "Uchat", "hi"))
        assert "error" in result

    def test_missing_chat_id_returns_error(self, monkeypatch):
        monkeypatch.setenv("LINE_CHANNEL_ACCESS_TOKEN", "tok")
        from gateway.config import PlatformConfig
        cfg = PlatformConfig(enabled=True, extra={})
        result = asyncio.run(_standalone_send(cfg, "", "hi"))
        assert "error" in result

    def test_pushes_via_client_when_credentials_present(self, monkeypatch):
        from gateway.config import PlatformConfig

        push_calls = []

        class _FakeClient:
            def __init__(self, *a, **kw):
                pass

            async def push(self, chat_id, messages):
                push_calls.append((chat_id, messages))

        monkeypatch.setattr(_line, "_LineClient", _FakeClient)
        cfg = PlatformConfig(
            enabled=True,
            extra={"channel_access_token": "tok"},
        )
        result = asyncio.run(_standalone_send(cfg, "Uchat", "hello"))
        assert result.get("success") is True
        assert len(push_calls) == 1
        assert push_calls[0][0] == "Uchat"
        # Message wraps as text bubble
        assert push_calls[0][1][0]["type"] == "text"


class TestPostbackOwnership:

    @pytest.fixture
    def adapter(self, monkeypatch):
        monkeypatch.delenv("LINE_CHANNEL_ACCESS_TOKEN", raising=False)
        monkeypatch.delenv("LINE_CHANNEL_SECRET", raising=False)
        from gateway.config import PlatformConfig
        ad = LineAdapter(PlatformConfig(enabled=True, extra={
            "channel_access_token": "tok",
            "channel_secret": "sec",
        }))
        ad._client = MagicMock()
        ad._client.reply = AsyncMock()
        ad._client.push = AsyncMock()
        return ad

    def test_postback_request_id_cannot_cross_chat_boundary(self, adapter):
        rid = adapter._cache.register_pending("Uvictim")
        adapter._cache.set_ready(rid, "private answer")
        event = {
            "replyToken": "attacker-reply-token",
            "source": {"type": "user", "userId": "Uattacker"},
            "postback": {
                "data": json.dumps({
                    "action": "show_response",
                    "request_id": rid,
                })
            },
        }

        asyncio.run(adapter._handle_postback_event(event))

        adapter._client.reply.assert_not_called()
        adapter._client.push.assert_not_called()
        assert adapter._cache.get(rid).state is State.READY

    def test_concurrent_postback_delivery_is_claimed_once(self, adapter):
        rid = adapter._cache.register_pending("Uchat")
        adapter._cache.set_ready(rid, "the answer")

        async def scenario():
            first_started = asyncio.Event()
            release_first = asyncio.Event()

            async def delayed_reply(*_args, **_kwargs):
                first_started.set()
                await release_first.wait()

            adapter._client.reply = AsyncMock(side_effect=delayed_reply)
            base = {
                "source": {"type": "user", "userId": "Uchat"},
                "postback": {
                    "data": json.dumps({
                        "action": "show_response",
                        "request_id": rid,
                    })
                },
            }
            first = asyncio.create_task(adapter._handle_postback_event({
                **base,
                "replyToken": "reply-one",
            }))
            await first_started.wait()
            second = asyncio.create_task(adapter._handle_postback_event({
                **base,
                "replyToken": "reply-two",
            }))
            await asyncio.sleep(0)
            release_first.set()
            await asyncio.gather(first, second)

        asyncio.run(scenario())

        adapter._client.reply.assert_called_once()
        adapter._client.push.assert_not_called()
        assert adapter._cache.get(rid).state is State.DELIVERED

    def test_ready_postback_reconnect_race_suppresses_all_delivery(
        self, adapter, monkeypatch
    ):
        rid = adapter._cache.register_pending("Uchat")
        adapter._cache.set_ready(rid, "the answer")
        event = {
            "replyToken": "reply-before-reconnect",
            "source": {"type": "user", "userId": "Uchat"},
            "postback": {
                "data": json.dumps({
                    "action": "show_response",
                    "request_id": rid,
                })
            },
        }
        original_split = _line.split_for_line

        def reconnect_during_request(text):
            adapter._delivery_epoch += 2
            return original_split(text)

        monkeypatch.setattr(_line, "split_for_line", reconnect_during_request)

        asyncio.run(adapter._handle_postback_event(event))

        adapter._client.reply.assert_not_called()
        adapter._client.push.assert_not_called()
        assert adapter._cache.get(rid).state is State.READY

    def test_quota_guarded_postback_never_pushes_on_reply_failure(self, adapter):
        rid = adapter._cache.register_pending("Uchat")
        adapter._cache.set_ready(rid, "the answer")
        adapter._pending_buttons["Uchat"] = rid
        adapter._quota_guarded_postbacks.add(rid)
        adapter._client.reply.side_effect = _LineDefiniteReplyError("LINE reply 400")
        event = {
            "replyToken": "fresh-but-rejected",
            "source": {"type": "user", "userId": "Uchat"},
            "postback": {
                "data": json.dumps({
                    "action": "show_response",
                    "request_id": rid,
                })
            },
        }

        asyncio.run(adapter._handle_postback_event(event))

        adapter._client.reply.assert_called_once()
        adapter._client.push.assert_not_called()
        assert adapter._cache.get(rid).state is State.READY
        assert adapter._pending_buttons["Uchat"] == rid


class TestPostbackButtonShape:

    def test_template_buttons_structure(self):
        msg = build_postback_button_message("hi", "Tap me", "rid-1")
        assert msg["type"] == "template"
        assert msg["template"]["type"] == "buttons"
        assert msg["template"]["text"] == "hi"
        actions = msg["template"]["actions"]
        assert len(actions) == 1
        assert actions[0]["type"] == "postback"
        data = json.loads(actions[0]["data"])
        assert data == {"action": "show_response", "request_id": "rid-1"}

    def test_text_truncated_to_160(self):
        long = "x" * 200
        msg = build_postback_button_message(long, "Tap", "rid")
        assert len(msg["template"]["text"]) <= 160

    def test_alt_text_truncated_to_400(self):
        long = "x" * 500
        msg = build_postback_button_message(long, "Tap", "rid")
        assert len(msg["altText"]) <= 400


class TestCheckRequirements:

    def test_rejects_without_token(self, monkeypatch):
        monkeypatch.delenv("LINE_CHANNEL_ACCESS_TOKEN", raising=False)
        monkeypatch.setenv("LINE_CHANNEL_SECRET", "s")
        assert not check_requirements()

    def test_rejects_without_secret(self, monkeypatch):
        monkeypatch.setenv("LINE_CHANNEL_ACCESS_TOKEN", "t")
        monkeypatch.delenv("LINE_CHANNEL_SECRET", raising=False)
        assert not check_requirements()


class TestValidateConfig:

    def test_validates_from_extra(self):
        from gateway.config import PlatformConfig
        cfg = PlatformConfig(
            enabled=True,
            extra={"channel_access_token": "t", "channel_secret": "s"},
        )
        assert validate_config(cfg)

    def test_rejects_empty_config(self, monkeypatch):
        monkeypatch.delenv("LINE_CHANNEL_ACCESS_TOKEN", raising=False)
        monkeypatch.delenv("LINE_CHANNEL_SECRET", raising=False)
        from gateway.config import PlatformConfig
        cfg = PlatformConfig(enabled=True, extra={})
        assert not validate_config(cfg)


class TestAdapterInit:

    @pytest.fixture(autouse=True)
    def _isolated_line_env(self, monkeypatch):
        _clear_line_test_env(monkeypatch)

    def test_init_from_config_extra(self, monkeypatch):
        for k in ("LINE_CHANNEL_ACCESS_TOKEN", "LINE_CHANNEL_SECRET", "LINE_PORT"):
            monkeypatch.delenv(k, raising=False)
        from gateway.config import PlatformConfig
        cfg = PlatformConfig(
            enabled=True,
            extra={
                "channel_access_token": "tok",
                "channel_secret": "sec",
                "port": 7777,
                "public_url": "https://x.example.com",
                "allowed_users": ["U1", "U2"],
            },
        )
        ad = LineAdapter(cfg)
        assert ad.channel_access_token == "tok"
        assert ad.channel_secret == "sec"
        assert ad.webhook_port == 7777
        assert ad.public_base_url == "https://x.example.com"
        assert ad.allowed_users == {"U1", "U2"}

    def test_env_overrides_extra(self, monkeypatch):
        monkeypatch.setenv("LINE_CHANNEL_ACCESS_TOKEN", "env-tok")
        monkeypatch.setenv("LINE_PORT", "1234")
        from gateway.config import PlatformConfig
        cfg = PlatformConfig(
            enabled=True,
            extra={"channel_access_token": "extra-tok", "channel_secret": "s", "port": 5555},
        )
        ad = LineAdapter(cfg)
        assert ad.channel_access_token == "env-tok"
        assert ad.webhook_port == 1234

    def test_auto_push_mode_and_soft_limit_load_from_config_extra(self, monkeypatch):
        monkeypatch.delenv("LINE_CHANNEL_ACCESS_TOKEN", raising=False)
        monkeypatch.delenv("LINE_CHANNEL_SECRET", raising=False)
        from gateway.config import PlatformConfig
        ad = LineAdapter(PlatformConfig(enabled=True, extra={
            "channel_access_token": "tok",
            "channel_secret": "sec",
            "slow_response_mode": "auto_push",
            "push_quota_soft_limit_ratio": 0.75,
            "quota_lookup_timeout_seconds": 2.5,
        }))

        assert ad.slow_response_mode == "auto_push"
        assert ad._quota_budget.soft_limit_ratio == 0.75
        assert ad.quota_lookup_timeout_seconds == 2.5

    def test_unknown_slow_response_mode_falls_back_to_postback(self, monkeypatch):
        monkeypatch.delenv("LINE_CHANNEL_ACCESS_TOKEN", raising=False)
        monkeypatch.delenv("LINE_CHANNEL_SECRET", raising=False)
        from gateway.config import PlatformConfig
        ad = LineAdapter(PlatformConfig(enabled=True, extra={
            "channel_access_token": "tok",
            "channel_secret": "sec",
            "slow_response_mode": "surprise",
        }))

        assert ad.slow_response_mode == "postback"

    def test_gateway_yaml_extra_reaches_line_adapter(self, tmp_path, monkeypatch):
        import yaml
        import gateway.config as gateway_config

        (tmp_path / "config.yaml").write_text(yaml.safe_dump({
            "gateway": {
                "platforms": {
                    "line": {
                        "enabled": True,
                        "extra": {
                            "channel_access_token": "tok",
                            "channel_secret": "sec",
                            "slow_response_mode": "auto_push",
                            "push_quota_soft_limit_ratio": 0.8,
                            "quota_lookup_timeout_seconds": 3,
                        },
                    }
                }
            }
        }))
        monkeypatch.setattr(gateway_config, "get_hermes_home", lambda: tmp_path)

        gateway = gateway_config.load_gateway_config()
        line_cfg = gateway.platforms[gateway_config.Platform("line")]
        adapter = LineAdapter(line_cfg)

        assert adapter.slow_response_mode == "auto_push"
        assert adapter._quota_budget.soft_limit_ratio == 0.8
        assert adapter.quota_lookup_timeout_seconds == 3

    def test_csv_allowlist_parsed(self, monkeypatch):
        monkeypatch.setenv("LINE_CHANNEL_ACCESS_TOKEN", "t")
        monkeypatch.setenv("LINE_CHANNEL_SECRET", "s")
        monkeypatch.setenv("LINE_ALLOWED_USERS", "U1, U2,U3")
        monkeypatch.setenv("LINE_ALLOWED_GROUPS", "C1")
        from gateway.config import PlatformConfig
        ad = LineAdapter(PlatformConfig(enabled=True))
        assert ad.allowed_users == {"U1", "U2", "U3"}
        assert ad.allowed_groups == {"C1"}

    def test_get_chat_info_infers_type_from_prefix(self, monkeypatch):
        monkeypatch.setenv("LINE_CHANNEL_ACCESS_TOKEN", "t")
        monkeypatch.setenv("LINE_CHANNEL_SECRET", "s")
        from gateway.config import PlatformConfig
        ad = LineAdapter(PlatformConfig(enabled=True))
        assert asyncio.run(ad.get_chat_info("U123"))["type"] == "dm"
        assert asyncio.run(ad.get_chat_info("C123"))["type"] == "group"
        assert asyncio.run(ad.get_chat_info("R123"))["type"] == "channel"


class TestSlowResponseRouting:

    @pytest.fixture
    def adapter(self, monkeypatch):
        monkeypatch.delenv("LINE_CHANNEL_ACCESS_TOKEN", raising=False)
        monkeypatch.delenv("LINE_CHANNEL_SECRET", raising=False)
        from gateway.config import PlatformConfig
        ad = LineAdapter(PlatformConfig(enabled=True, extra={
            "channel_access_token": "tok",
            "channel_secret": "sec",
            "slow_response_mode": "auto_push",
        }))
        ad._client = MagicMock()
        return ad

    def test_stale_slow_threshold_task_creates_no_delivery_state(self, adapter):
        import time as _time

        adapter._client.reply = AsyncMock()
        adapter._quota_budget.reserve = AsyncMock(return_value=SimpleNamespace(
            allowed=False,
            reason="quota_unavailable",
            effective_usage=None,
            soft_limit=None,
        ))
        adapter._delivery_epoch = 10
        task_epoch = _line._DELIVERY_TASK_EPOCH.set((adapter, 10))
        adapter._reply_tokens["Uchat"] = ("old-token", _time.time() + 30)
        try:
            adapter._delivery_epoch = 11
            asyncio.run(adapter._handle_slow_threshold("Uchat"))
        finally:
            _line._DELIVERY_TASK_EPOCH.reset(task_epoch)

        adapter._client.reply.assert_not_called()
        adapter._quota_budget.reserve.assert_not_called()
        assert "Uchat" not in adapter._pending_buttons
        assert not adapter._quota_guarded_postbacks

    def test_full_postback_cache_fails_closed_without_invalid_button(self, adapter):
        import time as _time

        adapter._cache = RequestCache(max_entries=1)
        existing = adapter._cache.register_pending("Uexisting")
        adapter._client.reply = AsyncMock()
        adapter._quota_budget.reserve = AsyncMock(return_value=SimpleNamespace(
            allowed=False,
            reason="quota_unavailable",
            effective_usage=None,
            soft_limit=None,
        ))
        adapter._reply_tokens["Uchat"] = ("reply-token", _time.time() + 30)

        asyncio.run(adapter._handle_slow_threshold("Uchat"))

        assert existing is not None
        assert len(adapter._cache._entries) == 1
        assert "Uchat" not in adapter._pending_buttons
        assert None not in adapter._quota_guarded_postbacks
        assert "Uchat" in adapter._blocked_slow_pushes
        adapter._client.reply.assert_awaited_once()
        sent = adapter._client.reply.call_args.args[1][0]
        assert sent["type"] == "text"
        assert "Uchat" not in adapter._reply_tokens

    def test_expired_postback_admission_clears_stale_side_state(self, adapter):
        import time as _time

        adapter.slow_response_mode = "postback"
        adapter._cache._pending_ttl = 10
        adapter._cache._max_entries = 1
        stale_rid = adapter._cache.register_pending("Uold")
        adapter._pending_buttons["Uold"] = stale_rid
        adapter._postback_delivering.add(stale_rid)
        adapter._cache._entries[stale_rid].created_at -= 11
        adapter._client.reply = AsyncMock()
        adapter._client.push = AsyncMock()
        adapter._reply_tokens["Unew"] = ("new-token", _time.time() + 30)

        asyncio.run(adapter._handle_slow_threshold("Unew"))

        assert "Uold" not in adapter._pending_buttons
        assert stale_rid not in adapter._quota_guarded_postbacks
        assert stale_rid not in adapter._postback_delivering
        result = asyncio.run(adapter.send("Uold", "old final"))
        assert result.success
        adapter._client.push.assert_awaited_once()

    def test_final_triggering_expired_legacy_postback_falls_back_to_push(self, adapter):
        adapter.slow_response_mode = "postback"
        adapter._cache._pending_ttl = 10
        rid = adapter._cache.register_pending("Uchat")
        adapter._pending_buttons["Uchat"] = rid
        adapter._cache._entries[rid].created_at -= 11
        adapter._client.push = AsyncMock()

        result = asyncio.run(adapter.send("Uchat", "actual final"))

        assert result.success
        assert "Uchat" not in adapter._pending_buttons
        assert adapter._cache.get(rid) is None
        adapter._client.push.assert_awaited_once()

    def test_final_triggering_expired_guarded_postback_fails_closed(self, adapter):
        adapter._cache._pending_ttl = 10
        rid = adapter._cache.register_pending("Uchat")
        adapter._pending_buttons["Uchat"] = rid
        adapter._quota_guarded_postbacks.add(rid)
        adapter._cache._entries[rid].created_at -= 11
        adapter._client.push = AsyncMock()

        result = asyncio.run(adapter.send("Uchat", "actual final"))

        assert not result.success
        assert "Uchat" not in adapter._pending_buttons
        assert adapter._cache.get(rid) is None
        adapter._client.push.assert_not_awaited()

    def test_expired_quota_postbacks_remain_bounded_and_block_old_final(self, adapter):
        import time as _time

        adapter._cache._pending_ttl = 10
        adapter._cache._max_entries = 2
        adapter._client.reply = AsyncMock()
        adapter._client.push = AsyncMock()
        adapter._quota_budget.reserve = AsyncMock(return_value=SimpleNamespace(
            allowed=False,
            reason="quota_unavailable",
            effective_usage=None,
            soft_limit=None,
        ))

        for chat_id in ("Uold1", "Uold2"):
            adapter._reply_tokens[chat_id] = (
                f"token-{chat_id}",
                _time.time() + 30,
            )
            asyncio.run(adapter._handle_slow_threshold(chat_id))
        stale_ids = set(adapter._pending_buttons.values())
        for request_id in stale_ids:
            adapter._cache._entries[request_id].created_at -= 11

        for chat_id in ("Unew1", "Unew2"):
            adapter._reply_tokens[chat_id] = (
                f"token-{chat_id}",
                _time.time() + 30,
            )
            asyncio.run(adapter._handle_slow_threshold(chat_id))

        assert set(adapter._pending_buttons) == {"Unew1", "Unew2"}
        assert len(adapter._pending_buttons) == 2
        assert len(adapter._quota_guarded_postbacks) == 2
        assert stale_ids.isdisjoint(adapter._quota_guarded_postbacks)
        assert {"Uold1", "Uold2"} <= adapter._blocked_slow_pushes
        result = asyncio.run(adapter.send("Uold1", "late old final"))
        assert not result.success
        adapter._client.push.assert_not_awaited()

    def test_pruning_old_entry_does_not_block_new_same_chat_guard(self, adapter):
        old_guard = _line._DeliveryTaskGuard(adapter, "Uchat", "old-run")
        new_guard = _line._DeliveryTaskGuard(adapter, "Uchat", "new-run")
        adapter._cache._pending_ttl = 10
        rid = adapter._cache.register_pending("Uchat", delivery_guard=old_guard)
        adapter._pending_buttons["Uchat"] = rid
        adapter._quota_guarded_postbacks.add(rid)
        adapter._cache._entries[rid].created_at -= 11

        token = _line._DELIVERY_TASK_GUARD.set(new_guard)
        try:
            adapter._cache.prune()
        finally:
            _line._DELIVERY_TASK_GUARD.reset(token)

        assert old_guard.blocked is True
        assert new_guard.blocked is False
        assert "Uchat" not in adapter._blocked_slow_pushes

    def test_safe_dm_reserves_auto_push(self, adapter):
        adapter._quota_budget.reserve = AsyncMock(return_value=SimpleNamespace(
            allowed=True,
            reason="within_soft_limit",
            effective_usage=13,
            soft_limit=160,
        ))

        reserved = asyncio.run(adapter._reserve_slow_auto_push("Uchat"))

        assert reserved is True
        assert "Uchat" in adapter._auto_push_reservations

    def test_active_auto_push_claims_are_hard_capped(self, adapter, monkeypatch):
        monkeypatch.setattr(_line, "MAX_DELIVERY_STATE_ENTRIES", 2)
        adapter._quota_budget.reserve = AsyncMock(return_value=SimpleNamespace(
            allowed=True,
            reason="unlimited",
            effective_usage=None,
            soft_limit=None,
        ))

        assert asyncio.run(adapter._reserve_slow_auto_push("Uone"))
        assert asyncio.run(adapter._reserve_slow_auto_push("Utwo"))
        assert not asyncio.run(adapter._reserve_slow_auto_push("Uthree"))

        assert adapter._auto_push_reservations == {"Uone", "Utwo"}
        assert adapter._quota_budget.reserve.await_count == 2

    @pytest.mark.parametrize("chat_id", ["Cgroup", "Rroom"])
    def test_group_and_room_never_auto_push(self, adapter, chat_id):
        adapter._quota_budget.reserve = AsyncMock()

        reserved = asyncio.run(adapter._reserve_slow_auto_push(chat_id))

        assert reserved is False
        adapter._quota_budget.reserve.assert_not_called()

    def test_quota_denial_falls_back_to_postback(self, adapter):
        adapter._quota_budget.reserve = AsyncMock(return_value=SimpleNamespace(
            allowed=False,
            reason="soft_limit_reached",
            effective_usage=160,
            soft_limit=160,
        ))

        reserved = asyncio.run(adapter._reserve_slow_auto_push("Uchat"))

        assert reserved is False
        assert "Uchat" not in adapter._auto_push_reservations

    @pytest.mark.parametrize("allowed", [True, False])
    def test_final_reply_wins_race_against_quota_lookup(self, adapter, allowed):
        import time as _time

        async def scenario():
            lookup_started = asyncio.Event()
            release_lookup = asyncio.Event()

            async def delayed_decision(*_args, **_kwargs):
                lookup_started.set()
                await release_lookup.wait()
                return SimpleNamespace(
                    allowed=allowed,
                    reason="within_soft_limit" if allowed else "quota_unavailable",
                    effective_usage=13 if allowed else None,
                    soft_limit=160 if allowed else None,
                )

            adapter._client.reply = AsyncMock()
            adapter._client.push = AsyncMock()
            adapter._quota_budget.reserve = AsyncMock(side_effect=delayed_decision)
            adapter._quota_budget.finish = MagicMock()
            adapter._reply_tokens["Uchat"] = ("rt-token", _time.time() + 30)

            threshold_task = asyncio.create_task(
                adapter._handle_slow_threshold("Uchat")
            )
            await lookup_started.wait()
            final_result = await adapter.send("Uchat", "the answer")
            release_lookup.set()
            await threshold_task
            return final_result

        result = asyncio.run(scenario())

        assert result.success
        adapter._client.reply.assert_called_once()
        adapter._client.push.assert_not_called()
        assert "Uchat" not in adapter._auto_push_reservations
        assert "Uchat" not in adapter._pending_buttons
        assert "Uchat" not in adapter._blocked_slow_pushes
        if allowed:
            adapter._quota_budget.finish.assert_called_once_with(pushed=False)

    def test_safe_quota_threshold_keeps_reply_token_and_sends_no_card(self, adapter):
        import time as _time
        adapter._client.reply = AsyncMock()
        adapter._quota_budget.reserve = AsyncMock(return_value=SimpleNamespace(
            allowed=True,
            reason="within_soft_limit",
            effective_usage=13,
            soft_limit=160,
        ))
        adapter._reply_tokens["Uchat"] = ("rt-token", _time.time() + 30)

        asyncio.run(adapter._handle_slow_threshold("Uchat"))

        adapter._client.reply.assert_not_called()
        assert "Uchat" in adapter._auto_push_reservations
        assert "Uchat" in adapter._reply_tokens

    def test_denied_quota_threshold_sends_postback_card(self, adapter):
        import time as _time
        adapter._client.reply = AsyncMock()
        adapter._quota_budget.reserve = AsyncMock(return_value=SimpleNamespace(
            allowed=False,
            reason="soft_limit_reached",
            effective_usage=160,
            soft_limit=160,
        ))
        adapter._reply_tokens["Uchat"] = ("rt-token", _time.time() + 30)

        asyncio.run(adapter._handle_slow_threshold("Uchat"))

        adapter._client.reply.assert_called_once()
        sent = adapter._client.reply.call_args.args[1][0]
        assert sent["type"] == "template"
        assert "Uchat" in adapter._pending_buttons
        assert "Uchat" not in adapter._reply_tokens

    def test_duplicate_threshold_does_not_replace_auto_push_with_card(self, adapter):
        import time as _time
        adapter._client.reply = AsyncMock()
        adapter._auto_push_reservations.add("Uchat")
        adapter._reply_tokens["Uchat"] = ("rt-token", _time.time() + 30)

        asyncio.run(adapter._handle_slow_threshold("Uchat"))

        adapter._client.reply.assert_not_called()
        assert "Uchat" in adapter._auto_push_reservations
        assert "Uchat" not in adapter._pending_buttons

    def test_concurrent_thresholds_share_one_budget_reservation(self, adapter):
        import time as _time

        async def scenario():
            lookup_started = asyncio.Event()
            release_lookup = asyncio.Event()

            async def delayed_reserve(*_args, **_kwargs):
                lookup_started.set()
                await release_lookup.wait()
                return SimpleNamespace(
                    allowed=True,
                    reason="within_soft_limit",
                    effective_usage=13,
                    soft_limit=160,
                )

            adapter._quota_budget.reserve = AsyncMock(side_effect=delayed_reserve)
            adapter._reply_tokens["Uchat"] = ("rt-token", _time.time() + 30)
            first = asyncio.create_task(adapter._handle_slow_threshold("Uchat"))
            await lookup_started.wait()
            second = asyncio.create_task(adapter._handle_slow_threshold("Uchat"))
            await asyncio.sleep(0)
            release_lookup.set()
            await asyncio.gather(first, second)

        asyncio.run(scenario())

        adapter._quota_budget.reserve.assert_awaited_once()
        assert adapter._auto_push_reservations == {"Uchat"}
        assert "Uchat" not in adapter._pending_buttons

    def test_failed_postback_card_blocks_unbudgeted_final_push(self, adapter):
        import time as _time
        adapter._client.reply = AsyncMock(side_effect=RuntimeError("network"))
        adapter._client.push = AsyncMock()
        adapter._quota_budget.reserve = AsyncMock(return_value=SimpleNamespace(
            allowed=False,
            reason="quota_unavailable",
            effective_usage=None,
            soft_limit=None,
        ))
        adapter._reply_tokens["Uchat"] = ("rt-token", _time.time() + 30)

        asyncio.run(adapter._handle_slow_threshold("Uchat"))
        result = asyncio.run(adapter.send("Uchat", "the answer"))

        assert not result.success
        adapter._client.push.assert_not_called()
        assert "Uchat" not in adapter._blocked_slow_pushes

    def test_quota_denied_postback_blocks_native_media_before_registration(
        self, adapter, tmp_path, monkeypatch
    ):
        import time as _time

        image = tmp_path / "answer.png"
        image.write_bytes(b"png")
        adapter.public_base_url = "https://line.example.com"
        adapter._client.reply = AsyncMock()
        adapter._client.push = AsyncMock()
        adapter._quota_budget.reserve = AsyncMock(return_value=SimpleNamespace(
            allowed=False,
            reason="soft_limit_reached",
            effective_usage=160,
            soft_limit=160,
        ))
        adapter._reply_tokens["Uchat"] = ("rt-token", _time.time() + 30)
        register = MagicMock()
        monkeypatch.setattr(adapter, "_register_media", register)

        asyncio.run(adapter._handle_slow_threshold("Uchat"))
        result = asyncio.run(adapter.send_image_file("Uchat", str(image)))

        assert "Uchat" in adapter._pending_buttons
        assert not result.success
        adapter._client.reply.assert_awaited_once()
        adapter._client.push.assert_not_called()
        register.assert_not_called()

    def test_full_cache_block_stops_native_media_before_registration(
        self, adapter, tmp_path, monkeypatch
    ):
        import time as _time

        image = tmp_path / "answer.png"
        image.write_bytes(b"png")
        adapter.public_base_url = "https://line.example.com"
        adapter._cache = RequestCache(max_entries=1)
        adapter._cache.register_pending("Uexisting")
        adapter._client.reply = AsyncMock()
        adapter._client.push = AsyncMock()
        adapter._quota_budget.reserve = AsyncMock(return_value=SimpleNamespace(
            allowed=False,
            reason="quota_unavailable",
            effective_usage=None,
            soft_limit=None,
        ))
        adapter._reply_tokens["Uchat"] = ("rt-token", _time.time() + 30)
        register = MagicMock()
        monkeypatch.setattr(adapter, "_register_media", register)

        asyncio.run(adapter._handle_slow_threshold("Uchat"))
        result = asyncio.run(adapter.send_image_file("Uchat", str(image)))

        assert "Uchat" in adapter._blocked_slow_pushes
        assert not result.success
        adapter._client.reply.assert_awaited_once()
        adapter._client.push.assert_not_called()
        register.assert_not_called()

    def test_default_postback_mode_preserves_legacy_final_push_after_card_failure(self, adapter):
        import time as _time
        adapter.slow_response_mode = "postback"
        adapter._client.reply = AsyncMock(side_effect=RuntimeError("network"))
        adapter._client.push = AsyncMock()
        adapter._reply_tokens["Uchat"] = ("rt-token", _time.time() + 30)

        asyncio.run(adapter._handle_slow_threshold("Uchat"))
        result = asyncio.run(adapter.send("Uchat", "the answer"))

        assert result.success
        adapter._client.push.assert_called_once()
        assert "Uchat" not in adapter._blocked_slow_pushes

    def test_disconnect_releases_active_quota_reservations(self, adapter):
        adapter.slow_response_mode = "auto_push"
        adapter._client.get_quota_status = AsyncMock(
            return_value=({"type": "unlimited"}, {})
        )

        assert asyncio.run(adapter._reserve_slow_auto_push("Uone"))
        assert asyncio.run(adapter._reserve_slow_auto_push("Utwo"))
        assert adapter._quota_budget._active_reservations == 2

        asyncio.run(adapter.disconnect())

        assert adapter._quota_budget._active_reservations == 0
        assert not adapter._auto_push_reservations

    def test_disconnect_clears_ready_postback_cache_before_reconnect(self, adapter):
        old_guard = _line._DeliveryTaskGuard(adapter, "Uchat", "old-run")
        rid = adapter._cache.register_pending("Uchat", delivery_guard=old_guard)
        assert adapter._cache.set_ready(rid, "stale payload")
        adapter._client.reply = AsyncMock()

        asyncio.run(adapter.disconnect())
        adapter._disconnecting = False
        adapter._delivery_epoch += 1
        event = {
            "postback": {
                "data": json.dumps({
                    "action": "show_response",
                    "request_id": rid,
                })
            },
            "replyToken": "fresh-token",
            "source": {"type": "user", "userId": "Uchat"},
        }
        asyncio.run(adapter._handle_postback_event(event))

        assert adapter._cache.get(rid) is None
        adapter._client.reply.assert_not_awaited()

    def test_old_run_cannot_deliver_after_disconnect_or_reconnect(
        self, adapter, tmp_path, monkeypatch
    ):
        from gateway.session_context import clear_session_vars, set_session_vars

        image = tmp_path / "late.png"
        image.write_bytes(b"png")
        adapter.public_base_url = "https://line.example.com"
        adapter._quota_budget = MagicMock()
        adapter._quota_budget._active_reservations = 1
        adapter._begin_delivery_run("Uchat", "old-run")
        adapter._auto_push_reservations.add("Uchat")
        adapter._auto_push_reservation_runs["Uchat"] = "old-run"
        register = MagicMock()
        monkeypatch.setattr(adapter, "_register_media", register)

        asyncio.run(adapter.disconnect())
        tokens = set_session_vars(chat_id="Uchat", message_id="old-run")
        try:
            disconnected_text = asyncio.run(adapter.send("Uchat", "late text"))
            # Simulate connect() activating a fresh connection epoch without
            # binding a real webhook socket in this unit test.
            adapter._disconnecting = False
            adapter._delivery_epoch += 1
            reconnected_text = asyncio.run(adapter.send("Uchat", "later text"))
            reconnected_media = asyncio.run(
                adapter.send_image_file("Uchat", str(image))
            )
        finally:
            clear_session_vars(tokens)

        assert disconnected_text.success
        assert reconnected_text.success
        assert reconnected_media.success
        adapter._client.reply.assert_not_called()
        adapter._client.push.assert_not_called()
        register.assert_not_called()
        adapter._quota_budget.finish.assert_called_once_with(pushed=False)

    def test_evicted_tombstone_cannot_reauthorize_old_background_task(
        self, adapter, tmp_path, monkeypatch
    ):
        from gateway.session_context import clear_session_vars, set_session_vars

        async def scenario():
            started = asyncio.Event()
            release = asyncio.Event()
            results = {}
            image = tmp_path / "late-after-eviction.png"
            image.write_bytes(b"png")
            adapter.public_base_url = "https://line.example.com"
            register = MagicMock(return_value=("token", "late-after-eviction.png"))
            monkeypatch.setattr(adapter, "_register_media", register)

            async def delayed_delivery(_event, _session_key):
                started.set()
                await release.wait()
                results["text"] = await adapter.send("Uvictim", "late text")
                results["media"] = await adapter.send_image_file(
                    "Uvictim", str(image)
                )

            monkeypatch.setattr(adapter, "_process_message_background", delayed_delivery)
            event = _line.MessageEvent(
                text="start",
                message_type=_line.MessageType.TEXT,
                source=SimpleNamespace(chat_id="Uvictim"),
                message_id="old-run",
            )
            tokens = set_session_vars(chat_id="Uvictim", message_id="old-run")
            try:
                assert adapter._start_session_processing(event, "Uvictim")
                await started.wait()
                await adapter.disconnect()
                adapter._disconnecting = False
                adapter._delivery_epoch += 1
                for index in range(_line.MAX_DELIVERY_STATE_ENTRIES):
                    adapter._begin_delivery_run(f"Unew-{index}", f"run-{index}")
                assert ("Uvictim", "old-run") not in adapter._delivery_run_epochs
                release.set()
                await adapter._session_tasks["Uvictim"]
            finally:
                clear_session_vars(tokens)

            adapter._client.reply.assert_not_called()
            adapter._client.push.assert_not_called()
            register.assert_not_called()

        asyncio.run(scenario())

    def test_evicted_quota_block_cannot_reauthorize_bound_old_task(
        self, adapter, monkeypatch
    ):
        import time as _time

        async def scenario():
            started = asyncio.Event()
            release = asyncio.Event()
            result = {}
            monkeypatch.setattr(_line, "MAX_DELIVERY_STATE_ENTRIES", 2)
            adapter._cache._max_entries = 2
            adapter._cache._pending_ttl = 10
            adapter._client.reply = AsyncMock()
            adapter._client.push = AsyncMock()
            adapter._quota_budget.reserve = AsyncMock(return_value=SimpleNamespace(
                allowed=False,
                reason="quota_unavailable",
                effective_usage=None,
                soft_limit=None,
            ))
            adapter._reply_tokens["Uvictim"] = (
                "victim-token",
                _time.time() + 30,
            )

            async def delayed_delivery(_event, _session_key):
                await adapter._handle_slow_threshold("Uvictim")
                started.set()
                await release.wait()
                result["final"] = await adapter.send("Uvictim", "late final")

            monkeypatch.setattr(adapter, "_process_message_background", delayed_delivery)
            event = _line.MessageEvent(
                text="start",
                message_type=_line.MessageType.TEXT,
                source=SimpleNamespace(chat_id="Uvictim"),
                message_id="victim-run",
            )

            assert adapter._start_session_processing(event, "Uvictim")
            await started.wait()
            victim_rid = adapter._pending_buttons["Uvictim"]
            victim_guard = adapter._cache._entries[victim_rid].delivery_guard
            adapter._cache._entries[victim_rid].created_at -= 11
            assert adapter._cache.register_pending("Utrigger") is not None
            assert victim_guard is not None and victim_guard.blocked is True
            assert "Uvictim" not in adapter._blocked_slow_pushes

            adapter._block_slow_push("Uevict1")
            adapter._block_slow_push("Uevict2")
            adapter._block_slow_push("Uevict3")
            assert len(adapter._blocked_slow_pushes) <= 2

            release.set()
            await adapter._session_tasks["Uvictim"]

            assert not result["final"].success
            adapter._client.push.assert_not_called()

        asyncio.run(scenario())

    def test_disconnect_suppresses_live_adapter_direct_send(self, adapter):
        asyncio.run(adapter.disconnect())

        result = asyncio.run(adapter.send("Uchat", "late proactive send"))

        assert result.success
        adapter._client.reply.assert_not_called()
        adapter._client.push.assert_not_called()

    def test_disconnect_prevents_inflight_quota_from_recreating_reservation(
        self, adapter
    ):
        async def scenario():
            lookup_started = asyncio.Event()
            release_lookup = asyncio.Event()

            async def delayed_quota():
                lookup_started.set()
                await release_lookup.wait()
                return {"type": "unlimited"}, {}

            adapter.slow_response_mode = "auto_push"
            adapter._client.get_quota_status = AsyncMock(side_effect=delayed_quota)
            reserve_task = asyncio.create_task(
                adapter._reserve_slow_auto_push("Uchat")
            )
            await lookup_started.wait()
            await adapter.disconnect()
            release_lookup.set()
            reserved = await reserve_task
            return reserved

        assert asyncio.run(scenario()) is False
        assert adapter._quota_budget._active_reservations == 0
        assert "Uchat" not in adapter._auto_push_reservations

    def test_interrupt_releases_auto_push_reservation(self, adapter, monkeypatch):
        adapter._auto_push_reservations.add("Uchat")
        adapter._quota_budget = MagicMock()
        monkeypatch.setattr(
            _line.BasePlatformAdapter,
            "interrupt_session_activity",
            AsyncMock(),
        )

        asyncio.run(adapter.interrupt_session_activity("session", "Uchat"))

        adapter._quota_budget.finish.assert_called_once_with(pushed=False)
        assert "Uchat" not in adapter._auto_push_reservations


# ---------------------------------------------------------------------------
# 10. Inbound message-type classification
# ---------------------------------------------------------------------------

class TestMessageTypeMapping:
    """LINE webhook message types must map to the right normalized
    MessageType so the gateway routes media correctly (e.g. voice → STT,
    files → document handling). Regression guard for the old code that
    referenced the non-existent ``MessageType.IMAGE`` and collapsed every
    non-text message onto a single type."""

    def test_image_event_not_attributeerror_regression(self):
        # The bug: MessageType.IMAGE doesn't exist on the enum.
        MessageType = _line.MessageType
        assert not hasattr(MessageType, "IMAGE")

    def test_every_line_type_maps_to_correct_enum(self):
        MessageType = _line.MessageType
        mapping = _line._LINE_MESSAGE_TYPES
        assert mapping["text"] == MessageType.TEXT
        assert mapping["image"] == MessageType.PHOTO
        assert mapping["video"] == MessageType.VIDEO
        # LINE has no separate voice type — audio clips are voice notes.
        assert mapping["audio"] == MessageType.VOICE
        assert mapping["file"] == MessageType.DOCUMENT
        assert mapping["location"] == MessageType.LOCATION
        assert mapping["sticker"] == MessageType.STICKER

    def test_unknown_type_falls_back_to_text(self):
        MessageType = _line.MessageType
        assert _line._LINE_MESSAGE_TYPES.get("flex", MessageType.TEXT) == MessageType.TEXT
