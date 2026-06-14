"""Backend adapter boundary for the future Agent Mail product.

The public /v1/mail API is stable; concrete mail infrastructure (Stalwart,
Postfix/Dovecot/Rspamd, or another backend) implements this protocol later.
"""

from __future__ import annotations

from typing import Protocol

from hyrule_cloud.models import (
    MailAccountCreateRequest,
    MailAccountResponse,
    MailMessageResponse,
    MailSendRequest,
)


class MailBackendUnavailableError(RuntimeError):
    pass


class MailBackend(Protocol):
    async def create_account(self, request: MailAccountCreateRequest) -> MailAccountResponse: ...

    async def delete_account(self, mailbox_id: str) -> None: ...

    async def send_message(self, request: MailSendRequest) -> MailMessageResponse: ...


class NullMailBackend:
    async def create_account(self, request: MailAccountCreateRequest) -> MailAccountResponse:
        raise MailBackendUnavailableError("Agent Mail backend is not enabled yet")

    async def delete_account(self, mailbox_id: str) -> None:
        raise MailBackendUnavailableError("Agent Mail backend is not enabled yet")

    async def send_message(self, request: MailSendRequest) -> MailMessageResponse:
        raise MailBackendUnavailableError("Agent Mail backend is not enabled yet")
