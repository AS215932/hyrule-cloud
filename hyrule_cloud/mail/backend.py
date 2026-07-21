"""Narrow Stalwart control/data-plane client used by Agent Mail.

The public product never exposes Stalwart credentials or SMTP/IMAP. Hyrule
uses the management JMAP extension for provisioning and ordinary JMAP for
mailbox access and submission.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import quote

import httpx

from hyrule_cloud.config import MailConfig


class MailBackendError(RuntimeError):
    pass


class MailAttachmentTooLargeError(MailBackendError):
    pass


@dataclass(frozen=True, slots=True)
class ProvisionedAccount:
    account_id: str
    domain_id: str
    dns_records: list[dict[str, Any]]


class StalwartClient:
    def __init__(self, config: MailConfig) -> None:
        self.config = config
        self.base_url = config.backend_url.rstrip("/")
        self._http = httpx.AsyncClient(
            timeout=config.backend_timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": "hyrule-cloud-agent-mail/1"},
        )

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.config.backend_token)

    async def close(self) -> None:
        await self._http.aclose()

    async def ready(self) -> bool:
        if not self.configured:
            return False
        try:
            payload = await self._manage(
                [["x:Domain/query", {"limit": 1}, "readiness-domain-query"]]
            )
            self._method_data(payload, "readiness-domain-query")
            return True
        except MailBackendError:
            return False

    async def _manage(self, method_calls: list[list[Any]]) -> dict[str, Any]:
        if not self.configured:
            raise MailBackendError("Stalwart management API is not configured")
        try:
            response = await self._http.post(
                f"{self.base_url}/api",
                headers={"Authorization": f"Bearer {self.config.backend_token}"},
                json={
                    "using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
                    "methodCalls": method_calls,
                },
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise MailBackendError("Stalwart management request failed") from exc
        if not isinstance(payload, dict):
            raise MailBackendError("Stalwart management response was not an object")
        responses = payload.get("methodResponses")
        if not isinstance(responses, list):
            raise MailBackendError("Stalwart management response omitted method responses")
        for item in responses:
            if (
                not isinstance(item, list)
                or len(item) != 3
                or not isinstance(item[0], str)
                or not isinstance(item[1], dict)
                or not isinstance(item[2], str)
            ):
                raise MailBackendError("Stalwart management method response was malformed")
            if item[0].endswith("/error"):
                raise MailBackendError(str(item[1].get("description") or item[1].get("type")))
        return cast(dict[str, Any], payload)

    @staticmethod
    def _method_data(payload: dict[str, Any], call_id: str) -> dict[str, Any]:
        responses = payload.get("methodResponses")
        if not isinstance(responses, list):
            raise MailBackendError("Stalwart response omitted method responses")
        for item in responses:
            if not isinstance(item, list) or len(item) != 3:
                raise MailBackendError("Stalwart method response was malformed")
            _name, data, response_call_id = item
            if response_call_id == call_id:
                if not isinstance(data, dict):
                    raise MailBackendError(f"Stalwart response for {call_id} was not an object")
                return cast(dict[str, Any], data)
        raise MailBackendError(f"Stalwart response omitted call {call_id}")

    def _certificate_management(self) -> dict[str, Any]:
        provider_id = self.config.acme_provider_id.strip()
        if not provider_id:
            return {"@type": "Manual"}
        return {
            "@type": "Automatic",
            "acmeProviderId": provider_id,
            "subjectAlternativeNames": [],
        }

    @staticmethod
    def _local_part(address: str) -> str:
        local_part, separator, domain = address.rpartition("@")
        if not separator or not local_part or not domain:
            raise MailBackendError("Mailbox address is invalid")
        return local_part

    async def ensure_domain(self, domain: str) -> tuple[str, list[dict[str, Any]]]:
        queried = await self._manage(
            [["x:Domain/query", {"filter": {"name": domain}, "limit": 1}, "query-domain"]]
        )
        ids = self._method_data(queried, "query-domain").get("ids", [])
        if ids:
            domain_id = str(ids[0])
        else:
            created = await self._manage(
                [
                    [
                        "x:Domain/set",
                        {
                            "create": {
                                "domain": {
                                    "name": domain,
                                    "aliases": [],
                                    "certificateManagement": self._certificate_management(),
                                    "dkimManagement": {"@type": "Automatic"},
                                    # Hyrule reconciles the returned zone centrally.
                                    "dnsManagement": {"@type": "Manual"},
                                    "subAddressing": {"@type": "Disabled"},
                                }
                            }
                        },
                        "create-domain",
                    ]
                ]
            )
            result = self._method_data(created, "create-domain")
            domain_id = str((result.get("created") or {}).get("domain", {}).get("id") or "")
            if not domain_id:
                raise MailBackendError("Stalwart did not return a domain id")
        loaded = await self._manage(
            [["x:Domain/get", {"ids": [domain_id], "properties": ["dnsZoneFile"]}, "get-domain"]]
        )
        data = self._method_data(loaded, "get-domain")
        items = data.get("list") or []
        zone = items[0].get("dnsZoneFile", "") if items else ""
        return domain_id, _zone_file_records(zone)

    async def create_account(
        self,
        *,
        address: str,
        domain_id: str,
        password: str,
        quota_bytes: int,
    ) -> str:
        local_part = self._local_part(address)
        result = await self._manage(
            [
                [
                    "x:Account/set",
                    {
                        "create": {
                            "account": {
                                "@type": "User",
                                "name": local_part,
                                "domainId": domain_id,
                                "credentials": [{"@type": "Password", "secret": password}],
                                "memberGroupIds": [],
                                "roles": {"@type": "User"},
                                "permissions": {"@type": "Inherit"},
                                "quotas": {"maxDiskQuota": quota_bytes},
                                "aliases": [],
                                "encryptionAtRest": {"@type": "Disabled"},
                            }
                        }
                    },
                    "create-account",
                ]
            ]
        )
        account_id = str(
            (self._method_data(result, "create-account").get("created") or {})
            .get("account", {})
            .get("id")
            or ""
        )
        if not account_id:
            raise MailBackendError("Stalwart did not return an account id")
        return account_id

    async def ensure_account(
        self,
        *,
        address: str,
        domain_id: str,
        password: str,
        quota_bytes: int,
    ) -> str:
        local_part = self._local_part(address)
        queried = await self._manage(
            [
                [
                    "x:Account/query",
                    {
                        "filter": {"name": local_part, "domainId": domain_id},
                        "limit": 1,
                    },
                    "query-account",
                ]
            ]
        )
        ids = self._method_data(queried, "query-account").get("ids", [])
        if ids:
            return str(ids[0])
        return await self.create_account(
            address=address,
            domain_id=domain_id,
            password=password,
            quota_bytes=quota_bytes,
        )

    async def delete_account(self, account_id: str) -> None:
        await self._manage([["x:Account/set", {"destroy": [account_id]}, "delete-account"]])

    async def delete_message(self, *, address: str, password: str, message_id: str) -> None:
        session, _auth = await self._session(address, password)
        account_id = str(session.get("primaryAccounts", {}).get("urn:ietf:params:jmap:mail", ""))
        if not account_id:
            raise MailBackendError("Mailbox has no JMAP mail account")
        result = await self._jmap(
            address,
            password,
            [
                [
                    "Email/set",
                    {"accountId": account_id, "destroy": [message_id]},
                    "delete-email",
                ]
            ],
            ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        )
        response = self._method_data(result["response"], "delete-email")
        failure = (response.get("notDestroyed") or {}).get(message_id)
        if failure and failure.get("type") != "notFound":
            raise MailBackendError(
                str(failure.get("description") or failure.get("type") or "Message deletion failed")
            )

    async def delete_messages_before(
        self,
        *,
        address: str,
        password: str,
        cutoff: datetime,
    ) -> int:
        """Permanently remove every message older than ``cutoff`` via JMAP.

        This authoritative mailbox scan is intentionally independent of the
        webhook-backed local index: a delayed or lost ingest event must never
        turn into indefinite message retention.
        """

        session, _auth = await self._session(address, password)
        account_id = str(session.get("primaryAccounts", {}).get("urn:ietf:params:jmap:mail", ""))
        if not account_id:
            raise MailBackendError("Mailbox has no JMAP mail account")
        cutoff_value = cutoff.astimezone(UTC).isoformat().replace("+00:00", "Z")
        deleted = 0
        for _page in range(100):
            queried = await self._jmap(
                address,
                password,
                [
                    [
                        "Email/query",
                        {
                            "accountId": account_id,
                            "filter": {"before": cutoff_value},
                            "sort": [{"property": "receivedAt", "isAscending": True}],
                            "position": 0,
                            "limit": 500,
                        },
                        "retention-query",
                    ]
                ],
                ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            )
            ids = [
                str(value)
                for value in self._method_data(queried["response"], "retention-query").get(
                    "ids", []
                )
                if value
            ]
            if not ids:
                return deleted
            destroyed = await self._jmap(
                address,
                password,
                [
                    [
                        "Email/set",
                        {"accountId": account_id, "destroy": ids},
                        "retention-delete",
                    ]
                ],
                ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            )
            result = self._method_data(destroyed["response"], "retention-delete")
            failures = result.get("notDestroyed") or {}
            fatal = next(
                (
                    value
                    for value in failures.values()
                    if isinstance(value, dict) and value.get("type") != "notFound"
                ),
                None,
            )
            if fatal is not None:
                raise MailBackendError(
                    str(
                        fatal.get("description")
                        or fatal.get("type")
                        or "Message retention deletion failed"
                    )
                )
            deleted += len(ids)
        raise MailBackendError("Mailbox retention sweep exceeded its safety page limit")

    async def _session(self, address: str, password: str) -> tuple[dict[str, Any], httpx.BasicAuth]:
        auth = httpx.BasicAuth(address, password)
        try:
            response = await self._http.get(f"{self.base_url}/.well-known/jmap", auth=auth)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise MailBackendError("Stalwart JMAP session discovery failed") from exc
        if not isinstance(payload, dict):
            raise MailBackendError("Stalwart JMAP session was not an object")
        return cast(dict[str, Any], payload), auth

    async def _jmap(
        self,
        address: str,
        password: str,
        method_calls: list[list[Any]],
        using: list[str],
    ) -> dict[str, Any]:
        session, auth = await self._session(address, password)
        try:
            response = await self._http.post(
                str(session["apiUrl"]),
                auth=auth,
                json={"using": using, "methodCalls": method_calls},
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            raise MailBackendError("Stalwart JMAP request failed") from exc
        if not isinstance(payload, dict):
            raise MailBackendError("Stalwart JMAP response was not an object")
        responses = payload.get("methodResponses")
        if not isinstance(responses, list):
            raise MailBackendError("Stalwart JMAP response omitted method responses")
        for item in responses:
            if (
                not isinstance(item, list)
                or len(item) != 3
                or not isinstance(item[0], str)
                or not isinstance(item[1], dict)
                or not isinstance(item[2], str)
            ):
                raise MailBackendError("Stalwart JMAP method response was malformed")
            if item[0].endswith("/error"):
                raise MailBackendError(str(item[1].get("description") or item[1].get("type")))
        return {"session": session, "response": payload}

    async def send_message(
        self,
        *,
        address: str,
        password: str,
        recipient: str,
        subject: str,
        text: str,
        html: str | None,
        in_reply_to: str | None,
        send_id: str,
    ) -> str:
        session, _auth = await self._session(address, password)
        account_id = str(session.get("primaryAccounts", {}).get("urn:ietf:params:jmap:mail", ""))
        if not account_id:
            raise MailBackendError("Mailbox has no JMAP mail account")
        calls: list[list[Any]] = [
            [
                "Mailbox/query",
                {"accountId": account_id, "filter": {"role": "drafts"}, "limit": 1},
                "drafts",
            ],
            [
                "Identity/get",
                {"accountId": account_id},
                "identities",
            ],
        ]
        bootstrap = await self._jmap(
            address,
            password,
            calls,
            [
                "urn:ietf:params:jmap:core",
                "urn:ietf:params:jmap:mail",
                "urn:ietf:params:jmap:submission",
            ],
        )
        payload = bootstrap["response"]
        drafts = self._method_data(payload, "drafts").get("ids", [])
        identities = self._method_data(payload, "identities").get("list", [])
        if not drafts or not identities:
            raise MailBackendError("Mailbox is missing a drafts folder or sending identity")
        body_values: dict[str, Any] = {"text": {"value": text, "isTruncated": False}}
        email: dict[str, Any] = {
            "mailboxIds": {str(drafts[0]): True},
            "from": [{"email": address}],
            "to": [{"email": recipient}],
            "subject": subject,
            "bodyValues": body_values,
            "textBody": [{"partId": "text", "type": "text/plain"}],
            "header:X-Hyrule-Send-ID:asText": send_id,
        }
        if html:
            body_values["html"] = {"value": html, "isTruncated": False}
            email["htmlBody"] = [{"partId": "html", "type": "text/html"}]
        if in_reply_to:
            email["inReplyTo"] = [in_reply_to]
        submitted = await self._jmap(
            address,
            password,
            [
                ["Email/set", {"accountId": account_id, "create": {"draft": email}}, "email"],
                [
                    "EmailSubmission/set",
                    {
                        "accountId": account_id,
                        "create": {
                            "submission": {
                                "identityId": str(identities[0]["id"]),
                                "emailId": "#draft",
                            }
                        },
                        "onSuccessUpdateEmail": {"#submission": {"keywords/$draft": None}},
                    },
                    "submit",
                ],
            ],
            [
                "urn:ietf:params:jmap:core",
                "urn:ietf:params:jmap:mail",
                "urn:ietf:params:jmap:submission",
            ],
        )
        created = self._method_data(submitted["response"], "email").get("created", {})
        message_id = str((created.get("draft") or {}).get("id") or "")
        if not message_id:
            raise MailBackendError("Stalwart did not accept the message draft")
        submission = self._method_data(submitted["response"], "submit")
        submitted_id = str(
            ((submission.get("created") or {}).get("submission") or {}).get("id") or ""
        )
        if not submitted_id:
            failure = (submission.get("notCreated") or {}).get("submission") or {}
            raise MailBackendError(
                str(
                    failure.get("description")
                    or failure.get("type")
                    or "Stalwart did not accept the message submission"
                )
            )
        return message_id

    async def find_message_by_send_id(
        self, *, address: str, password: str, send_id: str
    ) -> str | None:
        """Find a previously submitted message using its durable send intent id."""

        session, _auth = await self._session(address, password)
        account_id = str(session.get("primaryAccounts", {}).get("urn:ietf:params:jmap:mail", ""))
        if not account_id:
            raise MailBackendError("Mailbox has no JMAP mail account")
        result = await self._jmap(
            address,
            password,
            [
                [
                    "Email/query",
                    {
                        "accountId": account_id,
                        "filter": {"header": ["X-Hyrule-Send-ID", send_id]},
                        "limit": 1,
                    },
                    "send-intent-query",
                ]
            ],
            ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        )
        ids = self._method_data(result["response"], "send-intent-query").get("ids", [])
        return str(ids[0]) if ids else None

    async def get_message(self, *, address: str, password: str, message_id: str) -> dict[str, Any]:
        session, _auth = await self._session(address, password)
        account_id = str(session.get("primaryAccounts", {}).get("urn:ietf:params:jmap:mail", ""))
        result = await self._jmap(
            address,
            password,
            [
                [
                    "Email/get",
                    {
                        "accountId": account_id,
                        "ids": [message_id],
                        "properties": [
                            "id",
                            "blobId",
                            "threadId",
                            "mailboxIds",
                            "keywords",
                            "receivedAt",
                            "from",
                            "to",
                            "subject",
                            "textBody",
                            "htmlBody",
                            "bodyValues",
                            "attachments",
                        ],
                        "fetchTextBodyValues": True,
                        "fetchHTMLBodyValues": True,
                        "maxBodyValueBytes": 1_000_000,
                    },
                    "get-email",
                ]
            ],
            ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        )
        items = self._method_data(result["response"], "get-email").get("list", [])
        if not items:
            raise MailBackendError("Message not found")
        return dict(items[0])

    async def download_blob(
        self,
        *,
        address: str,
        password: str,
        blob_id: str,
        name: str,
        media_type: str,
    ) -> tuple[bytes, str]:
        session, auth = await self._session(address, password)
        account_id = str(session.get("primaryAccounts", {}).get("urn:ietf:params:jmap:mail", ""))
        template = str(session.get("downloadUrl") or "")
        if not template or not account_id:
            raise MailBackendError("Mailbox does not advertise blob downloads")
        url = (
            template.replace("{accountId}", quote(account_id, safe=""))
            .replace("{blobId}", quote(blob_id, safe=""))
            .replace("{name}", quote(name, safe=""))
            .replace("{type}", quote(media_type, safe=""))
        )
        try:
            async with self._http.stream("GET", url, auth=auth) as response:
                response.raise_for_status()
                content_length = response.headers.get("content-length")
                if content_length is not None:
                    try:
                        declared_length = int(content_length)
                    except ValueError as exc:
                        raise MailBackendError(
                            "Attachment returned an invalid content length"
                        ) from exc
                    if declared_length > self.config.max_attachment_bytes:
                        raise MailAttachmentTooLargeError("Attachment exceeds the download limit")
                chunks: list[bytes] = []
                received = 0
                async for chunk in response.aiter_bytes():
                    received += len(chunk)
                    if received > self.config.max_attachment_bytes:
                        raise MailAttachmentTooLargeError("Attachment exceeds the download limit")
                    chunks.append(chunk)
                content = b"".join(chunks)
                media_type_header = response.headers.get("content-type", "application/octet-stream")
        except httpx.HTTPError as exc:
            raise MailBackendError("Attachment download failed") from exc
        return content, media_type_header


def _zone_file_records(zone: str) -> list[dict[str, Any]]:
    """Parse Stalwart's simple generated zone file without accepting $INCLUDE.

    The central DNS service still validates the resulting RRsets before apply.
    This parser intentionally supports only the record types Agent Mail owns.
    """

    supported = {"A", "AAAA", "CNAME", "MX", "TXT"}
    records: list[dict[str, Any]] = []
    for raw in zone.splitlines():
        line = raw.strip()
        if not line or line.startswith((";", "$")):
            continue
        fields = line.split()
        type_index = next((i for i, value in enumerate(fields) if value.upper() in supported), None)
        if type_index is None or type_index == 0 or type_index + 1 >= len(fields):
            continue
        ttl = 3600
        for value in fields[1:type_index]:
            if value.isdigit():
                ttl = int(value)
                break
        records.append(
            {
                "name": fields[0],
                "type": fields[type_index].upper(),
                "ttl": ttl,
                "value": " ".join(fields[type_index + 1 :]),
            }
        )
    return records
