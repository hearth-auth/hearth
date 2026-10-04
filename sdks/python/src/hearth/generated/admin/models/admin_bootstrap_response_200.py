from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset


T = TypeVar("T", bound="AdminBootstrapResponse200")


@_attrs_define
class AdminBootstrapResponse200:
    """
    Attributes:
        realm_id (str | Unset): UUID of the created dev realm.
        user_id (str | Unset): UUID of the admin user in the dev realm.
        access_token (str | Unset): Long-lived Bearer token for the dev-realm admin. Scoped to the dev
            realm only — cannot manage other realms. Use for REST API calls in
            dev/test scripts and as the `Authorization` header on re-bootstrap.
        refresh_token (str | Unset): Refresh token for the dev-realm admin session.
        admin_password (str | Unset): Randomly generated admin password. Non-empty **only** on the **first**
            bootstrap call. Empty on all subsequent re-bootstrap calls — store this
            value securely; it is never returned again. Use for browser login at
            `/ui/admin/login`.
        quickstart (str | Unset): Ready-to-copy shell commands with the actual realm ID and token
            interpolated for convenience. Only populated in --dev mode.
        system_access_token (str | Unset): Bearer token for the **system-realm** admin (`admin@hearth.test` in the
            nil-UUID system realm). Unlike `access_token`, this token can manage
            **any** realm cross-realm (e.g. rotate another realm's signing key) — the
            BOLA guard only permits cross-realm operations for a nil-UUID system-realm
            token. Use with `X-Realm-ID: <system_realm_id>` for cross-realm admin API
            calls. Populated on every bootstrap and re-bootstrap (HEA-2087).
        system_realm_id (str | Unset): The reserved system realm ID (the nil UUID,
            `00000000-0000-0000-0000-000000000000`). Send as the `X-Realm-ID` header
            alongside `system_access_token` for cross-realm admin API calls.
    """

    realm_id: str | Unset = UNSET
    user_id: str | Unset = UNSET
    access_token: str | Unset = UNSET
    refresh_token: str | Unset = UNSET
    admin_password: str | Unset = UNSET
    quickstart: str | Unset = UNSET
    system_access_token: str | Unset = UNSET
    system_realm_id: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        realm_id = self.realm_id

        user_id = self.user_id

        access_token = self.access_token

        refresh_token = self.refresh_token

        admin_password = self.admin_password

        quickstart = self.quickstart

        system_access_token = self.system_access_token

        system_realm_id = self.system_realm_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if realm_id is not UNSET:
            field_dict["realm_id"] = realm_id
        if user_id is not UNSET:
            field_dict["user_id"] = user_id
        if access_token is not UNSET:
            field_dict["access_token"] = access_token
        if refresh_token is not UNSET:
            field_dict["refresh_token"] = refresh_token
        if admin_password is not UNSET:
            field_dict["admin_password"] = admin_password
        if quickstart is not UNSET:
            field_dict["quickstart"] = quickstart
        if system_access_token is not UNSET:
            field_dict["system_access_token"] = system_access_token
        if system_realm_id is not UNSET:
            field_dict["system_realm_id"] = system_realm_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        realm_id = d.pop("realm_id", UNSET)

        user_id = d.pop("user_id", UNSET)

        access_token = d.pop("access_token", UNSET)

        refresh_token = d.pop("refresh_token", UNSET)

        admin_password = d.pop("admin_password", UNSET)

        quickstart = d.pop("quickstart", UNSET)

        system_access_token = d.pop("system_access_token", UNSET)

        system_realm_id = d.pop("system_realm_id", UNSET)

        admin_bootstrap_response_200 = cls(
            realm_id=realm_id,
            user_id=user_id,
            access_token=access_token,
            refresh_token=refresh_token,
            admin_password=admin_password,
            quickstart=quickstart,
            system_access_token=system_access_token,
            system_realm_id=system_realm_id,
        )

        admin_bootstrap_response_200.additional_properties = d
        return admin_bootstrap_response_200

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
