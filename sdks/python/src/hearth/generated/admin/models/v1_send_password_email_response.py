from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.v1_password_email_kind import V1PasswordEmailKind
from ..types import UNSET, Unset


T = TypeVar("T", bound="V1SendPasswordEmailResponse")


@_attrs_define
class V1SendPasswordEmailResponse:
    """The password email Hearth sent.

    Attributes:
        kind (V1PasswordEmailKind | Unset): Which password email Hearth sent.

             - PASSWORD_EMAIL_KIND_SETUP: The user has no password: the welcome email with a set-password link.
             - PASSWORD_EMAIL_KIND_RESET: The user has a password: the password-reset email.
    """

    kind: V1PasswordEmailKind | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        kind: str | Unset = UNSET
        if not isinstance(self.kind, Unset):
            kind = self.kind.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if kind is not UNSET:
            field_dict["kind"] = kind

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        _kind = d.pop("kind", UNSET)
        kind: V1PasswordEmailKind | Unset
        if isinstance(_kind, Unset):
            kind = UNSET
        else:
            kind = V1PasswordEmailKind(_kind)

        v1_send_password_email_response = cls(
            kind=kind,
        )

        v1_send_password_email_response.additional_properties = d
        return v1_send_password_email_response

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
