from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
    from ..models.admin_import_user_entry_attributes import (
        AdminImportUserEntryAttributes,
    )


T = TypeVar("T", bound="AdminImportUserEntry")


@_attrs_define
class AdminImportUserEntry:
    """
    Attributes:
        email (str):
        display_name (str):
        first_name (str | Unset):
        last_name (str | Unset):
        status (str | Unset): `active` (the default), `disabled` or `pending_verification`. Another value fails the
            entry.
        attributes (AdminImportUserEntryAttributes | Unset):
        password_hash (str | Unset): A PHC password hash from another system: bcrypt (`$2a$`, `$2b$`, `$2y$`),
            `$argon2id$`, `$scrypt$` or `$pbkdf2-sha256$`. Sign-in verifies it, and the first successful sign-in replaces it
            with an Argon2id hash. A hash that is malformed, in another format, or with a work factor above the server's
            ceilings fails the entry. Without it, the user gets no password.
    """

    email: str
    display_name: str
    first_name: str | Unset = UNSET
    last_name: str | Unset = UNSET
    status: str | Unset = UNSET
    attributes: AdminImportUserEntryAttributes | Unset = UNSET
    password_hash: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        from ..models.admin_import_user_entry_attributes import (
            AdminImportUserEntryAttributes,
        )  # noqa: PLC0415

        email = self.email

        display_name = self.display_name

        first_name = self.first_name

        last_name = self.last_name

        status = self.status

        attributes: dict[str, Any] | Unset = UNSET
        if not isinstance(self.attributes, Unset):
            attributes = self.attributes.to_dict()

        password_hash = self.password_hash

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "email": email,
                "display_name": display_name,
            }
        )
        if first_name is not UNSET:
            field_dict["first_name"] = first_name
        if last_name is not UNSET:
            field_dict["last_name"] = last_name
        if status is not UNSET:
            field_dict["status"] = status
        if attributes is not UNSET:
            field_dict["attributes"] = attributes
        if password_hash is not UNSET:
            field_dict["password_hash"] = password_hash

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.admin_import_user_entry_attributes import (
            AdminImportUserEntryAttributes,
        )  # noqa: PLC0415

        d = dict(src_dict)
        email = d.pop("email")

        display_name = d.pop("display_name")

        first_name = d.pop("first_name", UNSET)

        last_name = d.pop("last_name", UNSET)

        status = d.pop("status", UNSET)

        _attributes = d.pop("attributes", UNSET)
        attributes: AdminImportUserEntryAttributes | Unset
        if isinstance(_attributes, Unset):
            attributes = UNSET
        else:
            attributes = AdminImportUserEntryAttributes.from_dict(_attributes)

        password_hash = d.pop("password_hash", UNSET)

        admin_import_user_entry = cls(
            email=email,
            display_name=display_name,
            first_name=first_name,
            last_name=last_name,
            status=status,
            attributes=attributes,
            password_hash=password_hash,
        )

        return admin_import_user_entry
