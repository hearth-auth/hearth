from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from typing import cast

if TYPE_CHECKING:
    from ..models.admin_import_user_entry import AdminImportUserEntry


T = TypeVar("T", bound="AdminImportUsersRequest")


@_attrs_define
class AdminImportUsersRequest:
    """
    Attributes:
        users (list[AdminImportUserEntry]):
    """

    users: list[AdminImportUserEntry]

    def to_dict(self) -> dict[str, Any]:
        from ..models.admin_import_user_entry import AdminImportUserEntry  # noqa: PLC0415

        users = []
        for users_item_data in self.users:
            users_item = users_item_data.to_dict()
            users.append(users_item)

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "users": users,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.admin_import_user_entry import AdminImportUserEntry  # noqa: PLC0415

        d = dict(src_dict)
        users = []
        _users = d.pop("users")
        for users_item_data in _users:
            users_item = AdminImportUserEntry.from_dict(users_item_data)

            users.append(users_item)

        admin_import_users_request = cls(
            users=users,
        )

        return admin_import_users_request
