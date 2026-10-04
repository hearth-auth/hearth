from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from typing import cast
from uuid import UUID

if TYPE_CHECKING:
    from ..models.admin_subject import AdminSubject


T = TypeVar("T", bound="AdminGroupMembership")


@_attrs_define
class AdminGroupMembership:
    """
    Attributes:
        group_id (UUID):
        member (AdminSubject): A user or a group, as a group member or a role-assignment subject.
        added_at (int): Microseconds since the Unix epoch.
        added_by (None | UUID):
    """

    group_id: UUID
    member: AdminSubject
    added_at: int
    added_by: None | UUID
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.admin_subject import AdminSubject  # noqa: PLC0415

        group_id = str(self.group_id)

        member = self.member.to_dict()

        added_at = self.added_at

        added_by: None | str
        if isinstance(self.added_by, UUID):
            added_by = str(self.added_by)
        else:
            added_by = self.added_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "group_id": group_id,
                "member": member,
                "added_at": added_at,
                "added_by": added_by,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.admin_subject import AdminSubject  # noqa: PLC0415

        d = dict(src_dict)
        group_id = UUID(d.pop("group_id"))

        member = AdminSubject.from_dict(d.pop("member"))

        added_at = d.pop("added_at")

        def _parse_added_by(data: object) -> None | UUID:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                added_by_type_0 = UUID(data)

                return added_by_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | UUID, data)

        added_by = _parse_added_by(d.pop("added_by"))

        admin_group_membership = cls(
            group_id=group_id,
            member=member,
            added_at=added_at,
            added_by=added_by,
        )

        admin_group_membership.additional_properties = d
        return admin_group_membership

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
