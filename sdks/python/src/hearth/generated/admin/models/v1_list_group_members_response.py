from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
    from ..models.v1_group_member import V1GroupMember


T = TypeVar("T", bound="V1ListGroupMembersResponse")


@_attrs_define
class V1ListGroupMembersResponse:
    """
    Attributes:
        members (list[V1GroupMember] | Unset):
        next_cursor (str | Unset):
    """

    members: list[V1GroupMember] | Unset = UNSET
    next_cursor: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.v1_group_member import V1GroupMember  # noqa: PLC0415

        members: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.members, Unset):
            members = []
            for members_item_data in self.members:
                members_item = members_item_data.to_dict()
                members.append(members_item)

        next_cursor = self.next_cursor

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if members is not UNSET:
            field_dict["members"] = members
        if next_cursor is not UNSET:
            field_dict["nextCursor"] = next_cursor

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.v1_group_member import V1GroupMember  # noqa: PLC0415

        d = dict(src_dict)
        _members = d.pop("members", UNSET)
        members: list[V1GroupMember] | Unset = UNSET
        if _members is not UNSET:
            members = []
            for members_item_data in _members:
                members_item = V1GroupMember.from_dict(members_item_data)

                members.append(members_item)

        next_cursor = d.pop("nextCursor", UNSET)

        v1_list_group_members_response = cls(
            members=members,
            next_cursor=next_cursor,
        )

        v1_list_group_members_response.additional_properties = d
        return v1_list_group_members_response

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
