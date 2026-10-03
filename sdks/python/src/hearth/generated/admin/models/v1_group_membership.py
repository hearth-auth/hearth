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


T = TypeVar("T", bound="V1GroupMembership")


@_attrs_define
class V1GroupMembership:
    """
    Attributes:
        group_id (str | Unset):
        member (V1GroupMember | Unset):
        added_at_micros (str | Unset):
        added_by_user_id (str | Unset):
    """

    group_id: str | Unset = UNSET
    member: V1GroupMember | Unset = UNSET
    added_at_micros: str | Unset = UNSET
    added_by_user_id: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.v1_group_member import V1GroupMember  # noqa: PLC0415

        group_id = self.group_id

        member: dict[str, Any] | Unset = UNSET
        if not isinstance(self.member, Unset):
            member = self.member.to_dict()

        added_at_micros = self.added_at_micros

        added_by_user_id = self.added_by_user_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if group_id is not UNSET:
            field_dict["groupId"] = group_id
        if member is not UNSET:
            field_dict["member"] = member
        if added_at_micros is not UNSET:
            field_dict["addedAtMicros"] = added_at_micros
        if added_by_user_id is not UNSET:
            field_dict["addedByUserId"] = added_by_user_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.v1_group_member import V1GroupMember  # noqa: PLC0415

        d = dict(src_dict)
        group_id = d.pop("groupId", UNSET)

        _member = d.pop("member", UNSET)
        member: V1GroupMember | Unset
        if isinstance(_member, Unset):
            member = UNSET
        else:
            member = V1GroupMember.from_dict(_member)

        added_at_micros = d.pop("addedAtMicros", UNSET)

        added_by_user_id = d.pop("addedByUserId", UNSET)

        v1_group_membership = cls(
            group_id=group_id,
            member=member,
            added_at_micros=added_at_micros,
            added_by_user_id=added_by_user_id,
        )

        v1_group_membership.additional_properties = d
        return v1_group_membership

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
