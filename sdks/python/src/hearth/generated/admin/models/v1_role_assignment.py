from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.v1_group_member_type import V1GroupMemberType
from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
    from ..models.v1_scope import V1Scope


T = TypeVar("T", bound="V1RoleAssignment")


@_attrs_define
class V1RoleAssignment:
    """
    Attributes:
        id (str | Unset):
        realm_id (str | Unset):
        subject_id (str | Unset):
        subject_type (V1GroupMemberType | Unset):
        role_id (str | Unset):
        scope (V1Scope | Unset):
        assigned_at_micros (str | Unset):
        assigned_by_user_id (str | Unset):
    """

    id: str | Unset = UNSET
    realm_id: str | Unset = UNSET
    subject_id: str | Unset = UNSET
    subject_type: V1GroupMemberType | Unset = UNSET
    role_id: str | Unset = UNSET
    scope: V1Scope | Unset = UNSET
    assigned_at_micros: str | Unset = UNSET
    assigned_by_user_id: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.v1_scope import V1Scope  # noqa: PLC0415

        id = self.id

        realm_id = self.realm_id

        subject_id = self.subject_id

        subject_type: str | Unset = UNSET
        if not isinstance(self.subject_type, Unset):
            subject_type = self.subject_type.value

        role_id = self.role_id

        scope: dict[str, Any] | Unset = UNSET
        if not isinstance(self.scope, Unset):
            scope = self.scope.to_dict()

        assigned_at_micros = self.assigned_at_micros

        assigned_by_user_id = self.assigned_by_user_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if realm_id is not UNSET:
            field_dict["realmId"] = realm_id
        if subject_id is not UNSET:
            field_dict["subjectId"] = subject_id
        if subject_type is not UNSET:
            field_dict["subjectType"] = subject_type
        if role_id is not UNSET:
            field_dict["roleId"] = role_id
        if scope is not UNSET:
            field_dict["scope"] = scope
        if assigned_at_micros is not UNSET:
            field_dict["assignedAtMicros"] = assigned_at_micros
        if assigned_by_user_id is not UNSET:
            field_dict["assignedByUserId"] = assigned_by_user_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.v1_scope import V1Scope  # noqa: PLC0415

        d = dict(src_dict)
        id = d.pop("id", UNSET)

        realm_id = d.pop("realmId", UNSET)

        subject_id = d.pop("subjectId", UNSET)

        _subject_type = d.pop("subjectType", UNSET)
        subject_type: V1GroupMemberType | Unset
        if isinstance(_subject_type, Unset):
            subject_type = UNSET
        else:
            subject_type = V1GroupMemberType(_subject_type)

        role_id = d.pop("roleId", UNSET)

        _scope = d.pop("scope", UNSET)
        scope: V1Scope | Unset
        if isinstance(_scope, Unset):
            scope = UNSET
        else:
            scope = V1Scope.from_dict(_scope)

        assigned_at_micros = d.pop("assignedAtMicros", UNSET)

        assigned_by_user_id = d.pop("assignedByUserId", UNSET)

        v1_role_assignment = cls(
            id=id,
            realm_id=realm_id,
            subject_id=subject_id,
            subject_type=subject_type,
            role_id=role_id,
            scope=scope,
            assigned_at_micros=assigned_at_micros,
            assigned_by_user_id=assigned_by_user_id,
        )

        v1_role_assignment.additional_properties = d
        return v1_role_assignment

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
