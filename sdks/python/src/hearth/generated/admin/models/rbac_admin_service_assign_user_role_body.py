from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
    from ..models.v1_scope import V1Scope


T = TypeVar("T", bound="RbacAdminServiceAssignUserRoleBody")


@_attrs_define
class RbacAdminServiceAssignUserRoleBody:
    """
    Attributes:
        realm_id (str | Unset):
        role_id (str | Unset):
        scope (V1Scope | Unset):
    """

    realm_id: str | Unset = UNSET
    role_id: str | Unset = UNSET
    scope: V1Scope | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.v1_scope import V1Scope  # noqa: PLC0415

        realm_id = self.realm_id

        role_id = self.role_id

        scope: dict[str, Any] | Unset = UNSET
        if not isinstance(self.scope, Unset):
            scope = self.scope.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if realm_id is not UNSET:
            field_dict["realmId"] = realm_id
        if role_id is not UNSET:
            field_dict["roleId"] = role_id
        if scope is not UNSET:
            field_dict["scope"] = scope

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.v1_scope import V1Scope  # noqa: PLC0415

        d = dict(src_dict)
        realm_id = d.pop("realmId", UNSET)

        role_id = d.pop("roleId", UNSET)

        _scope = d.pop("scope", UNSET)
        scope: V1Scope | Unset
        if isinstance(_scope, Unset):
            scope = UNSET
        else:
            scope = V1Scope.from_dict(_scope)

        rbac_admin_service_assign_user_role_body = cls(
            realm_id=realm_id,
            role_id=role_id,
            scope=scope,
        )

        rbac_admin_service_assign_user_role_body.additional_properties = d
        return rbac_admin_service_assign_user_role_body

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
