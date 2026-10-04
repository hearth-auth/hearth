from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.admin_role_scope_kind import AdminRoleScopeKind
from ..models.admin_role_status import AdminRoleStatus
from typing import cast
from uuid import UUID


T = TypeVar("T", bound="AdminRole")


@_attrs_define
class AdminRole:
    """
    Attributes:
        id (UUID):
        realm_id (UUID):
        name (str):
        description (None | str):
        permissions (list[str]):
        parent_roles (list[UUID]):
        scope_kind (AdminRoleScopeKind):
        status (AdminRoleStatus):
        yaml_managed (bool): Declared in hearth.yaml; the admin API cannot change it.
        created_at (int): Microseconds since the Unix epoch.
        updated_at (int): Microseconds since the Unix epoch.
    """

    id: UUID
    realm_id: UUID
    name: str
    description: None | str
    permissions: list[str]
    parent_roles: list[UUID]
    scope_kind: AdminRoleScopeKind
    status: AdminRoleStatus
    yaml_managed: bool
    created_at: int
    updated_at: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = str(self.id)

        realm_id = str(self.realm_id)

        name = self.name

        description: None | str
        description = self.description

        permissions = self.permissions

        parent_roles = []
        for parent_roles_item_data in self.parent_roles:
            parent_roles_item = str(parent_roles_item_data)
            parent_roles.append(parent_roles_item)

        scope_kind = self.scope_kind.value

        status = self.status.value

        yaml_managed = self.yaml_managed

        created_at = self.created_at

        updated_at = self.updated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "realm_id": realm_id,
                "name": name,
                "description": description,
                "permissions": permissions,
                "parent_roles": parent_roles,
                "scope_kind": scope_kind,
                "status": status,
                "yaml_managed": yaml_managed,
                "created_at": created_at,
                "updated_at": updated_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = UUID(d.pop("id"))

        realm_id = UUID(d.pop("realm_id"))

        name = d.pop("name")

        def _parse_description(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        description = _parse_description(d.pop("description"))

        permissions = cast(list[str], d.pop("permissions"))

        parent_roles = []
        _parent_roles = d.pop("parent_roles")
        for parent_roles_item_data in _parent_roles:
            parent_roles_item = UUID(parent_roles_item_data)

            parent_roles.append(parent_roles_item)

        scope_kind = AdminRoleScopeKind(d.pop("scope_kind"))

        status = AdminRoleStatus(d.pop("status"))

        yaml_managed = d.pop("yaml_managed")

        created_at = d.pop("created_at")

        updated_at = d.pop("updated_at")

        admin_role = cls(
            id=id,
            realm_id=realm_id,
            name=name,
            description=description,
            permissions=permissions,
            parent_roles=parent_roles,
            scope_kind=scope_kind,
            status=status,
            yaml_managed=yaml_managed,
            created_at=created_at,
            updated_at=updated_at,
        )

        admin_role.additional_properties = d
        return admin_role

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
