from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from typing import cast
from uuid import UUID

if TYPE_CHECKING:
    from ..models.admin_assignment_scope import AdminAssignmentScope
    from ..models.admin_subject import AdminSubject


T = TypeVar("T", bound="AdminRoleAssignment")


@_attrs_define
class AdminRoleAssignment:
    """
    Attributes:
        id (UUID):
        realm_id (UUID):
        subject (AdminSubject): A user or a group, as a group member or a role-assignment subject.
        role_id (UUID):
        scope (AdminAssignmentScope):
        assigned_at (int): Microseconds since the Unix epoch.
        assigned_by (None | UUID):
    """

    id: UUID
    realm_id: UUID
    subject: AdminSubject
    role_id: UUID
    scope: AdminAssignmentScope
    assigned_at: int
    assigned_by: None | UUID
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.admin_assignment_scope import AdminAssignmentScope  # noqa: PLC0415
        from ..models.admin_subject import AdminSubject  # noqa: PLC0415

        id = str(self.id)

        realm_id = str(self.realm_id)

        subject = self.subject.to_dict()

        role_id = str(self.role_id)

        scope = self.scope.to_dict()

        assigned_at = self.assigned_at

        assigned_by: None | str
        if isinstance(self.assigned_by, UUID):
            assigned_by = str(self.assigned_by)
        else:
            assigned_by = self.assigned_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "realm_id": realm_id,
                "subject": subject,
                "role_id": role_id,
                "scope": scope,
                "assigned_at": assigned_at,
                "assigned_by": assigned_by,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.admin_assignment_scope import AdminAssignmentScope  # noqa: PLC0415
        from ..models.admin_subject import AdminSubject  # noqa: PLC0415

        d = dict(src_dict)
        id = UUID(d.pop("id"))

        realm_id = UUID(d.pop("realm_id"))

        subject = AdminSubject.from_dict(d.pop("subject"))

        role_id = UUID(d.pop("role_id"))

        scope = AdminAssignmentScope.from_dict(d.pop("scope"))

        assigned_at = d.pop("assigned_at")

        def _parse_assigned_by(data: object) -> None | UUID:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                assigned_by_type_0 = UUID(data)

                return assigned_by_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | UUID, data)

        assigned_by = _parse_assigned_by(d.pop("assigned_by"))

        admin_role_assignment = cls(
            id=id,
            realm_id=realm_id,
            subject=subject,
            role_id=role_id,
            scope=scope,
            assigned_at=assigned_at,
            assigned_by=assigned_by,
        )

        admin_role_assignment.additional_properties = d
        return admin_role_assignment

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
