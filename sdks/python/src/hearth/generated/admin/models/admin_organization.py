from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.admin_organization_status import AdminOrganizationStatus
from ..types import UNSET, Unset
from typing import cast
from uuid import UUID

if TYPE_CHECKING:
    from ..models.admin_organization_attributes import AdminOrganizationAttributes


T = TypeVar("T", bound="AdminOrganization")


@_attrs_define
class AdminOrganization:
    """
    Attributes:
        id (UUID):
        slug (str):
        display_name (str):
        status (AdminOrganizationStatus):
        mfa_required (bool): Members need MFA even where the realm does not require it.
        attributes (AdminOrganizationAttributes):
        created_at (int): Microseconds since the Unix epoch.
        updated_at (int): Microseconds since the Unix epoch.
        member_limit (int | None | Unset):
    """

    id: UUID
    slug: str
    display_name: str
    status: AdminOrganizationStatus
    mfa_required: bool
    attributes: AdminOrganizationAttributes
    created_at: int
    updated_at: int
    member_limit: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.admin_organization_attributes import AdminOrganizationAttributes  # noqa: PLC0415

        id = str(self.id)

        slug = self.slug

        display_name = self.display_name

        status = self.status.value

        mfa_required = self.mfa_required

        attributes = self.attributes.to_dict()

        created_at = self.created_at

        updated_at = self.updated_at

        member_limit: int | None | Unset
        if isinstance(self.member_limit, Unset):
            member_limit = UNSET
        else:
            member_limit = self.member_limit

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "slug": slug,
                "display_name": display_name,
                "status": status,
                "mfa_required": mfa_required,
                "attributes": attributes,
                "created_at": created_at,
                "updated_at": updated_at,
            }
        )
        if member_limit is not UNSET:
            field_dict["member_limit"] = member_limit

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.admin_organization_attributes import AdminOrganizationAttributes  # noqa: PLC0415

        d = dict(src_dict)
        id = UUID(d.pop("id"))

        slug = d.pop("slug")

        display_name = d.pop("display_name")

        status = AdminOrganizationStatus(d.pop("status"))

        mfa_required = d.pop("mfa_required")

        attributes = AdminOrganizationAttributes.from_dict(d.pop("attributes"))

        created_at = d.pop("created_at")

        updated_at = d.pop("updated_at")

        def _parse_member_limit(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        member_limit = _parse_member_limit(d.pop("member_limit", UNSET))

        admin_organization = cls(
            id=id,
            slug=slug,
            display_name=display_name,
            status=status,
            mfa_required=mfa_required,
            attributes=attributes,
            created_at=created_at,
            updated_at=updated_at,
            member_limit=member_limit,
        )

        admin_organization.additional_properties = d
        return admin_organization

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
