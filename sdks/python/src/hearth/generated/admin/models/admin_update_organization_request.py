from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.admin_update_organization_request_status import (
    AdminUpdateOrganizationRequestStatus,
)
from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
    from ..models.admin_update_organization_request_attributes import (
        AdminUpdateOrganizationRequestAttributes,
    )


T = TypeVar("T", bound="AdminUpdateOrganizationRequest")


@_attrs_define
class AdminUpdateOrganizationRequest:
    """Absent fields are unchanged. `slug` is immutable and is refused with 400.

    Attributes:
        display_name (str | Unset):
        status (AdminUpdateOrganizationRequestStatus | Unset):
        member_limit (int | None | Unset):
        mfa_required (bool | Unset):
        attributes (AdminUpdateOrganizationRequestAttributes | Unset): Replaces the whole attribute map.
    """

    display_name: str | Unset = UNSET
    status: AdminUpdateOrganizationRequestStatus | Unset = UNSET
    member_limit: int | None | Unset = UNSET
    mfa_required: bool | Unset = UNSET
    attributes: AdminUpdateOrganizationRequestAttributes | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.admin_update_organization_request_attributes import (
            AdminUpdateOrganizationRequestAttributes,
        )  # noqa: PLC0415

        display_name = self.display_name

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

        member_limit: int | None | Unset
        if isinstance(self.member_limit, Unset):
            member_limit = UNSET
        else:
            member_limit = self.member_limit

        mfa_required = self.mfa_required

        attributes: dict[str, Any] | Unset = UNSET
        if not isinstance(self.attributes, Unset):
            attributes = self.attributes.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if display_name is not UNSET:
            field_dict["display_name"] = display_name
        if status is not UNSET:
            field_dict["status"] = status
        if member_limit is not UNSET:
            field_dict["member_limit"] = member_limit
        if mfa_required is not UNSET:
            field_dict["mfa_required"] = mfa_required
        if attributes is not UNSET:
            field_dict["attributes"] = attributes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.admin_update_organization_request_attributes import (
            AdminUpdateOrganizationRequestAttributes,
        )  # noqa: PLC0415

        d = dict(src_dict)
        display_name = d.pop("display_name", UNSET)

        _status = d.pop("status", UNSET)
        status: AdminUpdateOrganizationRequestStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = AdminUpdateOrganizationRequestStatus(_status)

        def _parse_member_limit(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        member_limit = _parse_member_limit(d.pop("member_limit", UNSET))

        mfa_required = d.pop("mfa_required", UNSET)

        _attributes = d.pop("attributes", UNSET)
        attributes: AdminUpdateOrganizationRequestAttributes | Unset
        if isinstance(_attributes, Unset):
            attributes = UNSET
        else:
            attributes = AdminUpdateOrganizationRequestAttributes.from_dict(_attributes)

        admin_update_organization_request = cls(
            display_name=display_name,
            status=status,
            member_limit=member_limit,
            mfa_required=mfa_required,
            attributes=attributes,
        )

        admin_update_organization_request.additional_properties = d
        return admin_update_organization_request

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
