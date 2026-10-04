from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
    from ..models.admin_create_organization_request_attributes import (
        AdminCreateOrganizationRequestAttributes,
    )


T = TypeVar("T", bound="AdminCreateOrganizationRequest")


@_attrs_define
class AdminCreateOrganizationRequest:
    """
    Attributes:
        slug (str):
        display_name (str):
        member_limit (int | None | Unset):
        mfa_required (bool | Unset):  Default: False.
        attributes (AdminCreateOrganizationRequestAttributes | Unset):
    """

    slug: str
    display_name: str
    member_limit: int | None | Unset = UNSET
    mfa_required: bool | Unset = False
    attributes: AdminCreateOrganizationRequestAttributes | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.admin_create_organization_request_attributes import (
            AdminCreateOrganizationRequestAttributes,
        )  # noqa: PLC0415

        slug = self.slug

        display_name = self.display_name

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
        field_dict.update(
            {
                "slug": slug,
                "display_name": display_name,
            }
        )
        if member_limit is not UNSET:
            field_dict["member_limit"] = member_limit
        if mfa_required is not UNSET:
            field_dict["mfa_required"] = mfa_required
        if attributes is not UNSET:
            field_dict["attributes"] = attributes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.admin_create_organization_request_attributes import (
            AdminCreateOrganizationRequestAttributes,
        )  # noqa: PLC0415

        d = dict(src_dict)
        slug = d.pop("slug")

        display_name = d.pop("display_name")

        def _parse_member_limit(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        member_limit = _parse_member_limit(d.pop("member_limit", UNSET))

        mfa_required = d.pop("mfa_required", UNSET)

        _attributes = d.pop("attributes", UNSET)
        attributes: AdminCreateOrganizationRequestAttributes | Unset
        if isinstance(_attributes, Unset):
            attributes = UNSET
        else:
            attributes = AdminCreateOrganizationRequestAttributes.from_dict(_attributes)

        admin_create_organization_request = cls(
            slug=slug,
            display_name=display_name,
            member_limit=member_limit,
            mfa_required=mfa_required,
            attributes=attributes,
        )

        admin_create_organization_request.additional_properties = d
        return admin_create_organization_request

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
