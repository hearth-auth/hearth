from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
    from ..models.v1_org_scope import V1OrgScope
    from ..models.v1_realm_scope import V1RealmScope


T = TypeVar("T", bound="V1Scope")


@_attrs_define
class V1Scope:
    """
    Attributes:
        realm (V1RealmScope | Unset):
        org (V1OrgScope | Unset):
    """

    realm: V1RealmScope | Unset = UNSET
    org: V1OrgScope | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.v1_org_scope import V1OrgScope  # noqa: PLC0415
        from ..models.v1_realm_scope import V1RealmScope  # noqa: PLC0415

        realm: dict[str, Any] | Unset = UNSET
        if not isinstance(self.realm, Unset):
            realm = self.realm.to_dict()

        org: dict[str, Any] | Unset = UNSET
        if not isinstance(self.org, Unset):
            org = self.org.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if realm is not UNSET:
            field_dict["realm"] = realm
        if org is not UNSET:
            field_dict["org"] = org

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.v1_org_scope import V1OrgScope  # noqa: PLC0415
        from ..models.v1_realm_scope import V1RealmScope  # noqa: PLC0415

        d = dict(src_dict)
        _realm = d.pop("realm", UNSET)
        realm: V1RealmScope | Unset
        if isinstance(_realm, Unset):
            realm = UNSET
        else:
            realm = V1RealmScope.from_dict(_realm)

        _org = d.pop("org", UNSET)
        org: V1OrgScope | Unset
        if isinstance(_org, Unset):
            org = UNSET
        else:
            org = V1OrgScope.from_dict(_org)

        v1_scope = cls(
            realm=realm,
            org=org,
        )

        v1_scope.additional_properties = d
        return v1_scope

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
