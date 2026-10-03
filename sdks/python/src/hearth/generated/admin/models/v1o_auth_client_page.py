from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
    from ..models.v1o_auth_client import V1OAuthClient


T = TypeVar("T", bound="V1OAuthClientPage")


@_attrs_define
class V1OAuthClientPage:
    """A cursor-based page of OAuth clients.

    Attributes:
        items (list[V1OAuthClient] | Unset):
        next_cursor (str | Unset):
    """

    items: list[V1OAuthClient] | Unset = UNSET
    next_cursor: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.v1o_auth_client import V1OAuthClient  # noqa: PLC0415

        items: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.items, Unset):
            items = []
            for items_item_data in self.items:
                items_item = items_item_data.to_dict()
                items.append(items_item)

        next_cursor = self.next_cursor

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if items is not UNSET:
            field_dict["items"] = items
        if next_cursor is not UNSET:
            field_dict["nextCursor"] = next_cursor

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.v1o_auth_client import V1OAuthClient  # noqa: PLC0415

        d = dict(src_dict)
        _items = d.pop("items", UNSET)
        items: list[V1OAuthClient] | Unset = UNSET
        if _items is not UNSET:
            items = []
            for items_item_data in _items:
                items_item = V1OAuthClient.from_dict(items_item_data)

                items.append(items_item)

        next_cursor = d.pop("nextCursor", UNSET)

        v1o_auth_client_page = cls(
            items=items,
            next_cursor=next_cursor,
        )

        v1o_auth_client_page.additional_properties = d
        return v1o_auth_client_page

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
