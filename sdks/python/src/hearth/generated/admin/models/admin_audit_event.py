from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast
from uuid import UUID

if TYPE_CHECKING:
    from ..models.admin_audit_event_metadata import AdminAuditEventMetadata


T = TypeVar("T", bound="AdminAuditEvent")


@_attrs_define
class AdminAuditEvent:
    """
    Attributes:
        id (str):
        realm_id (UUID):
        actor (str):
        action (str): The audit action name, e.g. `UserCreated`.
        resource_type (str):
        resource_id (str):
        timestamp (int): Microseconds since the Unix epoch.
        integrity_hash (str):
        metadata (AdminAuditEventMetadata | Unset): Present only when the event carries metadata.
    """

    id: str
    realm_id: UUID
    actor: str
    action: str
    resource_type: str
    resource_id: str
    timestamp: int
    integrity_hash: str
    metadata: AdminAuditEventMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.admin_audit_event_metadata import AdminAuditEventMetadata  # noqa: PLC0415

        id = self.id

        realm_id = str(self.realm_id)

        actor = self.actor

        action = self.action

        resource_type = self.resource_type

        resource_id = self.resource_id

        timestamp = self.timestamp

        integrity_hash = self.integrity_hash

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "realm_id": realm_id,
                "actor": actor,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "timestamp": timestamp,
                "integrity_hash": integrity_hash,
            }
        )
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.admin_audit_event_metadata import AdminAuditEventMetadata  # noqa: PLC0415

        d = dict(src_dict)
        id = d.pop("id")

        realm_id = UUID(d.pop("realm_id"))

        actor = d.pop("actor")

        action = d.pop("action")

        resource_type = d.pop("resource_type")

        resource_id = d.pop("resource_id")

        timestamp = d.pop("timestamp")

        integrity_hash = d.pop("integrity_hash")

        _metadata = d.pop("metadata", UNSET)
        metadata: AdminAuditEventMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = AdminAuditEventMetadata.from_dict(_metadata)

        admin_audit_event = cls(
            id=id,
            realm_id=realm_id,
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            timestamp=timestamp,
            integrity_hash=integrity_hash,
            metadata=metadata,
        )

        admin_audit_event.additional_properties = d
        return admin_audit_event

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
