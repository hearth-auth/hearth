from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.v1_audit_action import V1AuditAction
from ..types import UNSET, Unset


T = TypeVar("T", bound="V1AuditEvent")


@_attrs_define
class V1AuditEvent:
    """A recorded audit event in the append-only log.

    Attributes:
        id (str | Unset):
        realm_id (str | Unset):
        actor (str | Unset):
        action (V1AuditAction | Unset): Categories of security-critical actions recorded in the audit log.

             - AUDIT_ACTION_GROUP_CREATED: RBAC group management
             - AUDIT_ACTION_ORPHANED_REFERENCE_SKIPPED: Permission management
             - AUDIT_ACTION_LOGIN_FAILED: Login events
             - AUDIT_ACTION_BACKUP_CREATED: Backup and export
             - AUDIT_ACTION_REQUIRED_ACTION_ASSIGNED: Required actions
             - AUDIT_ACTION_PASSWORD_COMPROMISED_REJECTED: Password security
             - AUDIT_ACTION_SESSION_LIMIT_ENFORCED: Session management
             - AUDIT_ACTION_ABUSE_DETECTED: Abuse detection
             - AUDIT_ACTION_EMAIL_CHANGE_INITIATED: Email change
             - AUDIT_ACTION_OIDC_SILENT_AUTH_PROBED: OIDC silent auth
             - AUDIT_ACTION_AGENT_CREATED: Agent lifecycle
             - AUDIT_ACTION_AGENT_DELEGATION: Agent delegation and MCP (M2)
             - AUDIT_ACTION_AAT_ISSUED: Phase D — advanced agent surface
             - AUDIT_ACTION_MFA_ENABLED: MFA lifecycle
             - AUDIT_ACTION_INVITATION_CREATED: Organization invitation lifecycle
        resource_type (str | Unset):
        resource_id (str | Unset):
        timestamp (str | Unset):
        metadata (str | Unset): Optional additional context (JSON-encoded).
        integrity_hash (str | Unset):
    """

    id: str | Unset = UNSET
    realm_id: str | Unset = UNSET
    actor: str | Unset = UNSET
    action: V1AuditAction | Unset = UNSET
    resource_type: str | Unset = UNSET
    resource_id: str | Unset = UNSET
    timestamp: str | Unset = UNSET
    metadata: str | Unset = UNSET
    integrity_hash: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        realm_id = self.realm_id

        actor = self.actor

        action: str | Unset = UNSET
        if not isinstance(self.action, Unset):
            action = self.action.value

        resource_type = self.resource_type

        resource_id = self.resource_id

        timestamp = self.timestamp

        metadata = self.metadata

        integrity_hash = self.integrity_hash

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if realm_id is not UNSET:
            field_dict["realmId"] = realm_id
        if actor is not UNSET:
            field_dict["actor"] = actor
        if action is not UNSET:
            field_dict["action"] = action
        if resource_type is not UNSET:
            field_dict["resourceType"] = resource_type
        if resource_id is not UNSET:
            field_dict["resourceId"] = resource_id
        if timestamp is not UNSET:
            field_dict["timestamp"] = timestamp
        if metadata is not UNSET:
            field_dict["metadata"] = metadata
        if integrity_hash is not UNSET:
            field_dict["integrityHash"] = integrity_hash

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id", UNSET)

        realm_id = d.pop("realmId", UNSET)

        actor = d.pop("actor", UNSET)

        _action = d.pop("action", UNSET)
        action: V1AuditAction | Unset
        if isinstance(_action, Unset):
            action = UNSET
        else:
            action = V1AuditAction(_action)

        resource_type = d.pop("resourceType", UNSET)

        resource_id = d.pop("resourceId", UNSET)

        timestamp = d.pop("timestamp", UNSET)

        metadata = d.pop("metadata", UNSET)

        integrity_hash = d.pop("integrityHash", UNSET)

        v1_audit_event = cls(
            id=id,
            realm_id=realm_id,
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            timestamp=timestamp,
            metadata=metadata,
            integrity_hash=integrity_hash,
        )

        v1_audit_event.additional_properties = d
        return v1_audit_event

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
