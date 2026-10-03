from enum import StrEnum


class V1RealmStatus(StrEnum):
    REALM_STATUS_ACTIVE = "REALM_STATUS_ACTIVE"
    REALM_STATUS_SUSPENDED = "REALM_STATUS_SUSPENDED"
    REALM_STATUS_UNSPECIFIED = "REALM_STATUS_UNSPECIFIED"

    def __str__(self) -> str:
        return str(self.value)
