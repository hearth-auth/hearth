from enum import StrEnum


class AdminUpdateOrganizationRequestStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"

    def __str__(self) -> str:
        return str(self.value)
