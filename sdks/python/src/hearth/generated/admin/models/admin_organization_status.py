from enum import StrEnum


class AdminOrganizationStatus(StrEnum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    SUSPENDED = "suspended"

    def __str__(self) -> str:
        return str(self.value)
