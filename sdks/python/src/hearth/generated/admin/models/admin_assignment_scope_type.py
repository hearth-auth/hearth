from enum import StrEnum


class AdminAssignmentScopeType(StrEnum):
    ORG = "org"
    REALM = "realm"

    def __str__(self) -> str:
        return str(self.value)
