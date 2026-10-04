from enum import StrEnum


class AdminRoleScopeKind(StrEnum):
    ANY = "any"
    ORGANIZATION = "organization"
    REALM = "realm"

    def __str__(self) -> str:
        return str(self.value)
