from enum import StrEnum


class V1AccessTokenAuthorization(StrEnum):
    DECISION = "DECISION"
    EMBEDDED = "EMBEDDED"
    INTROSPECTION = "INTROSPECTION"

    def __str__(self) -> str:
        return str(self.value)
