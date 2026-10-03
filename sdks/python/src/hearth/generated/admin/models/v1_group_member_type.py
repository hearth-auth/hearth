from enum import StrEnum


class V1GroupMemberType(StrEnum):
    TYPE_GROUP = "TYPE_GROUP"
    TYPE_UNSPECIFIED = "TYPE_UNSPECIFIED"
    TYPE_USER = "TYPE_USER"

    def __str__(self) -> str:
        return str(self.value)
