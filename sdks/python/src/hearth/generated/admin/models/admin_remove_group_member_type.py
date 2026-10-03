from enum import StrEnum


class AdminRemoveGroupMemberType(StrEnum):
    GROUP = "group"
    USER = "user"

    def __str__(self) -> str:
        return str(self.value)
