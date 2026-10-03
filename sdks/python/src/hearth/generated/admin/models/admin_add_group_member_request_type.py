from enum import StrEnum


class AdminAddGroupMemberRequestType(StrEnum):
    GROUP = "group"
    USER = "user"

    def __str__(self) -> str:
        return str(self.value)
