from enum import StrEnum


class AdminSubjectType(StrEnum):
    GROUP = "group"
    USER = "user"

    def __str__(self) -> str:
        return str(self.value)
