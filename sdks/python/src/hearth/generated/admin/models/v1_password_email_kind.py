from enum import StrEnum


class V1PasswordEmailKind(StrEnum):
    PASSWORD_EMAIL_KIND_RESET = "PASSWORD_EMAIL_KIND_RESET"
    PASSWORD_EMAIL_KIND_SETUP = "PASSWORD_EMAIL_KIND_SETUP"
    PASSWORD_EMAIL_KIND_UNSPECIFIED = "PASSWORD_EMAIL_KIND_UNSPECIFIED"

    def __str__(self) -> str:
        return str(self.value)
