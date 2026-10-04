from enum import StrEnum


class V1RegisterClientRequestTokenEndpointAuthMethod(StrEnum):
    CLIENT_SECRET_BASIC = "client_secret_basic"
    CLIENT_SECRET_POST = "client_secret_post"
    NONE = "none"
    PRIVATE_KEY_JWT = "private_key_jwt"

    def __str__(self) -> str:
        return str(self.value)
