from enum import StrEnum


class V1ClientTrustLevel(StrEnum):
    CLIENT_TRUST_LEVEL_FIRST_PARTY = "CLIENT_TRUST_LEVEL_FIRST_PARTY"
    CLIENT_TRUST_LEVEL_THIRD_PARTY = "CLIENT_TRUST_LEVEL_THIRD_PARTY"
    CLIENT_TRUST_LEVEL_UNSPECIFIED = "CLIENT_TRUST_LEVEL_UNSPECIFIED"

    def __str__(self) -> str:
        return str(self.value)
