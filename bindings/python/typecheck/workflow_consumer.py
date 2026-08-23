from auths.protocol import RemoteVerifier
from auths.verify import AuthorizedVerification, VerificationInput


async def authorize(verifier: RemoteVerifier, value: VerificationInput) -> bool:
    result = await verifier.verify(value)
    return isinstance(result, AuthorizedVerification)
