from abc import ABC, abstractmethod


class IdentityProvider(ABC):
    """
    Abstract base class for all identity providers in Kest.

    An IdentityProvider is responsible for identifying the current principal
    and signing audit entries (Passport nodes).
    """

    @abstractmethod
    def get_identity(self) -> str:
        """
        Returns the unique identifier for the current principal.

        Returns:
            str: The principal identifier (e.g., SPIFFE ID, AWS Role ARN).
        """
        pass

    @abstractmethod
    def sign(self, payload: bytes) -> str:
        """
        Signs a payload and returns a JWS-formatted signature.

        Args:
            payload: The raw bytes to sign.

        Returns:
            str: A complete JWS string (header.payload.signature).
        """
        pass

    def verify_svid(self, svid: str) -> str:
        """
        Verifies a SVID (Software Value Identity) and extracts the principal ID.

        In a real system, this would perform cryptographic verification of a
        JWT or X509 SVID.

        Args:
            svid: The SVID string to verify.

        Returns:
            str: The verified principal identifier.
        """
        return self.get_identity()

    def sign_payload(self, payload: bytes) -> str:
        """
        Aliased bridge method for signing payloads.

        Args:
            payload: The raw bytes to sign.

        Returns:
            str: A JWS signature.
        """
        return self.sign(payload)
