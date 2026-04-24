import re
from abc import ABC, abstractmethod
from typing import Any, List


class OutputValidator(ABC):
    """
    Base class for output validation hooks in @kest_verified.
    """

    @abstractmethod
    def validate(self, output: Any) -> None:
        """
        Validates the output of a decorated function.

        Args:
            output: The return value of the function.

        Raises:
            ValueError: If validation fails.
        """
        pass


class MaxLengthValidator(OutputValidator):
    """
    Ensures the output (string or list) does not exceed a maximum length.
    """

    def __init__(self, max_length: int):
        self.max_length = max_length

    def validate(self, output: Any) -> None:
        if hasattr(output, "__len__"):
            if len(output) > self.max_length:
                raise ValueError(
                    f"Output length {len(output)} exceeds maximum of {self.max_length}"
                )


class RegexDenyListValidator(OutputValidator):
    """
    Ensures the output string does not match any of the provided regex patterns.
    Useful for PII detection or prompt injection artifact filtering.
    """

    def __init__(self, patterns: List[str]):
        self.patterns = [re.compile(p) for p in patterns]

    def validate(self, output: Any) -> None:
        if not isinstance(output, str):
            return

        for pattern in self.patterns:
            if pattern.search(output):
                raise ValueError(
                    f"Output matched deny-list pattern: {pattern.pattern}"
                )
