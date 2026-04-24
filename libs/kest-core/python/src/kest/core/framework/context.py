from opentelemetry import baggage


def get_current_user():
    """Reads kest.user from OTel Baggage."""
    return baggage.get_baggage("kest.user")


def get_current_agent():
    """Reads kest.agent from OTel Baggage."""
    return baggage.get_baggage("kest.agent")


def get_current_task():
    """Reads kest.task from OTel Baggage."""
    return baggage.get_baggage("kest.task")


def get_current_passport():
    """Reads kest.passport from OTel Baggage."""
    return baggage.get_baggage("kest.passport")


def get_current_jwt():
    """Reads kest.jwt from OTel Baggage."""
    return baggage.get_baggage("kest.jwt")
