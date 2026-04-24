from opentelemetry import baggage


def get_current_passport():
    return baggage.get_baggage("kest.passport")


def get_current_jwt():
    return baggage.get_baggage("kest.jwt")


def get_current_user():
    return baggage.get_baggage("kest.user")


def get_current_agent():
    return baggage.get_baggage("kest.agent")


def get_current_task():
    return baggage.get_baggage("kest.task")
