from opentelemetry import baggage


def get_current_passport():
    return baggage.get_baggage("kest.passport")


def get_current_jwt():
    return baggage.get_baggage("kest.jwt")
