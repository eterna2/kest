import logging
from typing import Any

from opentelemetry import baggage, trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

from kest.core import (
    PolicyEngine,
    IdentityProvider,
    configure,
    kest_verified,
    Passport,
    version,
)


# 1. Setup OpenTelemetry
def setup_otel():
    resource = Resource.create({"service.name": "kest-e2e-example"})
    provider = TracerProvider(resource=resource)
    processor = BatchSpanProcessor(ConsoleSpanExporter())
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)
    return trace.get_tracer(__name__)


# 2. Mock Identity Provider
class MockIdentityProvider(IdentityProvider):
    def get_workload_id(self) -> str:
        return "spiffe://internal/example-service"

    def sign(self, payload: bytes) -> str:
        # Dummy signature for demonstration
        return f"mock-sig.{payload.hex()[:10]}"


# 3. Mock Policy Engine
class MockPolicyEngine(PolicyEngine):
    def evaluate(
        self, entry_id: str, policy_names: list[str], context: dict[str, Any]
    ) -> bool:
        print("\n[POLICY EVALUATION]")
        print(f"  Entry ID:  {entry_id}")
        print(f"  Policies:  {policy_names}")
        print(f"  Workload:  {context.get('workload_id')}")
        print(f"  Passport:  {context.get('passport')}")
        print(f"  JWT Claim: {context.get('jwt')}")

        # Simple mock logic: allow everything except "restricted" policy if trust is low
        if "restricted" in policy_names:
            return False
        return True


# 4. Decorated Functions
@kest_verified(policy="audit_only")
def process_data(payload: str):
    print(f"  Executing process_data with payload: {payload}")
    return f"Processed: {payload}"


@kest_verified(policy="restricted")
def secure_operation():
    print("  Executing secure_operation...")
    return "Secret accessed!"


def main():
    print(f"Kest Core Version: {version()}")

    # Setup OTEL
    tracer = setup_otel()

    # Configure Kest
    configure(engine=MockPolicyEngine(), identity=MockIdentityProvider())

    # Initialize a Passport for this session
    passport = Passport()

    with tracer.start_as_current_span("e2e-main"):
        # Set some baggage (this would normally come from a parent service or auth middleware)
        ctx = baggage.set_baggage("kest.passport", "passport-v3-alpha")
        ctx = baggage.set_baggage(
            "kest.jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", context=ctx
        )

        # Attach context to current execution
        import opentelemetry.context as otel_context

        token = otel_context.attach(ctx)

        try:
            print("\n--- TEST 1: Allowed Execution ---")
            result = process_data("Hello, secret Zero Trust!")
            print(f"Result 1: {result}")

            print("\n--- TEST 3: Denied Execution ---")
            try:
                secure_operation()
            except PermissionError as e:
                print(f"Caught expected error: {e}")

            print(f"\nFinal Session State: {passport.serialize()}")

        finally:
            otel_context.detach(token)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
