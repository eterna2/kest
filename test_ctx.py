import asyncio, contextvars
from opentelemetry import baggage
import opentelemetry.context as otel_context
async def main():
    ctx = baggage.set_baggage("kest.user", "test")
    otel_context.attach(ctx)
    cv = contextvars.copy_context()
    return await asyncio.get_running_loop().run_in_executor(None, cv.run, lambda: baggage.get_baggage("kest.user"))
print(asyncio.run(main()))
