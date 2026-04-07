# Distributed Context Propagation

For Kest's Merkle DAG lineage to survive across microservice boundaries, the cryptographic state (`kest.passport` and `kest.lineage_root`) must be continuously extracted and injected into the transport layer.

Kest achieves this through **OpenTelemetry Baggage** (W3C standard), which provides a vendor-neutral mechanism for propagating contextual key-value pairs via HTTP headers.

## FastAPI Middleware

If your service is built using FastAPI or Starlette, you can use `KestMiddleware` to automatically extract the incoming lineage.

```python
from fastapi import FastAPI
from kest.core.ext import KestMiddleware

app = FastAPI()

# Automatically parses the `baggage` HTTP header, 
# updates the OTel Context, and manages asyncio thread-locals.
app.add_middleware(KestMiddleware)
```

By adding this middleware, any route handler decorated with `@kest_verified` will automatically read the incoming lineage instead of starting a new "root" chain.

## HTTPX Interceptor

When your service calls a downstream dependency, the current execution state must be injected into the outgoing HTTP request. Kest provides an interceptor for the `httpx` asynchronous client.

```python
import httpx
from kest.core.ext import KestHttpxInterceptor

async def call_downstream_service(payload: dict):
    # The interceptor automatically fetches the active `kest.passport` 
    # from the OTel Context and formats it as a RFC 7230 Baggage header.
    interceptor = KestHttpxInterceptor()
    
    async with httpx.AsyncClient(timeout=5.0) as client:
        # Build the request
        request = client.build_request("POST", "http://internal-service/api/v1/process", json=payload)
        
        # Inject Kest Baggage
        request = interceptor(request)
        
        # Send
        response = await client.send(request)
        return response.json()
```

## Overcoming Size Limitations (Claim Check)

The base64 encoded JSON Web Signatures in the `kest.passport` grow with every hop. Standard HTTP servers typically limit total header size to 8KB. Once a lineage crosses ~4KB, Kest shifts to a **Claim Check Pattern**.

### How Claim Check Works

1.  During `@kest_verified` execution, if the passport exceeds the safe threshold, Kest uploads the serialized JWS array to a shared high-performance data store (e.g., Redis).
2.  The middleware injects a tiny UUID into the baggage: `kest.claim_check=uuid-1234`.
3.  The downstream `KestMiddleware` detects the `claim_check` key.
4.  It immediately fetches the full passport payload from the shared data store and rehydrates the OTel context before executing the policy evaluation.

**Configuring Claim Check:**
```python
from kest.core import SimpleCache, configure

# Simply provide a CacheProvider during initialization.
# Kest handles the rest transparently.
configure(engine=my_engine, identity=my_id, cache=SimpleCache())
```
