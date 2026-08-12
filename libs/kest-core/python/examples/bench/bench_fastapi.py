import asyncio
import os
import threading

import httpx
import uvicorn
from fastapi import FastAPI
from kest.core import CedarLocalEngine, MockIdentityProvider, configure, kest_verified

app = FastAPI()

# ---------------------------------------------------------
# Set up Kest backend
# ---------------------------------------------------------

configure(
    identity=MockIdentityProvider("abc"),
    engine=CedarLocalEngine(
        policies={"test_pol": "permit(principal, action, resource);"}, entities=[]
    ),
)


@app.get("/sync-verified")
@kest_verified(policy="test_pol", context_map={"role": "admin"})
def sync_verified():
    # Sync endpoints in FastAPI are pushed to a ThreadPool.
    # This is where Kest GIL-release (rust-v2 backend) shines!
    return {"status": "ok"}


@app.get("/async-verified")
@kest_verified(policy="test_pol", context_map={"role": "admin"})
async def async_verified():
    # Async endpoints share the single event loop thread.
    return {"status": "ok"}


# ---------------------------------------------------------
# HTTP Client Load Generator
# ---------------------------------------------------------
async def blast_endpoint(client, url, duration, concurrency):
    """
    Blast the given endpoint for `duration` seconds with `concurrency` parallel tasks.
    """
    stop_flag = False
    counts = [0] * concurrency

    async def worker(worker_id):
        while not stop_flag:
            resp = await client.get(url)
            assert resp.status_code == 200
            counts[worker_id] += 1

    tasks = [asyncio.create_task(worker(i)) for i in range(concurrency)]
    await asyncio.sleep(duration)
    stop_flag = True
    await asyncio.gather(*tasks)
    return sum(counts)


async def run_benchmark():
    port = 8888
    # Start uvicorn in a background thread so we can hit it over actual HTTP.
    # We restrict to 1 worker so the thread pool is exactly testing 1 event loop
    # and multiple background worker threads managed by FastAPI's AnyIO pool.

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="critical")
    server = uvicorn.Server(config)

    t = threading.Thread(target=server.run)
    t.start()

    # wait for server to start
    await asyncio.sleep(1)

    print(f"\n# FastAPI Benchmark — backend={os.environ.get('KEST_BACKEND', 'python')}")
    print("  Window: 3s per test | Concurrency tested: [1, 2, 4, 8, 16, 32]")

    async with httpx.AsyncClient(
        limits=httpx.Limits(max_connections=None, max_keepalive_connections=None)
    ) as client:
        # Warmup
        await blast_endpoint(client, f"http://127.0.0.1:{port}/sync-verified", 1, 1)

        print("\n## Scalability: Sync Endpoint (FastAPI ThreadPool)")
        print(f" {'Threads':>7} | {'ops/sec':>10}")
        print("-" * 25)
        for c in [1, 2, 4, 8, 16, 32]:
            total = await blast_endpoint(
                client, f"http://127.0.0.1:{port}/sync-verified", 3.0, c
            )
            ops = total / 3.0
            print(f" {c:>7} | {ops:>10.1f}")

        print("\n## Scalability: Async Endpoint (Single Event Loop)")
        print(f" {'Tasks ':>7} | {'ops/sec':>10}")
        print("-" * 25)
        for c in [1, 2, 4, 8, 16, 32]:
            total = await blast_endpoint(
                client, f"http://127.0.0.1:{port}/async-verified", 3.0, c
            )
            ops = total / 3.0
            print(f" {c:>7} | {ops:>10.1f}")

    server.should_exit = True
    t.join()


if __name__ == "__main__":
    asyncio.run(run_benchmark())
