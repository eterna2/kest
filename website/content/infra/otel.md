# Audit Aggregation (OTel)

Kest generates a non-fungible audit trail in the form of OpenTelemetry (OTel) spans. Each time an execution hop completes, Kest produces a span containing the cryptographic signature and the Merkle root of the execution lineage.

## The Role of the Collector

While spans can be exported directly from applications, the recommended deployment involves sending spans to a local **OpenTelemetry Collector**.

1.  The Kest application sends raw OTLP (OpenTelemetry Protocol) traces to the Collector over gRPC (`4317`) or HTTP (`4318`).
2.  The Collector acts as a buffer and aggregator, processing the spans and forwarding them to final storage backends like Prometheus, Jaeger, AWS X-Ray, or a simple JSON file for localized testing.

## Docker Compose Example

Deploy the `opentelemetry-collector-contrib` image to ensure you have the full suite of receivers and exporters.

```yaml
  otel-collector:
    image: otel/opentelemetry-collector-contrib:latest
    command: ["--config=/etc/otel-collector-config.yaml"]
    volumes:
      - ./otel/otel-collector-config.yaml:/etc/otel-collector-config.yaml
      - ./otel/output:/var/log/otel
    ports:
      - "4317:4317"
      - "4318:4318"
```

## Configuring the Collector

The `otel-collector-config.yaml` file defines how the Collector receives and exports data. For Kest's audit requirements, you must ensure the `otlp` receivers are active, and an exporter is configured to durably store the traces.

**Example `otel-collector-config.yaml`**
```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:

exporters:
  # During development, 'debug' is useful for observing the raw kest.signature attributes.
  debug:
    verbosity: detailed
  
  # In a real environment, you might use 'file' to write to an NFS mount, 
  # or configure an OTLP exporter to send traces to a SaaS provider.
  file:
    path: /var/log/otel/spans.json

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug, file]
```

## Extracting Kest Spans

Once the Collector is running, Kest spans will appear with the `kest.core` instrumentation scope and the `kest.verified.*` naming convention. The critical attributes needed for post-execution Merkle verification are `kest.signature` and `kest.parent_hash`.
