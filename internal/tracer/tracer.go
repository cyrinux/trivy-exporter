// Package tracer wires OpenTelemetry tracing (OTLP/gRPC) and Pyroscope
// continuous profiling.
package tracer

import (
	"context"
	"fmt"

	"github.com/grafana/pyroscope-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// InitTracer sets the global tracer provider and starts the profiler.
// When disable is true a no-op provider is installed and no profiler runs.
func InitTracer(ctx context.Context, appname, version, tempoEndpoint, pyroEndpoint string, disable bool) (*sdktrace.TracerProvider, *pyroscope.Profiler, error) {
	if disable {
		tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.NeverSample()))
		otel.SetTracerProvider(tp)
		return tp, nil, nil
	}
	exp, err := otlptracegrpc.New(ctx, otlptracegrpc.WithEndpoint(tempoEndpoint), otlptracegrpc.WithInsecure())
	if err != nil {
		return nil, nil, fmt.Errorf("otlp exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(appname),
			semconv.ServiceVersionKey.String(version),
		)),
	)
	otel.SetTracerProvider(tp)
	p, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: appname,
		ServerAddress:   pyroEndpoint,
	})
	if err != nil {
		_ = tp.Shutdown(ctx)
		return nil, nil, fmt.Errorf("pyroscope: %w", err)
	}
	return tp, p, nil
}
