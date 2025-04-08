package tracer

import (
	"context"

	"github.com/grafana/pyroscope-go"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

func InitTracer(ctx context.Context, appname, tempoEndpoint, pyroEndpoint string, disable bool) (*sdktrace.TracerProvider, *pyroscope.Profiler) {
	if disable {
		tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.NeverSample()))
		otel.SetTracerProvider(tp)
		return tp, nil
	}
	exp, err := otlptracegrpc.New(ctx, otlptracegrpc.WithEndpoint(tempoEndpoint), otlptracegrpc.WithInsecure())
	if err != nil {
		log.Fatalf("Tracer error: %v", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(appname),
			semconv.ServiceVersionKey.String("1.2.0"),
		)),
	)
	otel.SetTracerProvider(tp)
	p, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: appname,
		ServerAddress:   pyroEndpoint,
	})
	if err != nil {
		log.Fatalf("Pyroscope profiler error: %v", err)
	}
	return tp, p
}
