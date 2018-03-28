package main

import (
	"time"

	log "github.com/Sirupsen/logrus"
	_ "github.com/lib/pq"
	"github.com/quipo/statsd"
)

var (
	Metrics         *statsd.StatsdClient
	statsd_influxdb bool
)

func configure_metrics(statsd_address, statsd_prefix string) {
	if len(statsd_address) > 0 {
		Metrics = statsd.NewStatsdClient(statsd_address, statsd_prefix)
		err := Metrics.CreateSocket()
		if err != nil {
			log.Fatal("Could not configure StatsD connection")
		}
		log.Printf("Loaded StatsD connection: %#v", Metrics)
	}
}

func metric_incr(val string) {
	if Metrics != nil {
		var err error
		if statsd_influxdb {
			err = Metrics.Incr(",key="+val, 1)
		} else {
			err = Metrics.Incr(val, 1)
		}
		if err != nil {
			log.Error(err)
		}
	}
}

func metric_time(val string, elapsed time.Duration) {
	if Metrics != nil {
		var err error
		if statsd_influxdb {
			err = Metrics.PrecisionTiming(",key=query_timing", elapsed)
		} else {
			err = Metrics.PrecisionTiming("query_timing", elapsed)
		}

		if err != nil {
			log.Error(err)
		}
	}
}
