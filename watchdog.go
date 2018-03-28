package main

import (
	"time"
	"strings"
	"net/http"
	"github.com/coreos/go-systemd/daemon"
)

func launch_watchdog(watchdog_interval int, listenAddr string, expectedCode int, watchdog_cookie string) {
	// Listen addr should be `ip:port`, setup the check address. There is
	// probably a tidier way to do this within, never leaving golang until it's
	// directed to the backend but that's too much work to figure out.
	arr := strings.Split(listenAddr, ":")
	port := arr[1]
	checkAddr := "http://127.0.0.1:" + port
	// We'll check thrice per watchdog interval.

	go func() {
		for {
			req, err := http.NewRequest("GET", checkAddr, nil)
			req.Header.Add("Cookie", "galaxysession=" + watchdog_cookie)
			client := &http.Client{}
			resp, err := client.Do(req)

			if err == nil && resp.StatusCode == expectedCode {
				daemon.SdNotify(false, "WATCHDOG=1")
			}
			time.Sleep(time.Duration(watchdog_interval / 3) * time.Second)
		}
	}()
}
