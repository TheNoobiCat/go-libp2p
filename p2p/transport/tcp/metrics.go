//go:build !windows && !riscv64 && !loong64

package tcp

import (
	"strings"
	"sync"
	"time"

	"github.com/TheNoobiCat/go-libp2p/core/network"
	"github.com/TheNoobiCat/go-libp2p/core/transport"
	"github.com/marten-seemann/tcp"
	"github.com/mikioh/tcpinfo"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	newConns      *prometheus.CounterVec
	closedConns   *prometheus.CounterVec
	segsSentDesc  *prometheus.Desc
	segsRcvdDesc  *prometheus.Desc
	bytesSentDesc *prometheus.Desc
	bytesRcvdDesc *prometheus.Desc
)

const collectFrequency = 10 * time.Second

var defaultCollector *aggregatingCollector

var initMetricsOnce sync.Once

func initMetrics() {
	segsSentDesc = prometheus.NewDesc("tcp_sent_segments_total", "TCP segments sent", nil, nil)
	segsRcvdDesc = prometheus.NewDesc("tcp_rcvd_segments_total", "TCP segments received", nil, nil)
	bytesSentDesc = prometheus.NewDesc("tcp_sent_bytes", "TCP bytes sent", nil, nil)
	bytesRcvdDesc = prometheus.NewDesc("tcp_rcvd_bytes", "TCP bytes received", nil, nil)

	defaultCollector = newAggregatingCollector()
	prometheus.MustRegister(defaultCollector)

	const direction = "direction"

	newConns = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tcp_connections_new_total",
			Help: "TCP new connections",
		},
		[]string{direction},
	)
	prometheus.MustRegister(newConns)
	closedConns = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tcp_connections_closed_total",
			Help: "TCP connections closed",
		},
		[]string{direction},
	)
	prometheus.MustRegister(closedConns)
}

type aggregatingCollector struct {
	cronOnce sync.Once

	mutex                sync.Mutex
	highestID            uint64
	conns                map[uint64] /* id */ *tracingConn
	rtts                 prometheus.Histogram
	connDurations        prometheus.Histogram
	segsSent, segsRcvd   uint64
	bytesSent, bytesRcvd uint64
}

var _ prometheus.Collector = &aggregatingCollector{}

func newAggregatingCollector() *aggregatingCollector {
	c := &aggregatingCollector{
		conns: make(map[uint64]*tracingConn),
		rtts: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "tcp_rtt",
			Help:    "TCP round trip time",
			Buckets: prometheus.ExponentialBuckets(0.001, 1.25, 40), // 1ms to ~6000ms
		}),
		connDurations: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "tcp_connection_duration",
			Help:    "TCP Connection Duration",
			Buckets: prometheus.ExponentialBuckets(1, 1.5, 40), // 1s to ~12 weeks
		}),
	}
	return c
}

func (c *aggregatingCollector) AddConn(t *tracingConn) uint64 {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.highestID++
	c.conns[c.highestID] = t
	return c.highestID
}

func (c *aggregatingCollector) removeConn(id uint64) {
	delete(c.conns, id)
}

func (c *aggregatingCollector) Describe(descs chan<- *prometheus.Desc) {
	descs <- c.rtts.Desc()
	descs <- c.connDurations.Desc()
	if hasSegmentCounter {
		descs <- segsSentDesc
		descs <- segsRcvdDesc
	}
	if hasByteCounter {
		descs <- bytesSentDesc
		descs <- bytesRcvdDesc
	}
}

func (c *aggregatingCollector) cron() {
	ticker := time.NewTicker(collectFrequency)
	defer ticker.Stop()

	for now := range ticker.C {
		c.gatherMetrics(now)
	}
}

func (c *aggregatingCollector) gatherMetrics(now time.Time) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.segsSent = 0
	c.segsRcvd = 0
	c.bytesSent = 0
	c.bytesRcvd = 0
	for _, conn := range c.conns {
		info, err := conn.getTCPInfo()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				continue
			}
			log.Errorf("Failed to get TCP info: %s", err)
			continue
		}
		if hasSegmentCounter {
			c.segsSent += getSegmentsSent(info)
			c.segsRcvd += getSegmentsRcvd(info)
		}
		if hasByteCounter {
			c.bytesSent += getBytesSent(info)
			c.bytesRcvd += getBytesRcvd(info)
		}
		c.rtts.Observe(info.RTT.Seconds())
		c.connDurations.Observe(now.Sub(conn.startTime).Seconds())
	}
}

func (c *aggregatingCollector) Collect(metrics chan<- prometheus.Metric) {
	// Start collecting the metrics collection the first time Collect is called.
	c.cronOnce.Do(func() {
		c.gatherMetrics(time.Now())
		go c.cron()
	})

	c.mutex.Lock()
	defer c.mutex.Unlock()

	metrics <- c.rtts
	metrics <- c.connDurations
	if hasSegmentCounter {
		segsSentMetric, err := prometheus.NewConstMetric(segsSentDesc, prometheus.CounterValue, float64(c.segsSent))
		if err != nil {
			log.Errorf("creating tcp_sent_segments_total metric failed: %v", err)
			return
		}
		segsRcvdMetric, err := prometheus.NewConstMetric(segsRcvdDesc, prometheus.CounterValue, float64(c.segsRcvd))
		if err != nil {
			log.Errorf("creating tcp_rcvd_segments_total metric failed: %v", err)
			return
		}
		metrics <- segsSentMetric
		metrics <- segsRcvdMetric
	}
	if hasByteCounter {
		bytesSentMetric, err := prometheus.NewConstMetric(bytesSentDesc, prometheus.CounterValue, float64(c.bytesSent))
		if err != nil {
			log.Errorf("creating tcp_sent_bytes metric failed: %v", err)
			return
		}
		bytesRcvdMetric, err := prometheus.NewConstMetric(bytesRcvdDesc, prometheus.CounterValue, float64(c.bytesRcvd))
		if err != nil {
			log.Errorf("creating tcp_rcvd_bytes metric failed: %v", err)
			return
		}
		metrics <- bytesSentMetric
		metrics <- bytesRcvdMetric
	}
}

func (c *aggregatingCollector) ClosedConn(conn *tracingConn, direction string) {
	c.mutex.Lock()
	c.removeConn(conn.id)
	c.mutex.Unlock()
	closedConns.WithLabelValues(direction).Inc()
}

type tracingConn struct {
	id uint64

	collector *aggregatingCollector

	startTime time.Time
	isClient  bool

	manet.Conn
	tcpConn   *tcp.Conn
	closeOnce sync.Once
	closeErr  error
}

// newTracingConn wraps a manet.Conn with a tracingConn. A nil collector will use the default collector.
func newTracingConn(c manet.Conn, collector *aggregatingCollector, isClient bool) (*tracingConn, error) {
	initMetricsOnce.Do(func() { initMetrics() })
	conn, err := tcp.NewConn(c)
	if err != nil {
		return nil, err
	}
	tc := &tracingConn{
		startTime: time.Now(),
		isClient:  isClient,
		Conn:      c,
		tcpConn:   conn,
		collector: collector,
	}
	if tc.collector == nil {
		tc.collector = defaultCollector
	}
	tc.id = tc.collector.AddConn(tc)
	newConns.WithLabelValues(tc.getDirection()).Inc()
	return tc, nil
}

func (c *tracingConn) getDirection() string {
	if c.isClient {
		return "outgoing"
	}
	return "incoming"
}

func (c *tracingConn) Close() error {
	c.closeOnce.Do(func() {
		c.collector.ClosedConn(c, c.getDirection())
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *tracingConn) getTCPInfo() (*tcpinfo.Info, error) {
	var o tcpinfo.Info
	var b [256]byte
	i, err := c.tcpConn.Option(o.Level(), o.Name(), b[:])
	if err != nil {
		return nil, err
	}
	info := i.(*tcpinfo.Info)
	return info, nil
}

type tracingListener struct {
	transport.GatedMaListener
	collector *aggregatingCollector
}

// newTracingListener wraps a manet.Listener with a tracingListener. A nil collector will use the default collector.
func newTracingListener(l transport.GatedMaListener, collector *aggregatingCollector) *tracingListener {
	return &tracingListener{GatedMaListener: l, collector: collector}
}

func (l *tracingListener) Accept() (manet.Conn, network.ConnManagementScope, error) {
	conn, scope, err := l.GatedMaListener.Accept()
	if err != nil {
		if scope != nil {
			scope.Done()
			log.Errorf("BUG: got non-nil scope but also an error: %s", err)
		}
		return nil, nil, err
	}

	tc, err := newTracingConn(conn, l.collector, false)
	if err != nil {
		log.Errorf("failed to create tracingConn from %T: %s", conn, err)
		conn.Close()
		scope.Done()
		return nil, nil, err
	}
	return tc, scope, nil
}
