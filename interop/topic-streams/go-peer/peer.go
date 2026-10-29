package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/network"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
)

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: %s <address-file>", os.Args[0])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	host, err := libp2p.New(
		libp2p.NoTransports,
		libp2p.Transport(quic.NewTransport),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/udp/0/quic-v1"),
	)
	if err != nil {
		return err
	}
	defer host.Close()
	ps, err := pubsub.NewGossipSub(ctx, host, pubsub.WithTopicStreams())
	if err != nil {
		return err
	}

	done := make(chan struct{})
	var once sync.Once
	host.Network().Notify(&network.NotifyBundle{
		// Nim disconnects only after checking the final echo and live streams.
		DisconnectedF: func(n network.Network, conn network.Conn) {
			if len(n.ConnsToPeer(conn.RemotePeer())) == 0 {
				once.Do(func() { close(done) })
			}
		},
	})
	failures := make(chan error, 2)
	for _, name := range []string{"interop/topic-streams/small", "interop/topic-streams/large"} {
		topic, err := ps.Join(name)
		if err != nil {
			return err
		}
		defer topic.Close()
		sub, err := topic.Subscribe()
		if err != nil {
			return err
		}
		defer sub.Cancel()
		go func() {
			for {
				msg, err := sub.Next(ctx)
				if err != nil {
					failures <- err
					return
				}
				if msg.ReceivedFrom == host.ID() {
					continue
				}
				if err := topic.Publish(ctx, msg.Data); err != nil {
					failures <- err
					return
				}
			}
		}()
	}
	if err := os.WriteFile(os.Args[1], []byte(fmt.Sprintf("%s/p2p/%s", host.Addrs()[0], host.ID())), 0600); err != nil {
		return err
	}
	select {
	case <-done:
		return nil
	case err := <-failures:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
