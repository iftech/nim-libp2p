package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
)

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: %s <address-file>", os.Args[0])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
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
	address, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	remote, err := peer.AddrInfoFromString(strings.TrimSpace(string(address)))
	if err != nil {
		return err
	}

	topics := make([]*pubsub.Topic, 0, 2)
	subs := make([]*pubsub.Subscription, 0, 2)
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
		topics = append(topics, topic)
		subs = append(subs, sub)
	}
	if err := host.Connect(ctx, *remote); err != nil {
		return err
	}
	// Two rounds verify reuse of each topic's stream. Signatures remain enabled:
	// successful delivery also checks reconstruction of the omitted topic name.
	for round := 0; round < 2; round++ {
		for i, topic := range topics {
			size := 32
			if topic.String() == "interop/topic-streams/large" {
				size = 256 * 1024
			}
			payload := bytes.Repeat([]byte{byte(round + 1)}, size)
			if err := topic.Publish(ctx, payload, pubsub.WithReadiness(pubsub.MinTopicSize(1))); err != nil {
				return fmt.Errorf("publish %s round %d: %w", topic.String(), round, err)
			}
			for {
				msg, err := subs[i].Next(ctx)
				if err != nil {
					return fmt.Errorf("receive %s round %d: %w", topic.String(), round, err)
				}
				if msg.ReceivedFrom == host.ID() {
					continue
				}
				if msg.ReceivedFrom != remote.ID || msg.GetFrom() != remote.ID || msg.GetTopic() != topic.String() || !bytes.Equal(msg.Data, payload) {
					return fmt.Errorf("unexpected echo on %s round %d: receivedFrom=%s expected=%s from=%s expected=%s topic=%q expected=%q payloadLen=%d expected=%d payloadEqual=%t",
						topic.String(), round, msg.ReceivedFrom, remote.ID, msg.GetFrom(), remote.ID,
						msg.GetTopic(), topic.String(), len(msg.Data), len(payload), bytes.Equal(msg.Data, payload))
				}
				break
			}
		}
	}

	counts := map[network.Direction]int{}
	for _, conn := range host.Network().ConnsToPeer(remote.ID) {
		if conn.ConnState().Transport != "quic-v1" {
			return fmt.Errorf("expected QUIC v1 connection, got %s", conn.ConnState().Transport)
		}
		for _, stream := range conn.GetStreams() {
			if stream.Protocol() == "/gsts/v0beta" {
				counts[stream.Stat().Direction]++
			}
		}
	}
	if counts[network.DirInbound] != 2 || counts[network.DirOutbound] != 2 {
		return fmt.Errorf("expected two topic streams per direction, got inbound=%d outbound=%d", counts[network.DirInbound], counts[network.DirOutbound])
	}
	fmt.Println("Topic streams interop passed over QUIC v1: two signed round trips per topic, two streams per direction")
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
