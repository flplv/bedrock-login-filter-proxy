// This project used https://github.com/Sandertv/go-raknet/blob/master/examples/proxy/proxy.go as
// starting point

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/sandertv/go-raknet"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func main() {
	serverArg := flag.String("server", "", "Required: Bedrock/MCPE server IP address and port (ex: 1.2.3.4:19132)")
	portArg := flag.String("local-port", "19132", "Optional: Local port to listen to. Default is 19132")
	flag.Parse()

	if *serverArg == "" {
		log.Printf("Plrsdr provide -server argument.\n")
		flag.Usage()
		return
	}
	local := "0.0.0.0:" + *portArg
	runServer(*serverArg, local)
}

func runServer(serverAddress string, listenAddress string) {
	log.Printf("Listening to %s, proxying for %s", listenAddress, serverAddress)

	listener, err := raknet.Listen(listenAddress)
	defer func() {
		_ = listener.Close()
	}()
	if err != nil {
		panic(err)
	}
	// We hijack the pong of a Minecraft server, so our proxy will continuously send the pong data of the
	// server.
	//noinspection SpellCheckingInspection
	if err := listener.HijackPong(serverAddress); err != nil {
		panic(err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Unable to accept a connection from client: %v\n", err)
			continue
		}

		// We spin up a new connection with the server each time a client connects to the proxy.
		//noinspection SpellCheckingInspection
		server, err := raknet.Dial(serverAddress)
		if err != nil {
			// Try Again
			server, err = raknet.Dial(serverAddress)
			if err != nil {
				_ = conn.Close()
				log.Printf("Error connecting to the server: %v\n", err)
				continue
			}
		}
		go func() {
			loginAccepted := false
			b := make([]byte, 300000)
			for {

				n, err := conn.Read(b)
				if err != nil {
					if !raknet.ErrConnectionClosed(err) {
						log.Printf("error reading from client connection: %v\n", err)
					}
					_ = server.Close()
					return
				}
				packet := b[:n]

				if loginAccepted == false {
					parser := newParser(conn, bytes.NewReader(packet))
					identityData, clientData, success := parser.process()

					if success == true {
						loginAccepted = acceptLogin(identityData, clientData)
					}

					var msg string
					if loginAccepted {
						msg = "Accepted login"
					} else {
						msg = "Login denied"
					}

					log.Printf("%s: DisplayName %s, Identity %s, XUID %s, TitleID %s, DeviceOs %v, GameVersion %s, ServerAddress %s, DefaultInputMode %d, CurrentInputMode %d",
						msg,
						identityData.DisplayName,
						identityData.Identity,
						identityData.XUID,
						identityData.TitleID,
						clientData.DeviceOS,
						clientData.GameVersion,
						clientData.ServerAddress,
						clientData.DefaultInputMode,
						clientData.CurrentInputMode,
					)

					if loginAccepted == false {
						_ = conn.Close()
						continue
					}
				}

				if _, err := server.Write(packet); err != nil {
					if !raknet.ErrConnectionClosed(err) {
						log.Printf("error writing to server connection: %v\n", err)
					}
					_ = conn.Close()
					return
				}
			}
		}()
		go func() {
			b := make([]byte, 300000)
			for {
				n, err := server.Read(b)
				if err != nil {
					if !raknet.ErrConnectionClosed(err) {
						log.Printf("error reading from server connection: %v\n", err)
					}
					_ = conn.Close()
					return
				}
				packet := b[:n]
				if _, err := conn.Write(packet); err != nil {
					if !raknet.ErrConnectionClosed(err) {
						log.Printf("error writing to client connection: %v\n", err)
					}
					_ = server.Close()
					return
				}
			}
		}()
	}
}

type parser struct {
	pool    packet.Pool
	decoder *packet.Decoder
	conn    net.Conn
}

func newParser(conn net.Conn, reader io.Reader) parser {
	return parser{
		packet.NewPool(),
		packet.NewDecoder(reader),
		conn,
	}
}

func (parser parser) process() (login.IdentityData, login.ClientData, bool) {
	i := login.IdentityData{}
	c := login.ClientData{}

	packets, err := parser.decoder.Decode()
	if err != nil {
		log.Printf("Error decoding: %v\n", err)
		return i, c, false
	}

	for _, data := range packets {
		parsed, err := parser.parsePacket(data)
		if err != nil {
			return i, c, false
		}

		if parsed.ID() == packet.IDLogin {
			// This was all we want, we will stop sniffing after this.
			pk := parsed.(*packet.Login)

			_, authenticated, err := login.Verify(pk.ConnectionRequest)
			if err != nil {
				log.Printf("error verifying login request: %v", err)
				return i, c, false
			}
			if !authenticated {
				log.Printf("connection %v was not authenticated to XBOX Live", parser.conn.RemoteAddr())
				return i, c, false
			}

			i, c, err = login.Decode(pk.ConnectionRequest)
			if err != nil {
				log.Printf("error decoding login request: %v", err)
				return i, c, false
			}
			if err := i.Validate(); err != nil {
				log.Printf("invalid identity data: %v", err)
				return i, c, false
			}

			// Commented the check bellow because it doesn't work for PS4, PlatformOnlineID is not UUID format from PS4
			// if err := c.Validate(); err != nil {
			// 	log.Printf("invalid client data: %v", err)
			// 	return i, c, false
			// }
			return i, c, true
		}
	}
	return i, c, false
}

// parsePacket parses a packet from the data passed and returns it, if successful. If the packet could not be
// parsed successfully, nil and an error is returned.
func (parser parser) parsePacket(data []byte) (packet.Packet, error) {
	buf := bytes.NewBuffer(data)
	header := &packet.Header{}
	if err := header.Read(buf); err != nil {
		// We don't return this as an error as it's not in the hand of the user to control this. Instead,
		// we return to reading a new packet.
		return nil, fmt.Errorf("error reading packet header: %v", err)
	}
	// Attempt to fetch the packet with the right packet ID from the pool.
	pk, ok := parser.pool[header.PacketID]
	if !ok {
		// We haven't implemented this packet ID, so we return an unknown packet which could be used by
		// the reader.
		pk = &packet.Unknown{PacketID: header.PacketID}
	}
	var violationErr string

	if err := pk.Unmarshal(buf); err != nil {
		violationErr = fmt.Sprintf("error decoding packet %T from %v: %v", pk, parser.conn.RemoteAddr(), err)
		// We don't return this as an error as it's not in the hand of the user to control this. Instead,
		// we return to reading a new packet.
		return nil, errors.New(violationErr)
	}
	if buf.Len() != 0 {
		violationErr = fmt.Sprintf("%v unread bytes left in packet %T%v from %v: 0x%x (full payload: 0x%x)\n", buf.Len(), pk, fmt.Sprintf("%+v", pk)[1:], parser.conn.RemoteAddr(), buf.Bytes(), data)
		return nil, errors.New(violationErr)
	}
	return pk, nil
}

func acceptLogin(id login.IdentityData, cd login.ClientData) bool {

	blockedOss := map[protocol.DeviceOS]bool{
		// protocol.DeviceAndroid,
		// protocol.DeviceIOS,
		protocol.DeviceOSX: true,
		// protocol.DeviceFireOS,
		// protocol.DeviceGearVR,
		// protocol.DeviceHololens,
		protocol.DeviceWin10: true,
		protocol.DeviceWin32: true,
		// protocol.DeviceDedicated,
		// protocol.DeviceTVOS,
		// protocol.DeviceOrbis,
		protocol.DeviceNX: true,
		// protocol.DeviceXBOX,
	}

	blockedTitleIds := map[string]bool{
		"896928775": true,
	}

	blockedInputModes := map[int]bool{
		1: true,
	}

	if blockedOss[cd.DeviceOS] {
		return false
	}

	if blockedTitleIds[id.TitleID] {
		return false
	}

	if blockedInputModes[cd.DefaultInputMode] {
		return false
	}

	return true
}
