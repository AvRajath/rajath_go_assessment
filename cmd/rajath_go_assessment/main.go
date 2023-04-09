package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

func scanHostPort(host string, port int) {

	fmt.Printf(fmt.Sprintf("%s\n", strings.Repeat("-", 70)))

	target := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("Failed to connect %s\n", err.Error())
		return
	}

	handshakePacket := &InitialHandshakePacket{}
	err = handshakePacket.Decode(conn)
	if err != nil {
		log.Printf("Failed to decode packet: %s\n", err.Error())
		return
	}

	fmt.Printf("%s\n", target)
	fmt.Printf(handshakePacket.GetPacketInfo())
}

func main() {

	if len(os.Args) != 3 {
		fmt.Println("Usage: ./bin/rajath_go_assessment hostname port_number")
		return
	}

	flag.Parse()
	host := flag.Arg(0)
	port, err := strconv.Atoi(flag.Arg(1))
	if err != nil {
		os.Exit(-1)
	}
	scanHostPort(host, port)
	return

}
