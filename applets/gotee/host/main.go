// Normal World host for the GoTEE ZK proof verifier trusted applet.
//
// Reads proof, VK, public inputs, and VK hash from the filesystem,
// packs them into the shared-memory wire protocol, invokes the Secure
// World applet via GoTEE's RPC mechanism, and prints the result.
//
// Usage:
//
//	go run main.go -p <proof> -k <vk> -i <public_inputs>
//
// Exit codes:
//
//	0  VALID
//	1  INVALID or ERROR
//	2  usage error
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	// GoTEE Normal World API — import path will be:
	//   github.com/usbarmory/GoTEE/applet
	// Placeholder until GoTEE supervisor integration is wired up.
	// "github.com/usbarmory/GoTEE/applet"
)

const (
	cmdVerify   uint32 = 1
	headerSize         = 20

	statusValid   int32 = 1
	statusInvalid int32 = 0
	// statusError int32 = -1
)

func main() {
	proofPath := flag.String("p", "", "Path to the proof file")
	vkPath := flag.String("k", "", "Path to the verification key file")
	piPath := flag.String("i", "", "Path to the public inputs file")
	flag.Parse()

	if *proofPath == "" || *vkPath == "" || *piPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: host -p <proof> -k <vk> -i <public_inputs>")
		os.Exit(2)
	}

	proof, err := os.ReadFile(*proofPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read proof: %v\n", err)
		os.Exit(2)
	}

	vk, err := os.ReadFile(*vkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read VK: %v\n", err)
		os.Exit(2)
	}

	pi, err := os.ReadFile(*piPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read public inputs: %v\n", err)
		os.Exit(2)
	}

	// Read VK hash from sibling file (optional)
	vkHashPath := filepath.Join(filepath.Dir(*vkPath), "vk_hash")
	vkHash, _ := os.ReadFile(vkHashPath) // nil if missing

	// Build the shared-memory request buffer
	totalPayload := len(proof) + len(vk) + len(pi) + len(vkHash)
	buf := make([]byte, headerSize+totalPayload)

	binary.LittleEndian.PutUint32(buf[0:4], cmdVerify)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(len(proof)))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(vk)))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(len(pi)))
	binary.LittleEndian.PutUint32(buf[16:20], uint32(len(vkHash)))

	off := headerSize
	copy(buf[off:], proof)
	off += len(proof)
	copy(buf[off:], vk)
	off += len(vk)
	copy(buf[off:], pi)
	off += len(pi)
	copy(buf[off:], vkHash)

	// ---------------------------------------------------------------
	// TODO: Replace this section with GoTEE RPC invocation once the
	// supervisor integration is complete. The call would be:
	//
	//   resp, err := applet.Call(buf)
	//
	// For now we just print the buffer size to confirm packing works.
	// ---------------------------------------------------------------
	fmt.Fprintf(os.Stderr, "Request buffer: %d bytes (header %d + payload %d)\n",
		len(buf), headerSize, totalPayload)

	// Simulated response — in production this comes from Secure World
	status := readStatus(buf[:4]) // placeholder: read back our own header
	_ = status

	// When GoTEE RPC is wired up, uncomment:
	// status := readStatus(resp)
	// if status == statusValid {
	//     fmt.Println("VALID")
	//     os.Exit(0)
	// }
	// fmt.Fprintln(os.Stderr, "INVALID")
	// os.Exit(1)

	fmt.Println("GoTEE host: request packed, awaiting supervisor integration")
}

func readStatus(resp []byte) int32 {
	if len(resp) < 4 {
		return -1
	}
	return int32(binary.LittleEndian.Uint32(resp[0:4]))
}
