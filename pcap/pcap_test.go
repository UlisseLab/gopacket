// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcap

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestPcapNonexistentFile(t *testing.T) {
	handle, err := OpenOffline("/path/to/nonexistent/file")
	if err == nil {
		t.Error("No error returned for nonexistent file open")
	} else {
		t.Logf("Error returned for nonexistent file: %v", err)
	}
	if handle != nil {
		t.Error("Non-nil handle returned for nonexistent file open")
	}
}

func TestPcapFileRead(t *testing.T) {
	invalidData := []byte{
		0xAB, 0xAD, 0x1D, 0xEA,
	}

	invalidPcap, err := ioutil.TempFile("", "invalid.pcap")
	if err != nil {
		t.Fatal(err)
	}
	invalidPcap.Close() // if the file is still open later, the invalid test fails with permission denied on windows
	defer os.Remove(invalidPcap.Name())

	err = ioutil.WriteFile(invalidPcap.Name(), invalidData, 0644)
	if err != nil {
		t.Fatal(err)
	}

	for _, file := range []struct {
		filename       string
		num            int
		expectedLayers []gopacket.LayerType
		err            string
	}{
		{filename: "test_loopback.pcap",
			num: 24,
			expectedLayers: []gopacket.LayerType{
				layers.LayerTypeLoopback,
				layers.LayerTypeIPv6,
				layers.LayerTypeTCP,
			},
		},
		{filename: "test_ethernet.pcap",
			num: 10,
			expectedLayers: []gopacket.LayerType{
				layers.LayerTypeEthernet,
				layers.LayerTypeIPv4,
				layers.LayerTypeTCP,
			},
		},
		{filename: "test_dns.pcap",
			num: 10,
			expectedLayers: []gopacket.LayerType{
				layers.LayerTypeEthernet,
				layers.LayerTypeIPv4,
				layers.LayerTypeUDP,
				layers.LayerTypeDNS,
			},
		},
		{filename: invalidPcap.Name(),
			num: 0,
			err: "unknown file format",
		},
	} {
		t.Logf("\n\n\n\nProcessing file %s\n\n\n\n", file.filename)

		packets := []gopacket.Packet{}
		if handle, err := OpenOffline(file.filename); err != nil {
			if file.err != "" {
				if err.Error() != file.err {
					t.Errorf("expected message %q; got %q", file.err, err.Error())
				}
			} else {
				t.Fatal(err)
			}
		} else {
			if file.err != "" {
				t.Fatalf("Expected error, got none")
			}
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				packets = append(packets, packet)
			}
		}
		if len(packets) != file.num {
			t.Fatal("Incorrect number of packets, want", file.num, "got", len(packets))
		}
		for i, p := range packets {
			t.Log(p.Dump())
			for _, layertype := range file.expectedLayers {
				if p.Layer(layertype) == nil {
					t.Fatal("Packet", i, "has no layer type\n%s", layertype, p.Dump())
				}
			}
		}
	}
}

func TestBPF(t *testing.T) {
	handle, err := OpenOffline("test_ethernet.pcap")
	if err != nil {
		t.Fatal(err)
	}

	for _, expected := range []struct {
		expr   string
		Error  bool
		Result bool
	}{
		{"foobar", true, false},
		{"tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)", false, true},
		{"tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-ack", false, true},
		{"udp", false, false},
		{string([]byte("udp")), false, false}, // test for #664
	} {
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			t.Fatal(err)
		}
		t.Log("Testing filter", expected.expr)
		if bpf, err := handle.NewBPF(expected.expr); err != nil {
			if !expected.Error {
				t.Error(err, "while compiling filter was unexpected")
			}
		} else if expected.Error {
			t.Error("expected error but didn't see one")
		} else if matches := bpf.Matches(ci, data); matches != expected.Result {
			t.Error("Filter result was", matches, "but should be", expected.Result)
		}
	}
}

func TestBPFInstruction(t *testing.T) {
	handle, err := OpenOffline("test_ethernet.pcap")
	if err != nil {
		t.Fatal(err)
	}

	oversizedBpfInstructionBuffer := [MaxBpfInstructions + 1]BPFInstruction{}

	tests := []struct {
		Instructions []BPFInstruction
		Error        bool
		Result       bool
	}{
		// Invalid filter: empty instruction set
		{nil, true, false},

		// Valid filter: tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)
		{[]BPFInstruction{
			{0x28, 0, 0, 0x0000000c},
			{0x15, 0, 9, 0x00000800},
			{0x30, 0, 0, 0x00000017},
			{0x15, 0, 7, 0x00000006},
			{0x28, 0, 0, 0x00000014},
			{0x45, 5, 0, 0x00001fff},
			{0xb1, 0, 0, 0x0000000e},
			{0x50, 0, 0, 0x0000001b},
			{0x54, 0, 0, 0x00000012},
			{0x15, 0, 1, 0x00000012},
			{0x6, 0, 0, 0x0000ffff},
			{0x6, 0, 0, 0x00000000},
		}, false, true},

		// Valid filter: tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-ack
		{[]BPFInstruction{
			{0x28, 0, 0, 0x0000000c},
			{0x15, 0, 9, 0x00000800},
			{0x30, 0, 0, 0x00000017},
			{0x15, 0, 7, 0x00000006},
			{0x28, 0, 0, 0x00000014},
			{0x45, 5, 0, 0x00001fff},
			{0xb1, 0, 0, 0x0000000e},
			{0x50, 0, 0, 0x0000001b},
			{0x54, 0, 0, 0x00000012},
			{0x15, 0, 1, 0x00000010},
			{0x6, 0, 0, 0x0000ffff},
			{0x6, 0, 0, 0x00000000},
		}, false, true},

		// Valid filter: udp
		{[]BPFInstruction{
			{0x28, 0, 0, 0x0000000c},
			{0x15, 0, 2, 0x00000800},
			{0x30, 0, 0, 0x00000017},
			{0x15, 6, 7, 0x00000011},
			{0x15, 0, 6, 0x000086dd},
			{0x30, 0, 0, 0x00000014},
			{0x15, 3, 0, 0x00000011},
			{0x15, 0, 3, 0x0000002c},
			{0x30, 0, 0, 0x00000036},
			{0x15, 0, 1, 0x00000011},
			{0x6, 0, 0, 0x0000ffff},
			{0x6, 0, 0, 0x00000000},
		}, false, false},

		// Oversized instruction buffer
		{oversizedBpfInstructionBuffer[:], true, false},
	}

	for i, test := range tests {
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("Testing NewBPFInstructionFilter case %d", i)
		bpf, err := handle.NewBPFInstructionFilter(test.Instructions)
		if err != nil {
			if !test.Error {
				t.Errorf("unexpected error: %v", err)
			}
			continue
		}
		if test.Error {
			t.Error("expected error but didn't see one")
			continue
		}
		if matches := bpf.Matches(ci, data); matches != test.Result {
			t.Errorf("Filter result was %v but should be %v", matches, test.Result)
		}
	}
}

func TestBPFInstructionCorrespondenceToTcpdump(t *testing.T) {

	cases := []struct {
		Filter string
	}{
		{"tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)"},
		{"tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-ack"},
		{"udp"},
	}

	for i, c := range cases {
		out, err := exec.Command("tcpdump", "-ddd", "--snapshot-length", "65535", c.Filter).Output()
		if err != nil {
			t.Errorf("tcpdump -ddd %q failed: %v", c.Filter, err)
			continue
		}

		outString := string(out)
		t.Logf("tcpdump -ddd output for %q:\n%s", c.Filter, outString)

		var expectedBpf []BPFInstruction
		lines := strings.FieldsFunc(outString, func(c rune) bool { return c == '\n' || c == '\r' })
		if len(lines) == 0 {
			t.Errorf("tcpdump -ddd %q returned no output", c.Filter)
			continue
		}
		// The first line is the number of instructions
		numInstr := 0
		if _, err := fmt.Sscanf(lines[0], "%d", &numInstr); err != nil {
			t.Errorf("failed to parse instruction count from tcpdump -ddd output line %q: %v", lines[0], err)
			continue
		}
		if numInstr != len(lines)-1 {
			t.Errorf("tcpdump -ddd %q: expected %d instructions, got %d", c.Filter, numInstr, len(lines)-1)
			continue
		}
		for _, line := range lines[1:] {
			var bpf BPFInstruction
			if _, err := fmt.Sscanf(line, "%d %d %d %d", &bpf.Code, &bpf.Jt, &bpf.Jf, &bpf.K); err != nil {
				t.Errorf("failed to parse tcpdump -ddd output line %q: %v", line, err)
				continue
			}
			expectedBpf = append(expectedBpf, bpf)
		}

		bpf, err := CompileBPFFilter(layers.LinkTypeEthernet, 65535, c.Filter)
		if err != nil {
			t.Errorf("CompileBPFFilter(%q) error: %v", c.Filter, err)
			continue
		}
		if len(bpf) != len(expectedBpf) {
			t.Errorf("case %d: CompileBPFFilter: expected %d instructions, got %d", i, len(expectedBpf), len(bpf))
			continue
		}
		for j := range bpf {
			if bpf[j] != expectedBpf[j] {
				t.Errorf("case %d: CompileBPFFilter instruction %d: expected %+v, got %+v", i, j, expectedBpf[j], bpf[j])
			}
		}
	}
}

func ExampleBPF() {
	handle, err := OpenOffline("test_ethernet.pcap")
	if err != nil {
		log.Fatal(err)
	}
	synack, err := handle.NewBPF("tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)")
	if err != nil {
		log.Fatal(err)
	}
	syn, err := handle.NewBPF("tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn")
	if err != nil {
		log.Fatal(err)
	}
	for {
		data, ci, err := handle.ReadPacketData()
		switch {
		case err == io.EOF:
			return
		case err != nil:
			log.Fatal(err)
		case synack.Matches(ci, data):
			fmt.Println("SYN/ACK packet")
		case syn.Matches(ci, data):
			fmt.Println("SYN packet")
		default:
			fmt.Println("SYN flag not set")
		}
	}
	// Output:
	// SYN packet
	// SYN/ACK packet
	// SYN flag not set
	// SYN flag not set
	// SYN flag not set
	// SYN flag not set
	// SYN flag not set
	// SYN flag not set
	// SYN flag not set
	// SYN flag not set
}
