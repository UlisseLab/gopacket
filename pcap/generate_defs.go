// Copyright 2019 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build ignore

package main

// This file generates the godefs needed for the windows version.
// Rebuild is only necessary if additional libpcap functionality is implemented, or a new arch is implemented in golang.
// Call with go run generate_windows.go [-I includepath]
// Needs npcap sdk, go tool cgo, and gofmt to work. Location of npcap includes can be specified with -I

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const header = `// Copyright 2019 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// This file contains necessary structs/constants generated from libpcap headers with cgo -godefs
// generated with: %s
// DO NOT MODIFY

`

const source = `
package pcap

//#include <pcap.h>
import "C"

import "syscall" // needed for RawSockaddr

const errorBufferSize = C.PCAP_ERRBUF_SIZE

const (
	pcapErrorNotActivated    = C.PCAP_ERROR_NOT_ACTIVATED
	pcapErrorActivated       = C.PCAP_ERROR_ACTIVATED
	pcapWarningPromisc       = C.PCAP_WARNING_PROMISC_NOTSUP
	pcapErrorNoSuchDevice    = C.PCAP_ERROR_NO_SUCH_DEVICE
	pcapErrorDenied          = C.PCAP_ERROR_PERM_DENIED
	pcapErrorNotUp           = C.PCAP_ERROR_IFACE_NOT_UP
	pcapError                = C.PCAP_ERROR
	pcapWarning              = C.PCAP_WARNING
	pcapDIN                  = C.PCAP_D_IN
	pcapDOUT                 = C.PCAP_D_OUT
	pcapDINOUT               = C.PCAP_D_INOUT
	pcapNetmaskUnknown       = C.PCAP_NETMASK_UNKNOWN
	pcapTstampPrecisionMicro = C.PCAP_TSTAMP_PRECISION_MICRO
	pcapTstampPrecisionNano  = C.PCAP_TSTAMP_PRECISION_NANO
)

type timeval C.struct_timeval
type pcapPkthdr C.struct_pcap_pkthdr
type pcapTPtr uintptr
type pcapBpfInstruction C.struct_bpf_insn
type pcapBpfProgram C.struct_bpf_program
type pcapStats C.struct_pcap_stat
type pcapCint C.int
type pcapIf C.struct_pcap_if
// +godefs map struct_sockaddr syscall.RawSockaddr
type pcapAddr C.struct_pcap_addr
`

var includes = flag.String("I", "C:\\npcap-sdk-1.01\\Include", "Include path containing libpcap headers")

func main() {
	flag.Parse()

	infile, err := ioutil.TempFile(".", "defs.*.go")
	if err != nil {
		log.Fatal("Couldn't create temporary source file: ", err)
	}
	defer infile.Close()
	defer os.Remove(infile.Name())

	_, err = infile.WriteString(source)
	if err != nil {
		log.Fatalf("Couldn't write definitions to temporary file %s: %s", infile.Name(), err)
	}
	err = infile.Close()
	if err != nil {
		log.Fatalf("Couldn't close temporary source file %s: %s", infile.Name(), err)
	}

	archs := []string{"386", "amd64"}
	for _, arch := range archs {
		env := append(os.Environ(), "GOARCH="+arch)
		cmd := exec.Command("go", "tool", "cgo", "-godefs", "--", "-I", *includes, infile.Name())
		cmd.Env = env
		cmd.Stderr = os.Stderr
		var generated bytes.Buffer
		cmd.Stdout = &generated
		err := cmd.Run()
		if err != nil {
			log.Fatalf("Couldn't generated defs for %s: %s\n", arch, err)
		}

		cmd = exec.Command("gofmt")
		cmd.Env = env
		cmd.Stderr = os.Stderr
		outName := fmt.Sprintf("defs_windows_%s.go", arch)
		out, err := os.Create(outName)
		if err != nil {
			log.Fatalf("Couldn't open file %s: %s", outName, err)
		}
		cmd.Stdout = out
		in, err := cmd.StdinPipe()
		if err != nil {
			log.Fatal("Couldn't create input pipe for gofmt: ", err)
		}
		err = cmd.Start()
		if err != nil {
			log.Fatal("Couldn't start gofmt: ", err)
		}

		_, err = fmt.Fprintf(in, header, strings.Join(append([]string{filepath.Base(os.Args[0])}, os.Args[1:]...), " "))
		if err != nil {
			log.Fatal("Couldn't write header to gofmt: ", err)
		}

		for {
			line, err := generated.ReadBytes('\n')
			if err != nil {
				break
			}
			// remove godefs comments
			if bytes.HasPrefix(line, []byte("//")) {
				continue
			}
			_, err = in.Write(line)
			if err != nil {
				log.Fatal("Couldn't write line to gofmt: ", err)
			}
		}
		in.Close()
		err = cmd.Wait()
		if err != nil {
			log.Fatal("gofmt failed: ", err)
		}
		out.Close()
	}
}
