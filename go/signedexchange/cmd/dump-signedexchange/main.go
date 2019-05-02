package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/WICG/webpackage/go/signedexchange"
)

var (
	flagInput     = flag.String("i", "", "Signed-exchange input file")
	flagURI       = flag.String("u", "", "Signed-exchange uri")
	flagSignature = flag.Bool("signature", false, "Print signature value")
	flagVerify    = flag.Bool("verify", false, "Perform signature verification")
	flagCert      = flag.String("cert", "", "Certificate CBOR file. If specified, used instead of fetching from signature's cert-url")
	flagHeaders   = flag.Bool("headers", true, "Print headers")
	flagPayload   = flag.Bool("payload", false, "Print payload")
)

func run() error {
	var e *signedexchange.Exchange
	if *flagInput != "" {
		in, err := os.Open(*flagInput)
		if err != nil {
			return err
		}
		defer in.Close()
		e, err = signedexchange.ReadExchange(in)
		if err != nil {
			return err
		}
	} else if *flagURI != "" {
		client := http.DefaultClient
		req, err := http.NewRequest("GET", *flagURI, nil)
		req.Header.Add("Accept", "application/signed-exchange;v=b3")
		req.Header.Add("AMP-Cache-Transform", "google;v=1")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		e, err = signedexchange.ReadExchange(resp.Body)
		if err != nil {
			return err
		}
	}
	if e != nil {
		if *flagHeaders {
			e.PrettyPrintHeaders(os.Stdout)
		}

		if *flagPayload {
			e.PrettyPrintPayload(os.Stdout)
		}

		if *flagSignature {
			fmt.Println(e.SignatureHeaderValue)
		}

		if *flagVerify {
			fmt.Println()
			if err := verify(e); err != nil {
				return err
			}
		}
	} else {
		fmt.Println("Need to pass -u with URI of sxg or -i with file location of sxg")
	}

	return nil
}

func verify(e *signedexchange.Exchange) error {
	certFetcher := signedexchange.DefaultCertFetcher
	if *flagCert != "" {
		f, err := os.Open(*flagCert)
		if err != nil {
			return fmt.Errorf("could not open %s: %v\n", *flagCert, err)
		}
		defer f.Close()
		certBytes, err := ioutil.ReadAll(f)
		if err != nil {
			return fmt.Errorf("Could not read %s: %v\n", *flagCert, err)
		}
		certFetcher = func(_ string) ([]byte, error) {
			return certBytes, nil
		}
	}

	verificationTime := time.Now()
	if decodedPayload, ok := e.Verify(verificationTime, certFetcher, log.New(os.Stdout, "", 0)); ok {
		e.Payload = decodedPayload
		fmt.Println("The exchange has a valid signature.")
	}
	return nil
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
