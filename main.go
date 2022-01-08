package main

import (
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strings"
	"sync"

	"github.com/golang/snappy"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
)

const ext = ".fcle"

const chunkSize = 2 << 16

func main() {
	enc := flag.Bool("enc", false, "encrypt mode")
	dec := flag.Bool("dec", false, "decrypt mode")
	password := flag.String("pw", "1q2w3e4r", "password")
	filename := flag.String("file", "", "filename")

	flag.Parse()

	if *filename == "" {
		fmt.Println("filename not specified")
		os.Exit(1)
	}

	if *enc && *dec {
		fmt.Println("cannot be both encrypt and decrypt")
		os.Exit(1)
	}

	if *enc {
		fmt.Println("encrypt mode")

		from, err := os.Open(*filename)
		if err != nil {
			fmt.Println("error open input file")
			os.Exit(1)
		}

		readPipe, writePipe, err := os.Pipe()
		if err != nil {
			fmt.Println("error creating pipe")
			os.Exit(1)
		}

		to, err := os.Create(*filename + ext)
		if err != nil {
			fmt.Println("error creating output file")
			os.Exit(1)
		}

		wg := new(sync.WaitGroup)
		wg.Add(2)

		go func() {
			if err := encrypt(from, writePipe, *password); err != nil {
				fmt.Println("error encrypting")
				fmt.Println(err)
				os.Exit(1)
			}
			writePipe.Close()
			wg.Done()
		}()
		go func() {
			if err := compress(readPipe, to); err != nil {
				fmt.Println("error compressing")
				fmt.Println(err)
				os.Exit(1)
			}
			readPipe.Close()
			wg.Done()
		}()

		wg.Wait()

		return
	}

	if *dec {
		fmt.Println("decrypt mode")

		from, err := os.Open(*filename)
		if err != nil {
			fmt.Println("error open input file")
			os.Exit(1)
		}

		readPipe, writePipe, err := os.Pipe()
		if err != nil {
			fmt.Println("error creating pipe")
			os.Exit(1)
		}

		to, err := os.Create(strings.TrimSuffix(*filename, ext))
		if err != nil {
			fmt.Println("error creating output file")
			os.Exit(1)
		}

		wg := new(sync.WaitGroup)
		wg.Add(2)

		go func() {
			if err := uncompress(from, writePipe); err != nil {
				fmt.Println("error uncompressing")
				fmt.Println(err)
				os.Exit(1)
			}
			writePipe.Close()
			wg.Done()
		}()
		go func() {
			if err := decrypt(readPipe, to, *password); err != nil {
				fmt.Println("error decrypting")
				fmt.Println(err)
				os.Exit(1)
			}
			readPipe.Close()
			wg.Done()
		}()

		wg.Wait()

		return
	}
}

func compress(from io.Reader, to io.Writer) error {
	sw := snappy.NewWriter(to)
	buf := [chunkSize]byte{}

	for {
		n, err := from.Read(buf[:])
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if _, err := sw.Write(buf[:n]); err != nil {
			return err
		}
	}

	return nil
}

func uncompress(from io.Reader, to io.Writer) error {
	sr := snappy.NewReader(from)
	buf := [chunkSize]byte{}

	for {
		n, err := sr.Read(buf[:])
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if _, err := to.Write(buf[:n]); err != nil {
			return err
		}
	}

	return nil
}

func encrypt(src io.Reader, dst io.Writer, password string) error {
	nonce := make([]byte, chacha20.NonceSizeX)
	rand.Read(nonce)
	if _, err := dst.Write(nonce); err != nil {
		return err
	}

	hashed := blake2b.Sum256([]byte(password))
	cipher, err := chacha20.NewUnauthenticatedCipher(hashed[:], nonce)
	if err != nil {
		return err
	}

	from := make([]byte, chunkSize)
	to := make([]byte, chunkSize)

	for {
		n, err := src.Read(from)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		cipher.XORKeyStream(to, from[:n])
		if _, err := dst.Write(to[:n]); err != nil {
			return err
		}
	}

	return nil
}

func decrypt(src io.Reader, dst io.Writer, password string) error {
	nonce := make([]byte, chacha20.NonceSizeX)
	if _, err := src.Read(nonce); err != nil {
		return err
	}

	hashed := blake2b.Sum256([]byte(password))
	cipher, err := chacha20.NewUnauthenticatedCipher(hashed[:], nonce)
	if err != nil {
		return err
	}

	from := make([]byte, chunkSize)
	to := make([]byte, chunkSize)

	for {
		n, err := src.Read(from)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		cipher.XORKeyStream(to, from[:n])
		if err != nil {
			return err
		}
		if _, err := dst.Write(to[:n]); err != nil {
			return err
		}
	}

	return nil
}
