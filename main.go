package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/golang/snappy"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const ext = ".fcle"

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
	buf := [4096]byte{}

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
	buf := [4096]byte{}

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
	hashed := blake2b.Sum256([]byte(password))
	aead, err := chacha20poly1305.NewX(hashed[:])
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	copy(nonce, hashed[:])

	for {
		buf := make([]byte, 4096)
		n, err := src.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if _, err := dst.Write(aead.Seal(nil, nonce, buf[:n], nil)); err != nil {
			return err
		}
	}

	return nil
}

func decrypt(src io.Reader, dst io.Writer, password string) error {
	hashed := blake2b.Sum256([]byte(password))
	aead, err := chacha20poly1305.NewX(hashed[:])
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	copy(nonce, hashed[:])

	for {
		buf := make([]byte, 4096)
		n, err := src.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		plain, err := aead.Open(nil, nonce, buf[:n], nil)
		if err != nil {
			return err
		}
		if _, err := dst.Write(plain); err != nil {
			return err
		}
	}

	return nil
}
