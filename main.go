package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
    "time"
)

// ENT bits allowed by BIP-39 for 12/18/24 words.
var entBitsForWords = map[int]int{12: 128, 18: 192, 24: 256}

func main() {
	var (
		length   = flag.Int("length", 12, "mnemonic length: 12, 18, or 24")
		wordlist = flag.String("wordlist", "words.txt", "path to BIP-39 English wordlist (2048 words)")
		outPath  = flag.String("out", "valid_mnemonics.log", "file to write mnemonic for eth()")
	)
	flag.Parse()

	// Load wordlist
	words, err := loadWordlist(*wordlist)
	if err != nil {
		log.Fatalf("wordlist error: %v", err)
	}

	// Run indefinitely
	for {
		// === Generate mnemonic ===
		entBits := entBitsForWords[*length]
		mn, err := GenerateMnemonic(entBits, words)
		if err != nil {
			log.Fatalf("generate error: %v", err)
		}

		fmt.Println("Generated mnemonic:", mn)

		// Write to file
		if err := ensureDir(filepath.Dir(*outPath)); err != nil {
			log.Fatalf("cannot create output dir: %v", err)
		}
		if err := os.WriteFile(*outPath, []byte(mn+"\n"), 0600); err != nil {
			log.Fatalf("cannot write mnemonic: %v", err)
		}

		// === Call eth() to check balances ===
		eth()

		// === Clear the file after check ===
		if err := os.Truncate(*outPath, 0); err != nil {
			log.Fatalf("truncate file: %v", err)
		}

		// optional: small delay to avoid spamming RPC too fast
		time.Sleep(2 * time.Second)
	}
}

func ensureDir(dir string) error {
	if dir == "." || dir == "" { // current directory
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

// loadWordlist reads a 2048-line BIP-39 wordlist (English) and returns slice and a map.
func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	// Increase buffer in case of long lines (shouldn't be needed but safe)
	buf := make([]byte, 0, 64*1024)
	s.Buffer(buf, 1024*1024)

	var words []string
	for s.Scan() {
		w := strings.TrimSpace(s.Text())
		if w == "" { // skip empties if any
			continue
		}
		// enforce lowercase and no spaces
		w = strings.ToLower(w)
		if strings.ContainsAny(w, " \t\r\n") {
			return nil, fmt.Errorf("invalid word containing whitespace: %q", w)
		}
		words = append(words, w)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(words) != 2048 {
		return nil, fmt.Errorf("wordlist must contain 2048 words, got %d", len(words))
	}
	return words, nil
}

// GenerateMnemonic creates a BIP-39 mnemonic using ENT entropy bits and the given wordlist.
// ENT must be 128, 192, or 256 for 12, 18, 24 words.
func GenerateMnemonic(entBits int, wordlist []string) (string, error) {
	if entBits%32 != 0 {
		return "", errors.New("ENT must be divisible by 32")
	}
	byteLen := entBits / 8
	entropy := make([]byte, byteLen)
	if _, err := rand.Read(entropy); err != nil {
		return "", fmt.Errorf("entropy: %w", err)
	}
	return mnemonicFromEntropy(entropy, wordlist), nil
}

func mnemonicFromEntropy(entropy []byte, wordlist []string) string {
	entBits := len(entropy) * 8
	csBits := entBits / 32
	h := sha256.Sum256(entropy)

	bits := newBitBuilder(entropy)
	bits.appendBytes(h[:], csBits) // append only csBits of checksum

	indices := bits.split11()
	out := make([]string, len(indices))
	for i, idx := range indices {
		out[i] = wordlist[idx]
	}
	return strings.Join(out, " ")
}

func ValidateMnemonic(mnemonic string, wordlist []string) (bool, string) {
	mnemonic = strings.TrimSpace(mnemonic)
	if mnemonic == "" {
		return false, "empty mnemonic"
	}
	parts := strings.Fields(mnemonic)
	n := len(parts)
	if _, ok := entBitsForWords[n]; !ok {
		return false, fmt.Sprintf("length %d not one of 12/18/24", n)
	}
	// Build reverse index
	idx := make(map[string]int, len(wordlist))
	for i, w := range wordlist {
		idx[w] = i
	}
	//totalBits := n * 11
	src := make([]int, n)
	for i, w := range parts {
		j, ok := idx[w]
		if !ok {
			return false, fmt.Sprintf("word %q not in wordlist", w)
		}
		src[i] = j
	}

	bs := pack11(src)

	entBits := entBitsForWords[n]
	csBits := entBits / 32
	entBytes := entBits / 8

	if len(bs) < entBytes { // should not happen
		return false, "internal: insufficient bytes after packing"
	}
	entropy := bs[:entBytes]
	checksumBits := getBits(bs, entBits, csBits)

	h := sha256.Sum256(entropy)
	ref := getBits(h[:], 0, csBits)
	if checksumBits.Cmp(ref) != 0 {
		return false, "checksum mismatch"
	}
	return true, ""
}

// ---- Bit helpers ----

type bitBuilder struct {
	buf []byte
	bits int
}

func newBitBuilder(entropy []byte) *bitBuilder {
	b := &bitBuilder{buf: make([]byte, len(entropy)), bits: len(entropy) * 8}
	copy(b.buf, entropy)
	return b
}

func (b *bitBuilder) appendBytes(src []byte, nbits int) {
	if nbits == 0 {
		return
	}
	for i := 0; i < nbits; i++ {
		bit := (src[i/8] >> (7 - (i % 8))) & 1
		b.pushBit(bit == 1)
	}
}

func (b *bitBuilder) pushBit(one bool) {
	// Ensure capacity
	if b.bits%8 == 0 {
		b.buf = append(b.buf, 0)
	}
	if one {
		byteIndex := b.bits / 8
		bitPos := 7 - (b.bits % 8)
		b.buf[byteIndex] |= (1 << bitPos)
	}
	b.bits++
}

func (b *bitBuilder) split11() []int {
	n := b.bits / 11
	out := make([]int, n)
	// Read consecutive 11-bit values
	for i := 0; i < n; i++ {
		val := getBits(b.buf, i*11, 11)
		out[i] = int(val.Int64())
	}
	return out
}

func getBits(buf []byte, startBit, nbits int) *big.Int {
	v := big.NewInt(0)
	for i := 0; i < nbits; i++ {
		bit := (buf[(startBit+i)/8] >> (7 - ((startBit + i) % 8))) & 1
		v.Lsh(v, 1)
		if bit == 1 {
			v.Or(v, big.NewInt(1))
		}
	}
	return v
}

func pack11(indices []int) []byte {
	// total bits
	total := len(indices) * 11
	out := make([]byte, (total+7)/8)
	bitPos := 0
	for _, v := range indices {
		for i := 10; i >= 0; i-- { // MSB first
			bit := (v >> i) & 1
			byteIndex := bitPos / 8
			shift := 7 - (bitPos % 8)
			out[byteIndex] |= byte(bit << shift)
			bitPos++
		}
	}
	return out
}

