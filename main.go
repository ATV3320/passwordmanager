package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	mathrand "math/rand"
	"os"
	"time"
	"unicode"

	"golang.org/x/term"
)

// Password data structure to hold password details
type PasswordData struct {
	Username       string `json:"username"`
	Website        string `json:"website"`
	HashedPassword string `json:"hashed_password"`
	Encrypted      bool   `json:"encrypted"`
}

func generatePassword(username, website string, length int, key []byte) (string, error) {
	if length < 8 { // Minimum length for security
		return "", fmt.Errorf("password length must be at least 8 characters")
	}

	// Generate random bytes
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("error generating random bytes: %v", err)
	}

	// Create initial hash
	h := sha256.New()
	h.Write([]byte(username + website + hex.EncodeToString(randomBytes)))
	hash := h.Sum(nil)

	// Extract alphanumeric characters to reach desired length - 3
	// (reserving space for required characters)
	alphanum := ""
	for _, ch := range hash {
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			alphanum += string(ch)
		}
		if len(alphanum) >= length-3 {
			break
		}
	}
	alphanum = alphanum[:length-3] // Ensure exact length minus required characters

	// Add required characters
	// 1. Number
	numbers := "0123456789"
	numIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(numbers))))
	requiredNum := string(numbers[numIndex.Int64()])

	// 2. Symbol
	symbols := "!@#$%^&*"
	symIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(symbols))))
	requiredSymbol := string(symbols[symIndex.Int64()])

	// 3. Uppercase letter if not present
	hasUpper := false
	for _, ch := range alphanum {
		if unicode.IsUpper(ch) {
			hasUpper = true
			break
		}
	}
	positions := mathrand.New(mathrand.NewSource(time.Now().UnixNano())).Perm(length)
	// positions := rand.New(rand.NewSource(time.Now().UnixNano())).Perm(length)
	// positions := rand.Perm(length)
	result := make([]rune, length)

	// Fill with base password
	for i := 0; i < len(alphanum); i++ {
		result[positions[i]] = rune(alphanum[i])
	}

	// Add required characters
	result[positions[len(positions)-1]] = rune(requiredSymbol[0])
	result[positions[len(positions)-2]] = rune(requiredNum[0])

	if !hasUpper {
		// Convert one lowercase to uppercase if no uppercase exists
		for i, ch := range result {
			if unicode.IsLower(ch) {
				result[i] = unicode.ToUpper(ch)
				break
			}
		}
	}

	// Convert back to string
	finalPassword := string(result)

	// Encrypt the password
	encryptedPassword, err := encryptPasswordWithAES(finalPassword, key)
	if err != nil {
		return "", fmt.Errorf("error encrypting password: %v", err)
	}

	return encryptedPassword, nil
}

// Function to apply PKCS7 padding
func pkcs7Pad(data []byte, blockSize int) []byte {
	// Calculate the number of bytes needed to reach the next multiple of blockSize
	paddingLen := blockSize - len(data)%blockSize
	// Create padding of the required length (value is the number of padding bytes)
	padding := bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)
	// Return the data with the padding added
	return append(data, padding...)
}

// Unpad function to remove PKCS7 padding
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	paddingLen := int(data[len(data)-1]) // The padding length is the last byte
	if paddingLen > blockSize || paddingLen > len(data) {
		return nil, fmt.Errorf("invalid padding length")
	}
	return data[:len(data)-paddingLen], nil
}

func encryptPasswordWithAES(password string, key []byte) (string, error) {
	// Ensure key is 16 bytes long by truncating or padding
	if len(key) > 16 {
		key = key[:16] // Truncate to 16 bytes if too long
	} else if len(key) < 16 {
		key = append(key, make([]byte, 16-len(key))...) // Pad to 16 bytes if too short
	}

	// Pad plaintext to a multiple of the AES block size (16 bytes)
	paddedPassword := pkcs7Pad([]byte(password), aes.BlockSize)

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("error creating cipher block: %v", err)
	}

	// Initialize ciphertext slice
	ciphertext := make([]byte, len(paddedPassword))

	// Create a new CBC encrypter
	cipher.NewCBCEncrypter(block, key[:aes.BlockSize]).CryptBlocks(ciphertext, paddedPassword)

	// Return the encrypted password as a hex string
	return fmt.Sprintf("%x", ciphertext), nil
}

func storePasswordData(filename string, username, website, password string, encrypted bool) error {
	// Load existing data from file
	var data []PasswordData
	fileContent, err := os.ReadFile(filename)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error reading file: %v", err)
	}
	// Decode existing data if present, else start with an empty array
	fmt.Println("current filecontent size:", len(fileContent))
	if len(fileContent) > 5 {
		if err := json.Unmarshal(fileContent, &data); err != nil {
			return fmt.Errorf("error unmarshalling data: %v", err)
		}
	}

	// Append new password data
	data = append(data, PasswordData{
		Username:       username,
		Website:        website,
		HashedPassword: password,
		Encrypted:      encrypted,
	})
	// Write the updated data back to the file
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	// Ensure the data is written as an array (even if it's the first entry)
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("error encoding data: %v", err)
	}

	return nil
}

func decryptPasswordWithAES(hexCiphertext []byte, key []byte) (string, error) {
	// Convert hex string to bytes
	ciphertext := make([]byte, hex.DecodedLen(len(hexCiphertext)))
	_, err := hex.Decode(ciphertext, hexCiphertext)
	if err != nil {
		return "", fmt.Errorf("error decoding hex: %v", err)
	}

	// Ensure key is 16 bytes
	if len(key) > 16 {
		key = key[:16]
	} else if len(key) < 16 {
		key = append(key, make([]byte, 16-len(key))...)
	}

	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("error creating cipher block: %v", err)
	}

	// Create CBC decrypter
	mode := cipher.NewCBCDecrypter(block, key[:aes.BlockSize])
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove padding
	unpadded, err := pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return "", fmt.Errorf("error removing padding: %v", err)
	}

	return string(unpadded), nil
}

func getHiddenInput(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	input, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	return input, nil
}

func fetchPassword(filename, website string) (string, error) {
	// Load existing data from file
	var data []PasswordData
	fileContent, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("error reading file: %v", err)
	}

	// Decode existing data
	if len(fileContent) > 0 {
		if err := json.Unmarshal(fileContent, &data); err != nil {
			return "", fmt.Errorf("error unmarshalling data: %v", err)
		}
	}

	// Find the password for the specified website
	for _, entry := range data {
		if entry.Website == website {
			return entry.HashedPassword, nil
		}
	}

	return "", fmt.Errorf("password for website '%s' not found", website)
}

func main() {
	filename := "passwordsss.json"

	// Command-line flags
	username := flag.String("u", "", "Username for the platform")
	website := flag.String("w", "", "Website for the platform")
	length := flag.Int("l", 12, "Length of the password")
	fetch := flag.Bool("fetch", false, "Fetch the password for a website")
	decrypt := flag.Bool("decrypt", false, "Decrypt the password for a website") // Add flag for decryption
	flag.Parse()

	if *website == "" {
		fmt.Println("Website (-w) is required")
		os.Exit(1)
	}

	if *fetch {
		// Fetch the password for the website
		password, err := fetchPassword(filename, *website)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("Fetched password: %s\n", password)
		return
	}

	if *decrypt {
		// Decrypt the password for the website
		// Fetch the encrypted password first
		password, err := fetchPassword(filename, *website)
		if err != nil {
			fmt.Println(err)
			return
		}

		// Get the master password
		masterPasswordInput, err := getHiddenInput("Enter the master password to decrypt: ")
		if err != nil {
			fmt.Println("Error reading master password:", err)
			return
		}

		// Hash the master password
		key := sha256.Sum256(masterPasswordInput)

		// Decrypt the password
		decryptedPassword, err := decryptPasswordWithAES([]byte(password), key[:aes.BlockSize])
		if err != nil {
			fmt.Println("Error decrypting password:", err)
			return
		}

		fmt.Printf("Decrypted Password: %s\n", decryptedPassword)
		return
	}

	if *username == "" {
		fmt.Println("Username (-u) is required")
		os.Exit(1)
	}

	// Get the master password
	masterPasswordInput, err := getHiddenInput("Enter the master password: ")
	if err != nil {
		fmt.Println("Error reading master password:", err)
		return
	}
	masterPassword := masterPasswordInput

	// Check that master password is not empty
	if len(masterPassword) == 0 {
		fmt.Println("Master password cannot be empty")
		return
	}

	// Generate password and hash it
	key := sha256.Sum256(masterPassword)
	password, err := generatePassword(*username, *website, *length, key[:])
	if err != nil {
		fmt.Printf("Error generating password: %v\n", err)
		return
	}

	// Store password data
	err = storePasswordData(filename, *username, *website, password, true)
	if err != nil {
		fmt.Printf("Error storing password: %v\n", err)
		return
	}

	fmt.Printf("Password generated and stored successfully.\n")
	// if *showPassword {
	// 	fmt.Printf("Generated password: %s\n", password)
	// }
}

// func main() {
// 	filename := "passwordsss.json"

// 	// Command-line flags
// 	username := flag.String("u", "", "Username for the platform")
// 	website := flag.String("w", "", "Website for the platform")
// 	length := flag.Int("l", 12, "Length of the password")
// 	fetch := flag.Bool("fetch", false, "Fetch the password for a website")
// 	flag.Parse()

// 	if *website == "" {
// 		fmt.Println("Website (-w) is required")
// 		os.Exit(1)
// 	}

// 	if *fetch {
// 		// Fetch the password for the website
// 		password, err := fetchPassword(filename, *website)
// 		if err != nil {
// 			fmt.Println(err)
// 			return
// 		}
// 		fmt.Printf("Fetched password: %s\n", password)
// 		return
// 	}

// 	if *username == "" {
// 		fmt.Println("Username (-u) is required")
// 		os.Exit(1)
// 	}

// 	// Get the master password
// 	masterPasswordInput, err := getHiddenInput("Enter the master password: ")
// 	if err != nil {
// 		fmt.Println("Error reading master password:", err)
// 		return
// 	}
// 	masterPassword := masterPasswordInput

// 	// Check that master password is not empty
// 	if len(masterPassword) == 0 {
// 		fmt.Println("Master password cannot be empty")
// 		return
// 	}

// 	// Generate password and hash it
// 	key := sha256.Sum256(masterPassword)
// 	password, _ := generatePassword(*username, *website, *length, key[:])

// 	// Store password data (encrypted)
// 	err = storePasswordData(filename, *username, *website, password, true)
// 	if err != nil {
// 		fmt.Println("Error storing password:", err)
// 	}

// 	// Display the generated password
// 	fmt.Printf("Generated Password: %s\n", password)
// }
