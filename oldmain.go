// package main

// import (
// 	"crypto/aes"
// 	"crypto/rand"
// 	"crypto/sha256"
// 	"encoding/hex"
// 	"encoding/json"
// 	"flag"
// 	"fmt"
// 	"math/big"
// 	"os"
// 	// "syscall"
// 	"unicode"

// 	"golang.org/x/term"

// 	// "reflect"
// 	"strconv"
// 	// "unicode"
// )

// // func generatePassword(username, website string, length int) string {
// // 	// Simulate password generation logic here

// // 	randomBytes := make([]byte, 16)
// // 	_, err := rand.Read(randomBytes)
// // 	if err != nil {
// // 		fmt.Println("Error generating random bytes:", err)
// // 		return ""
// // 	}
// // 	fullString := username + website + hex.EncodeToString(randomBytes)
// // 	h := sha256.New()

// // 	h.Write([]byte(fullString))
// // 	hash := h.Sum(nil)
// // 	fmt.Println("hash is: ", fmt.Sprintf("%x", hash))
// // 	lenstr := (len(username+website) + 149) % 100
// // 	fmt.Println("lenstr is: ", lenstr)
// // 	alphanum := ""
// // 	for _, ch := range hash {
// // 		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
// // 			alphanum += string(ch)
// // 			// fmt.Println("the real truth", reflect.TypeOf(ch))
// // 		}
// // 		if len(alphanum) == length {
// // 			break
// // 		}
// // 	}
// // 	middleIndex := len(alphanum) / 2
// // 	alphanum = alphanum[:middleIndex] + strconv.Itoa(lenstr) + alphanum[middleIndex:]
// // 	fmt.Println("alphanum is: ", alphanum)
// // 	return fmt.Sprintf("GeneratedPasswordFor%s@%s", username, website)
// // }

// func generatePassword(username, website string, length int, key []byte) string {
// 	if length < 4 { // Minimum length to ensure uppercase, lowercase, digit, and symbol
// 		fmt.Println("Password length must be at least 4")
// 		return ""
// 	}

// 	// Generate random bytes
// 	randomBytes := make([]byte, 16)
// 	_, err := rand.Read(randomBytes)
// 	if err != nil {
// 		fmt.Println("Error generating random bytes:", err)
// 		return ""
// 	}
// 	fullString := username + website + hex.EncodeToString(randomBytes)
// 	h := sha256.New()

// 	// Create a hash of the full string
// 	h.Write([]byte(fullString))
// 	hash := h.Sum(nil)

// 	// Extract alphanumeric characters from the hash
// 	// reason I'm doing this is because earlier I had assumed that the hash was a alphanum string,
// 	//but as it turns out, it had some special characters in it, wide variety of them actually
// 	alphanum := ""
// 	for _, ch := range hash {
// 		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
// 			alphanum += string(ch)
// 		}
// 		if len(alphanum) == length-2 { // Reserve space for extra elements
// 			break
// 		}
// 	}

// 	// Add a number in the middle of the string
// 	lenstr := (len(username+website) + 149) % 100
// 	middleIndex := len(alphanum) / 2
// 	alphanum = alphanum[:middleIndex] + strconv.Itoa(lenstr) + alphanum[middleIndex:]

// 	// Ensure at least one uppercase letter
// 	hasUpper := false
// 	hasLower := false
// 	for _, ch := range alphanum {
// 		if unicode.IsUpper(ch) {
// 			hasUpper = true
// 		}
// 		if unicode.IsLower(ch) {
// 			hasLower = true
// 		}
// 		if hasUpper && hasLower {
// 			break
// 		}
// 	}

// 	// Replace with username's first character if necessary
// 	if len(username) > 0 {
// 		firstChar := rune(username[0])
// 		if !hasUpper && unicode.IsLetter(firstChar) {
// 			// Replace the first character with the uppercase version of username's first character
// 			alphanum = string(unicode.ToUpper(firstChar)) + alphanum[1:]
// 			hasUpper = true
// 		}
// 		if !hasLower && unicode.IsLetter(firstChar) {
// 			// Replace the second character with the lowercase version of username's first character
// 			alphanum = alphanum[:1] + string(unicode.ToLower(firstChar)) + alphanum[2:]
// 			hasLower = true
// 		}
// 	}

// 	// Add a random password-friendly symbol
// 	symbols := []rune{'.', ',', '#', '!', '@', '$', '%', '^', '&', '*'}
// 	randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(symbols))))
// 	if err != nil {
// 		fmt.Println("Error generating random index:", err)
// 		return ""
// 	}
// 	randomSymbol := symbols[randomIndex.Int64()] // Generate a pseudo-random symbol

// 	// Replace a character in a "safe" position with the symbol
// 	// Safe positions are from index 2 onward
// 	safePositionBigInt, err := rand.Int(rand.Reader, big.NewInt(int64(length-2))) // Random index starting from the third character
// 	if err != nil {
// 		fmt.Println("Error generating random index:", err)
// 		return ""
// 	}
// 	safePosition := 2 + int(safePositionBigInt.Int64())
// 	alphanum = alphanum[:safePosition] + string(randomSymbol) + alphanum[safePosition+1:]
// 	encrypted, _ := aes.NewCipher([]byte(alphanum))
// 	println("encrypted is:", encrypted)
// 	// fmt.Println("Final password string:", alphanum)
// 	return alphanum
// }

// func main() {
// 	filename := "passwordsss.json"

// 	err := initializeJSONFile(filename)
// 	if err!= nil {
// 		fmt.Println("error initializing the file", err)
// 	}
// 	//now the instructor is actually hititng an API but since we're creating the software for passwords, it will be better to make it all in-house
// 	//or offline, so offline it is
// 	//we will be using the crypto/rand package to generate random passwords
// 	username := flag.String("u", "", "Username for the platform")
// 	website := flag.String("w", "", "Website for the platform")
// 	length := flag.Int("l", 12, "Length of the password")
// 	lock := flag.Bool("lock", false, "Lock the password")
// 	flag.Parse()

// 	if *username == "" || *website == "" {
// 		fmt.Println("Username (-u) and Website (-w) are required")
// 		fmt.Println("Example usage: go run main.go -u 'exampleUser' -w 'example.com' -l 12")
// 		os.Exit(1)
// 	}

// 	if *lock {
// 		// Logic for asking master password and encrypting data
// 		fmt.Println("Locking mechanism activated")
// 		// Lock is skipped for a while, as by default we'll store and lock everything

// 	}
// 	var masterpassword string
// 	fmt.Println("enter the master password if you wish to encrypt the output")
// 	fmt.Scanln(&masterpassword)
// 	key, _ := getHiddenInput(masterpassword)
// 	password := generatePassword(*username, *website, *length, key)
// 	fmt.Println("Want to log the password? Y?")
// 	var response string
// 	fmt.Scanln(&response)
// 	if response != "y" && response != "Y" {
// 		fmt.Println("Password logging skipped")
// 		fmt.Println("Your password is secured, you can access it anytime by running the program again")
// 		return
// 	}
// 	fmt.Printf("Generated Password: %s\n", password)
// }

// func initializeJSONFile(filename string) error {
// 	if _, err := os.Stat(filename); err == nil {
// 		//when file already exists
// 		fmt.Println("File already exists:", filename)
// 		return nil
// 	} else if !os.IsNotExist(err) {
// 		return fmt.Errorf("Error checking if the file exists: %v", err)

// 	}
// 	initialData := make(map[string]interface{})
// 	file, err := os.Create(filename)
// 	if err != nil {
// 		return fmt.Errorf("error creating the file %v", err)
// 	}
// 	defer file.Close()

// 	//write the initial data to the file
// 	encoder := json.NewEncoder(file)
// 	encoder.SetIndent("", "  ")
// 	if err := encoder.Encode(initialData); err != nil {
// 		return fmt.Errorf("error encoding the initial data: %v", err)
// 	}
// 	fmt.Println("file created and initialiezed:", filename)
// 	return nil
// }

// func getHiddenInput(prompt string) ([]byte, error) {
// 	input, err := term.ReadPassword(int(os.Stdin.Fd()))
// 	// input, err:= term.Readpassword(int(syscall.Stdin))
// 	fmt.Println()
// 	if err != nil {
// 		return nil, err
// 	}
// 	// return string(input), nil
// 	hashedKey := sha256.Sum256(input)
// 	fmt.Println("about to return hidden hashed")
// 	return hashedKey[:], nil
// }
