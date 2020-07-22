package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"strings"

	"github.com/cheggaaa/pb"
)

var debugSyscalls bool

var count int

var (
	max         int
	min         int
	keyid       int
	hunt        bool
	output_path string
	debug       bool
	quiet       bool
)

func Usage() {
	bins := strings.SplitAfter(os.Args[0], "/")
	bin := bins[len(bins)-1]
	fmt.Println("Search for Linux kernel keyrings even if /proc/keys are masked in a container")
	fmt.Printf("Usage: \n\n\t%s -min 0 -max 999999999 \n\n\t%s -hunt\n\n\t%s -stderrthreshold=Info\n\n", bin, bin, bin)
	flag.PrintDefaults()
}

func init() {

	flag.Usage = Usage
	// Optional max count
	flag.IntVar(&max, "max", 999999999, "Max key id range")
	// OPtional min count
	flag.IntVar(&min, "min", 1, "Minimum key id range")
	// optional: specific key id
	flag.IntVar(&keyid, "key", 0, "Specific key ID to test (int32)")
	// Either hunt mode or key mode
	flag.BoolVar(&hunt, "hunt", true, "Enable brute force mode to search for key ids")
	// JSON output path
	flag.StringVar(&output_path, "output", "./keyctl_ids", "Output path")
	// Debug options
	flag.BoolVar(&debug, "d", false, "Log everything to stdout (cloud logging not supported)")
	// Quiet mode
	flag.BoolVar(&quiet, "q", false, "Quiet mode to disable logging and progress bar")
}

func main() {
	flag.Parse()

	if debug {
		// Setup verbose logging but don't use cloud
		Clogger(os.Stdout, os.Stdout, os.Stderr)
		Info.Println("Local logging enabled")
	} else if quiet {
		Clogger(ioutil.Discard, ioutil.Discard, ioutil.Discard)
	} else {
		Clogger(os.Stdout, os.Stdout, os.Stderr)
	}

	self, _ := user.Current()

	Info.Printf("Trying to get_persistent keyrings for user %s\n", self)
	if self.Uid != "0" {
		Warning.Printf("Your UID is %s so persistent keyrings will be associated to this user. Run as root(UID 0) to get better results", self.Uid)
	}

	err := keyctl_Get_Persistent(int(-1), keyId(-3))
	if err != nil {
		//TODO react to error here
		//I think in the case of non-linux hosts, something weird happens here
		Error.Printf("Your OS doesn't appear to support persistent volumes: %s", err.Error())
	}

	// Just return an individual key if you want
	// TODO update to use the linking stuff
	if keyid != 0 {
		Info.Println("Key read mode enabled for key: " + string(keyid))
		k := Key{KeyId: int32(keyid)}
		key_results, err := k.describeKeyId()
		//key_results, err := describeKeyId(keyId(keyid))
		if err == nil {
			Info.Printf("Describe keyid: %s", string(key_results))
			k.populate_describe(key_results)
			if k.Type == "keyring" {
				k.populate_subkeys()
			} else if k.Type == "user" {
				k.Get()
			}
		} else {
			//Error.Print(err.Error())
			Error.Print(err.Error())
		}
		// Convert to jsonoutput
		output, _ := json.MarshalIndent(k, "", " ")

		Error.Println((string(output)))

		// Save results to file
		f, _ := os.Create(output_path)
		defer f.Close()
		f.Write(output)

	} else if hunt {
		hunter()
	}

}

func (k *Key) Get() error {
	// Perform a syscall keyctlread() to get the secret bytes
	// of a key. Returns error if it can't read the key.

	var (
		b        []byte
		err      error
		sizeRead int
	)

	if k.size == 0 {
		k.size = 512
	}

	size := k.size

	b = make([]byte, int(size))
	sizeRead = size + 1
	for sizeRead > size {
		r1, err := keyctl_Read(keyId(k.KeyId), &b[0], size)
		if err != nil {
			return err
		}

		if sizeRead = int(r1); sizeRead > size {
			b = make([]byte, sizeRead)
			size = sizeRead
			sizeRead = size + 1
		} else {
			k.size = sizeRead
		}
	}

	// Update the original keypointer
	content := b[:k.size]
	k.Byte_Content = content
	k.String_Content = string(content)

	return err
}

func hunter() {
	// Status bar
	//bar := pb.StartNew(count)
	bar := pb.Full.Start(max - min)
	if quiet {
		bar.SetTemplateString("")
	}

	// Save results to file
	f, _ := os.Create(output_path)
	defer f.Close()

	// Brute force a range of keys in a container
	for i := min; i < max; i++ {
		bar.Increment()

		k := Key{KeyId: int32(i)}

		// syscall keyctl_describekeyid(keyid)
		// Collects information about a key ID but not its contents
		breturn, err := k.describeKeyId()
		if err != nil {
			//TODO I'm able to find keys in a lot of fun ways, do I care about keys I can't
			// read initially?
			continue

			if msg := err.Error(); msg == "permission denied" {
				// Permission denied means you don't possess it
				// or you don't have a UID that is permitted but
				// it confirms it exists in case you can become
				// another user
				k.Valid = true
				k.Comments = append(k.Comments, "Found key but describe permission denied")
			} else if msg := err.Error(); msg == "required key not available" {
				// Required key not available confirms it doesn't exist
				Info.Printf("Key %d error: %s", i, err.Error())
			} else {
				// Not a lot of other errors that I know of
				Error.Printf("%d: %s\n", i, err.Error())
			}

		} else {
			// Means the key/keyring is accessible to us
			k.Valid = true
			// Fill in the key details based on the syscall response
			k.populate_describe(breturn)

			if k.Type == "keyring" {
				// Keyrings hold keys and are what we're looking for

				// If you don't "possess" the keyring then you will likely
				// be unable to read its contents. This links the keyring
				// to your personal session keyring, and then tries to read
				// the contents.
				// syscall keyctl_link(src, -3=session keyring)
				err := keyctl_Link(keyId(k.KeyId), keyId(keySpecSessionKeyring))
				if err == nil {
					// list keys in keyring and fill in description deails
					// TODO this is populating subkeys before the link which
					// means the sub-sub keys can't do a read() op
					k.populate_subkeys()

					// Try to read all the secrets of the keys
					for i := range k.Subkeys {
						err := k.Subkeys[i].Get()
						if err != nil {
							//TODO what else can happen?
							//Error.Print(err.Error())
							Error.Print(err.Error())
						}

					}
					// Cleanup and unlink the keyring from your session
					keyctl_Unlink(keyId(k.KeyId), keyId(keySpecSessionKeyring))
				}

			} else if k.Type == "user" {
				// We skip this because we're brute forcing the keyrings anyways so we'll
				// get the keys from there instead.
				Info.Printf("User key found: %d, skipping", i)
				//TODO should I add a continue here if it's not a keyring?
				continue
			} else if k.Type == "" {
				// I think there are some other key types or if an error...
				Info.Printf("Type for key %d is blank", i)

				continue
			} else {
				// Punt if something else happens
				Error.Printf("Key %d is type %s, skipping for now", i, k.Type)
				continue
			}

			// Go back and collect the keyring data to be thorough
			err := k.Get()
			if err != nil {
				// We would haven't already deduced this but there's a scenario
				// where you have permission to describe() a key but not read() it
				if msg := err.Error(); msg == "permission denied" {
					k.Comments = append(k.Comments, "Read permission denied to user")
				} else if err != nil {
					// TODO not sure what other errors could be
					Error.Print(err.Error())
				}
			}
		}

		if k.Valid {
			// Output as JSON
			output, _ := json.MarshalIndent(k, "", " ")

			// DEBUG
			Info.Print(string(output))
			f.Write(output)
		}
	}
	bar.Finish()
	fmt.Println("Output saved to: ", output_path)
}

func (k *Key) populate_subkeys() (int, error) {
	// Consume a keyid and run the syscall listkeys()
	// Generates keyids for other keys part of the
	// keychain.
	nkid, err := listKeys(keyId(k.KeyId))
	if err != nil {
		return 0, err
	}
	var i int

	for _, kid := range nkid {
		// Turn each subkey ID into a key object
		i++
		nk := Key{KeyId: int32(kid)}
		nkdesc, err := nk.describeKeyId()
		// TODO IDK if you need to hunt for subkeys here because
		// you're already going to find them from /proc/keys
		// and you're going to get permission problems for subkeys
		// I would assume? idk.
		if err == nil {
			Info.Printf("Subkey description: %s", string(nkdesc))
			err := nk.populate_describe(nkdesc)
			if err != nil {
				nk.Comments = append(nk.Comments, "Error parsing subkey describe text")
			} else if nk.Type == "keyring" {
				// If the subkey isn't a keyring cool because we'll find the keyrings later
				nk.populate_subkeys() // TODO recursive, does this make sense?
			} else {
				// If the subkey is a user key, asymmetric key, or something else, try to read it
				err := nk.Get()
				if err != nil {
					//TODO Not sure why there's a permission error during subkey search. Maybe because no link
					nk.Comments = append(nk.Comments, fmt.Sprintf("Error during %s subkey read: %s", nk.Type, err.Error()))
				}
			}
			k.Subkeys = append(k.Subkeys, nk)
		} else {
			nk.Comments = append(nk.Comments, "Error during subkey describe")
		}
	}
	return i, nil
}
