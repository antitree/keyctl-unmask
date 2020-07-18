# Keyctl-demask

This tool aims to unmask keychains and keys used by the Linux kernel from 
within a container. 

## Usage 

From within a container you simply running `keyctl-unmask` will run like this:

![docker demo](/example/docker_demo.gif)

~~~bash
Search for Linux kernel keyrings even if /proc/keys are masked in a container
Usage: ./keyctl_unmask  argument ...
  -hunt
        Enable brute force mode to search for key ids (Default enabled) (default true)
  -key int
        Specific key ID to test (int32)
  -max int
        Max key id range (default 999999999)
  -min int
        Minimum key id range (default 1)
  -output string
        Output path (default "./keyctl_ids")
~~~

## Background 

the `keyctl()` syscall allows a user to interact with Linux kernel keyrings 
which store sensitive information per user, session, threat, or process. These
keyrings are used by many different applications and are visible in 
`/proc/keys`. 

For containers, this was deemed a security risk ( and you'd agree )
you don't want your containers
to be able to see your hosts' keys/keyrings but but the original 
fix for this was to simply 
"mask" `/proc/keys` so that `cat /proc/keys` would return no results.

This tool Goes Florida on those masks.

In reality, the mask just obfuscates the keys and you're free to 
issue syscalls to the kernel requesting any
keys you'd like. (Free as in Florida) 
So here we're brute forcing an `int32` to guess the keyring ID's 
and if they're found, we'll try to "Possess" them and then read the keys of another container... and even
worse, keys of the host.

What kind of things are stored in the Linux keyring you might ask:

* `azcopy` for Azure
* [fucking docker?](https://github.com/containers/image/blob/21244c96ad792ef415068dc1bc1ab82dffb68dc3/pkg/docker/config/config_linux.go)
* systemd unit files
* [trezord](https://github.com/trezor/trezor-core/blob/master/tools/keyctl)
* [neo4j](https://github.com/neo4j-apps/neo4j-desktop/wiki/Troubleshooting-(Linux))
* [kerberos](https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux)
* [cyberark](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Deployment/MasterKeyEncryption/serverkeyencryption.html)
* sssd-common
* nfs-common
* ceph-common
* libecryptfs1
* ecryptfs-utils
* cifs-utils
* [Google fscryptctl](https://github.com/google/fscryptctl/blob/142326810eb19d6794793db6d24d0775a15aa8e5/fscryptctl.c#L100)
* What's the meaning of this shit? https://github.com/moby/qemu/pull/7/commits/e2e55ccdab5eee09d3be37a6bd05bff78bc77381

TODO uhhh hol up

    > # /snap/docker/VERSION/bin/docker-runc
      #   "do not inherit the parent's session keyring"
      #   "make session keyring searcheable"
      # runC uses this to ensure the container doesn't have access to the host
      # keyring
      keyctl
   vas ist das? https://github.com/snapcore/snapd/blob/263fe79965e1d438a257c038e710bf444eefcb4f/interfaces/builtin/docker_support.go
  
Let me be clear, there is an easy solution to this problem (seccomp, user namespaces) and it's 
been known for years, but just like Florida's mask policy, we've decided that we 
don't need these things all the time because we need developers to have
the freedom to develop without the hindrence of security. 


# Demo

In one container, create a new key:

~~~
docker run -it --security-opt seccomp=unconfined keyctl /bin/bash \
> keyctl add user antitrees_secret thetruthisiliketrees @s
123456789
~~~

Run a container (with seccomp disabled like Kubernetes) and guess they keys:

~~~
docker run -it --security-opt seccomp=unconfined keyctl /bin/bash \
> keyctl_hunter -key 123456790
> cat keyctl_ids.txt
~~~


# History of Containers and Keyctl

The history of this issue goes like this:

1. Docker did not protect /proc/keys at all allowing all users to access the host keys
1. Someone finds a memory corruption [bug](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-9529) WRT the `keyctl()` syscall
1. Jesse Frazelle sees this issue and fixes it with a seccomp profile (that is sometimes disabled)
1. Docker realized that this should be protected so they add a mask over /proc/keys so that if you were to `cat /proc/keys` you wouldn't see it
1. In 2016, `stefanberger` thinks that each container should create its own session key. An [Epic Discussion is had](https://github.com/opencontainers/runc/pull/488). Concluding with:
   > "With the patch, each container gets its own session keyring. However, it does work better with user namespaces enabled than without it. With user namespaces each container has its own session keyring _ses and a 'docker exec' joins this session keyring. **Without user namespaces enabled, each container also gets a session keyring on 'docker run' but a 'docker exec' again joins the first created session keyring so that containers share it.** The advantage still is that it's not a keyring shared with the host, even though in the case that user namespaces are not enabled, the containers end up sharing a session keyring upon 'docker exec.'"
1. Jesse Frazelle requests an option to disable the mask so she can do sketchy things in her custom container based FrazelleOS. The option is called [Masked Paths](https://github.com/moby/moby/pull/36644/files). 
1. This is part of moby OCI defaults as the [MaskedPaths spec](https://github.com/moby/moby/blob/10866714412aea1bb587d1ad14b2ce1ba4cf4308/oci/defaults.go) but isn't exposed via Docker. 
1. In 2019, the Linux Kernel adds support for [Keys Namespaces](https://lwn.net/Articles/779895/) but Moby does not support it. 

The current state is that seccomp successfully defends from any risk here but it's a secondary security control so not a robust solution. 
(*cough Kubernetes *cough)  
User-Namespacing again will again save the day because a seperate namespace is created which includes one for a keyring -- but this isn't enabled by default.

So we're back at where we were in 2016, containers using the keyring have a shared session keyring and inherently share private information with eachother. 


# Further Reading

* [Blog About this Issue in 2014](https://www.projectatomic.io/blog/2014/09/yet-another-reason-containers-don-t-contain-kernel-keyrings/)
* [Indepth discussion on keys and how Posession works and is important](https://mjg59.dreamwidth.org/37333.html)
* [keyctl(2) Syscall Man Page](https://man7.org/linux/man-pages/man2/keyctl.2.html)
* [keyctl from keyutils usage page](https://manpages.debian.org/stretch/keyutils/keyctl.1.en.html)
* [Linux Kernel Keys and Keyrings Documentation](https://www.kernel.org/doc/Documentation/security/keys.txt)
* [Example using keyctl to access keys](https://davids-blog.gamba.ca/posts/caching-credentials-linux-keyring-golang/)a
* [IBM Blog covers syscalls used by keyctl](https://www.ibm.com/developerworks/library/l-key-retention/index.html)
* [Linux Kernel Trusted and Encrypted Docs](https://www.kernel.org/doc/Documentation/security/keys-trusted-encrypted.txt)
* 
* 
* 
