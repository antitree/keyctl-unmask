# Keyctl-hunt

the `keyctl()` syscall allows a user to interact with Linux kernel keyrings 
which store sensitive information per user, session, threat, or process. These
keyrings are used by many different applications and are visible in 
`/proc/keys`. 

For containers, this was deemed a security risk you don't want your containers
to be able to see your hosts keys but but the fix for this was to simply 
"mask" `/proc/keys` so that `cat /proc/keys` would return no results. 

This mask is ... a mask and not a security control. 

In reality, the mask just obfuscates the keys and there's nothing 
preventing one container from issuing syscalls to the kernfinding the keys of another container, and even
worse, keys of the host. 

# Hacks

So there's a subtle problem. When docker runs, it does make its own
session keyring and by default you aren't connected to it. Boo.

So in container A:

`keyctl add user antitreetest thisismysecret @s`

And container B:

`keyctl show`

You won't see the other session key. 

And you even won't be able to read the session key if you directly:

`keyctl print 123456`

Would get "permission denied"

BUT if you were to join the session:

`keyctl join {PARENT_KEYRING_ID_OR_SESS} @s`

You have now joined the session of another user. OMG. 

Then you can run:

`keyctl print 123456`
or
`keyctl show`

and the key will be there. 

To automate this I'm going to identify the difference between
keyrings and keys, and iterate through all of them to determine
if they're readable. 

Right now it's like:

* try keyid 
* if keyid is valid 
* read it
* if permission denied ignore

Should be

* try keyid
* if keyid is valid
* read it
* if permission denied, then try to find its session keyring
* link the session keyring
* read it again

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

~~~

NOTE: This doesn't work right now and only exposes keys between containers, not
from the host unless the host has some silly keys exposed. 

# Background

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

The current state is that seccomp successfully defends from any risk here but it's a secondary security control so not a robust solution. User-Namespacing again will save the day because a seperate NS is created including a separate keyring -- but this isn't enabled by default. 

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
