**dtlsproxy**
Lightweight DTLS reverse proxy server based on [tinydtls](https://projects.eclipse.org/projects/iot.tinydtls) and [libev](https://github.com/enki/libev).

Similar with [goldy](https://github.com/ibm-security-innovation/goldy), but using [tinydtls](https://projects.eclipse.org/projects/iot.tinydtls) instead of [mbed TLS](https://tls.mbed.org/), using pre-shared key (PSK) instead of certificate/private key files.

```shell
usage: dtlsproxy -l <host:port> -b <host:port> -k <psk>
        -l listen       listen on specified host and port
        -b backend      backend server host and port
        -k keys         psk identities (id1:key1,id2:key2,...,idN:keyN)
```
sample usage:
```shell
    $ dtlsproxy -l 0.0.0.0:5684 -b 127.0.0.1:15683 -k Client_identity:secretPSK
```
Tested on Cygwin and Ubuntu hosts with a [libcoap](https://github.com/obgm/libcoap) server (on port 15683) as the backend.