# VNC Check
This program checks VNC servers for the authentication types supported. Normal operation will print if the server is open or requires authentication. Verbose mode will print out the version string recieved, number of security types and the types themselves. Strongly influenced by [Gobuster](https://github.com/OJ/gobuster) by OJ Reeves

### Flags
```
-l      - Select the list of IP addresses, can either be in the form 'ip' or 'ip:port'. If no port is specified 5900 is used. 
-t      - Number of threads to use, the default is 10.
-q      - Seconds before quitting. Timeout value for connecting to the IP and reading in from the port, the default is 10s. 
-v      - Verbose. Will print out more information about the VNC server. 
```

### Examples
The standard, simple, scan these ip addresses and tell if they are opened or closed. 
```
go run main.go -t ips.txt
```

Scan the ip addresses with a timeout of 5 seconds using 20 threads and with extra verbosity. 
```
go run main -l ips.txt -q 5 -t 20 -v
```