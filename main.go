package main

import (
    "os"
    "log"
    "fmt"
    "net"
    "flag"
    "sync"
    "time"
    "bufio"
    "strconv"
    "strings"
)

var SecLookup = map[int]string {         
    0:"Invalid",
    1:"None",
    2:"VNC Authentication",
    5:"RA2",
    6:"RA2ne",
    16:"Tight",
    17:"Ultra",
    18:"TLS",
    19:"VeNCrypt",
    20:"GTK-VNC SASL",
    21:"MD5 hash authentication",
    22:"Colin Dean xvp",
}  

type Settings struct {
    // define settings as a struct
    List    string
    Threads int 
    Timeout int
    Verbose bool    
}

type VNC struct {
    // define result as a VNC server and associated information 
    SecNum      int
    Success     bool
    FailReason  string
    Version     string
    Addr        string
    SecTypes    []byte 
}

func parseCommand() Settings {  
    // Parse in command line
    s := Settings{}
    flag.StringVar(&s.List, "l", "", "List of IPs to scan")
    flag.IntVar(&s.Threads, "t", 10, "Amount of threads to scan with")
    flag.IntVar(&s.Timeout, "q", 5, "Quit attempting to connect after X seconds")
    flag.BoolVar(&s.Verbose, "v", false, "Verbose mode")
    flag.Parse()

    return s
}

func checkInfo(s Settings, ip string, vncChan chan<- VNC) {      // Take in settings, IP, results channel
    // Assign VNC results to channel
    vnc := VNC{}
    ip = strings.TrimSpace(ip)
    vnc.Addr = ip
    vnc.Success = true
    vnc.FailReason = ""
    portNum := "5900"

    str := strings.Split(ip, ":")

    ipAddr := str[0]

    if len(str) > 1 {
        portNum = str[1]
    }

    c, err := net.DialTimeout("tcp", ipAddr + ":" + portNum, time.Duration(s.Timeout)*time.Second)
    if err != nil {
        vnc.Success = false
        vnc.FailReason = "Connection to IP timed out"
    } else {
        c.SetReadDeadline(time.Now().Add(10 * time.Second))
    }

    if vnc.Success {
        reader := bufio.NewReader(c)
        // Read in version
        vnc.Version, err = reader.ReadString('\n')
        if err != nil || vnc.Version[0:3] != "RFB" {
            vnc.Success = false
            vnc.FailReason = "No socket data or version string doesn't start with RFB"
        }

        // Send back same version
        fmt.Fprintf(c, vnc.Version)

        if vnc.Success {
            // Read in number of security types
            major,_ := strconv.Atoi(vnc.Version[6:7])
            minor,_ := strconv.Atoi(vnc.Version[10:11])
            if  major > 3 || (major == 3 && minor >= 7) {
                num, err := reader.ReadByte()
                if err != nil { 
                    vnc.Success = false
                    vnc.FailReason = "Could not read in the number of security types"
                }
                vnc.SecNum = int(num)
                
                if vnc.Success {
                    for i := 0; i < vnc.SecNum; i++ {
                        val, err := reader.ReadByte()
                        if err != nil {
                            vnc.Success = false
                            vnc.FailReason = "Could not read in a security type"
                        }
                        // Read in all the VNC security types
                        vnc.SecTypes = append(vnc.SecTypes, val)
                    }
                }
            } else if major == 3 && minor == 3 {    // Read in version 3.3 security where 0 = Invalid, 1 = None, 2 = VNC Auth
                val := make([]byte, 4, 4)
                _,err := reader.Read(val)
                if err != nil {
                    vnc.Success = false
                    vnc.FailReason = "Could not read in v3.3 security type"
                }

                if vnc.Success {
                    vnc.SecNum = 1
                    vnc.SecTypes = append(vnc.SecTypes, val[3])
                }
            } else {
                vnc.Success = false
                vnc.FailReason = "Version detected but lower than 3.3, unsure how to handle"
            }
        }
    }
    vncChan <- vnc
}

func printer(s Settings, result VNC) {        // Take in settings and results channel
    // Print out the result
    if s.Verbose{
        if result.Success {
            fmt.Printf("Server Address: %s (%d)\n", result.Addr, result.SecNum)
            fmt.Printf("Version String: " + strings.TrimSpace(result.Version) + "\n")
            fmt.Printf("Supports: \n")
            for i,_ := range result.SecTypes {
                val := SecLookup[int(result.SecTypes[i])]
                if val == "" {
                    val = "Unknown Authentication"
                }
                fmt.Printf("\tType: %s\n", val)
            }
            fmt.Printf("\n")
        } else {
            fmt.Printf("Server Address: %s failed: %s\n\n", result.Addr, result.FailReason)
        }
    } else {
        if result.Success {
            open := false 
            for i,_ := range result.SecTypes {
                if int(result.SecTypes[i]) == 0 {
                    open = true
                }
            }
            if open {
                fmt.Printf("VNC Server %s is OPEN\n", result.Addr)
            } else {
                fmt.Printf("VNC Server %s requires AUTHENTICATION\n", result.Addr)
            }
        }
    }
    fmt.Printf("\n")
}

func processor(s Settings) {
    // Open list of IPs
    ipList, err := os.Open(s.List)
    if err != nil { 
        log.Fatal("Could not open wordlist")
    }

    // Create channel for IPs (buffer size of threads)
    // Create channel for results
    ipChan := make(chan string, s.Threads)
    vncChan := make(chan VNC)

    // Add syncing
    wg := new(sync.WaitGroup)
    wg.Add(s.Threads)

    // Create go routines for each thread to check the server information
    for i := 0; i < s.Threads; i++ {
        go func() {
            for {
                ip := <-ipChan

                // Did we reach the end? If so break.
                if ip == "" {
                    break
                }

                // Mode-specific processing
                checkInfo(s, ip, vncChan)
            }

            // Indicate to the wait group that the thread
            // has finished.
            wg.Done()
        }()
    }

    // Create go routines to print results
    go func() {
        for r := range vncChan {
            printer(s, r)
        }
    }()

    defer ipList.Close()

    // Read in list of IPs into channel
    scanner := bufio.NewScanner(ipList)
    for scanner.Scan() {
        ip := scanner.Text()
        ipChan <- ip
    }

    // Close the syncing, channels
    close(ipChan)
    wg.Wait()
    close(vncChan)
}

func main() {
    // parse command line and read in settings
    s := parseCommand()
    
    fmt.Printf("+-------------------------------+\n")
    fmt.Printf("|                               |\n")
    fmt.Printf("|             VNC Check         |\n")
    fmt.Printf("| Written by Peleus @0x42424242 |\n")
    fmt.Printf("|                               |\n")
    fmt.Printf("+-------------------------------+\n")
    fmt.Printf("\n\n")
    fmt.Printf("[+] IP List: %s\n", s.List)
    fmt.Printf("[+] Verbose: %t\n", s.Verbose)
    fmt.Printf("\n\n")
    processor(s)            // call a processor which will create threads    
}