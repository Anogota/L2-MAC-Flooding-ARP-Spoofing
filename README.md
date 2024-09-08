# L2-MAC-Flooding-ARP-Spoofing

<h3>1.Initial Access</h3>

```
User	  Password	IP	        Port
admin	  Layer2	  10.10.68.1	22
```

We need to login into that SSH, by above credentials.
Use that command in terminal ```ssh -o StrictHostKeyChecking=accept-new admin@10.10.68.1```
The admin user is in the sudo group. I suggest using the root user to complete this room: sudo su -

Task 1:Now, can you (re)gain access? (Yay/Nay)
The answer is: yay

<h3>2.Network Discovery</h3>

Task 1:What is your IP address?
We need to use that command to list it - ```ip a s eth1```

![image](https://github.com/user-attachments/assets/5f4e97e8-0a57-4bbb-abb5-9797033c3142)

The answer is: 192.168.12.66

Task 2:What's the network's CIDR prefix?
You can find answer in above screanshot:
/24 is the prefix length, indicating that the first 24 bits of the address are used for the network identifier.

Task 3:How many other live hosts are there?
We will use the nmap, in that exampel: ```nmap -sn 10.10.68.1```
The answe is: 2

Task 4:What's the hostname of the first host (lowest IP address) you've found?
The answer will be alice, chcek below:

![image](https://github.com/user-attachments/assets/5de8a446-48e2-43ad-bb4f-5ddf005207a2)


<h3>3.Passive Network Sniffing</h3>

Task 1:Can you see any traffic from those hosts? (Yay/Nay)
The answer will be: yay, because when u instert that command ```tcpdump -A -i eth1``` you can see a lot of trafic.

Task 2:Who keeps sending packets to eve?
We can check it by that command ```tcpdump -A -i eth1```, the answer will be: bob.

![image](https://github.com/user-attachments/assets/311ecd73-f656-42a9-b4a5-1afa97f4c5e9)

Task 3:What type of packets are sent?
We need to save all of that traffic in one file by that command: ```tcpdump -A -i eth1 -w /tmp/tcpdump.pcap```
Then open another windows and use that command to copy that file into our machine ```scp admin@10.10.68.1:/tmp/tcpdump.pcap .```, and open it by wireshark tcpdump.pcap
The answer is: ICMP

![image](https://github.com/user-attachments/assets/84c930dd-a2b4-4b9f-8141-8e2def8a73a2)

Task 4:What's the size of their data section? (bytes)
The answer will be: 666, check below:

![image](https://github.com/user-attachments/assets/1ff3784d-f07a-45fa-81dc-cea62d042d3f)


<h3>4.Sniffing while MAC Flooding</h3>


Task 1:What kind of packets is Alice continuously sending to Bob? 
For better usability, open a second SSH session. This way, you can leave the tcpdump process running in the foreground on the first SSH session:
```tcpdump -A -i eth1 -w /tmp/tcpdump2.pcap```

On the second SSH session, buckle up and let macof run against the interface to start flooding the switch:
```macof -i eth1```

After around 30 seconds, stop both macof and tcpdump (Ctrl+C).
As in the previous task, transfer the pcap to your machine by that command: ```scp admin@10.10.68.1:/tmp/tcpdump2.pcap .```

The answer will be ICMP:

![image](https://github.com/user-attachments/assets/8bc2814f-9cb2-4d60-89ec-c764f6476890)

Task 2:What's the size of their data section? (bytes)
The answer is: 1337

<h3>5.Man-in-the-Middle: Intro to ARP Spoofing</h3>

Task 1:Can ettercap establish a MITM in between Alice and Bob? (Yay/Nay)
Test that command in terminal: ```ettercap -T -i eth1 -M arp```, the answer is nay, you need to check it by your self, because i couldn't display all of this results is to much :D

Task 2:Would you expect a different result when attacking hosts without ARP packet validation enabled? (Yay/Nay)
The answer is: yay

tl;dr – "an attacker sends (spoofed) ARP messages […] to associate the attacker's MAC address with the IP address of another host […] causing any traffic meant for that IP address to be sent to the attacker instead. ARP spoofing may allow an attacker to intercept data frames on a network, modify the traffic, or stop all traffic. Often the attack is used as an opening for other attacks, such as denial of service, man in the middle, or session hijacking attacks."


<h3>6.Man-in-the-Middle: Sniffing</h3>

Task 1:Scan the network on eth1. Who's there? Enter their IP addresses in ascending order.
We need to use that command ```ip address show eth1``` to display that information

![image](https://github.com/user-attachments/assets/2dd8bc5d-8f47-4c68-a71a-d4648b5328ca)

Then u will gate that ip insert that command ``` nmap  192.168.12.66/24```
The answer is: 192.168.12.10, 192.168.12.20
```
Starting Nmap 7.80 ( https://nmap.org ) at 2024-09-08 13:52 UTC
Nmap scan report for alice (192.168.12.10)
Host is up (0.0019s latency).
Not shown: 999 closed ports
PORT     STATE SERVICE
4444/tcp open  krb524
MAC Address: 0A:4C:D2:BC:BD:86 (Unknown)

Nmap scan report for bob (192.168.12.20)
Host is up (0.0019s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
80/tcp open  http
MAC Address: C2:31:C0:3F:41:28 (Unknown)

Nmap scan report for eve (192.168.12.66)
Host is up (0.0000070s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp
5002/tcp open  rfe
```


