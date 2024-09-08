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




