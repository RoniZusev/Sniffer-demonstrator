# IDS – Intrusion Detection System

This project talks about an IDS — **Intrusion Detection System**.

I used **Tkinter** to create a UI application that simulates a **network (localhost) scanner**.  
The sniffer captures packets and sorts them by:

* TCP / UDP or main protocol  
* Port  
* IP addresses – Source IP, Destination IP  

The idea behind this project is to provide a **safe space to explore the packets** that go through your network.  
This project can be useful for **avoiding attacks or learning how to recognize them**.

---

## !*STEP BY STEP – THE SNIFFER*!

<img width="1339" height="850" alt="image_2025-12-02_225759238" src="https://github.com/user-attachments/assets/17fe16aa-c2cd-46bd-893b-b9025fb57b89" />

This image shows the menu that introduces the user to the application.  
There are two options:

1. Sniffer  
2. Analyze malware  

---

## !*SNIFFER*!

<img width="2559" height="1525" alt="Screenshot 2026-04-30 000308" src="https://github.com/user-attachments/assets/b6d49a0a-9c34-4dad-8114-3353abb868d6" />


This image represents the sniffer view.  
As you can see, the packets are divided into columns of:

* TCP / UDP or protocol  
* Port  
* IP addresses – Source IP, Destination IP  

---

## !*ANALYZE MALWARE*!

<img width="2560" height="1494" alt="Packet-Anylize_2026-04-30_00-04-59" src="https://github.com/user-attachments/assets/3b55924b-d5d2-4439-872b-56b529da62e3" />


This image shows the analysis page of the sniffer that you launched earlier.

also there is an option to see an Cake chart of the packets distribution
## !*PACKET DISTRIBUTION CAKE CHART*!

<img width="2560" height="1494" alt="Packet-Anylize_2026-04-29_23-33-54" src="https://github.com/user-attachments/assets/3c06a702-da3b-421a-b0a3-d311fc056c3d" />



You can see:
- A **graph of protocol distribution**, showing the most and least common protocols.
- A **traffic timeline graph**, showing how the number of packets changes over time — when traffic is high and when it is low.
