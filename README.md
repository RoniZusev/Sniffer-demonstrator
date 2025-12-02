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

<img width="2554" height="1525" alt="image_2025-12-02_230142550" src="https://github.com/user-attachments/assets/d7bf49de-ab63-4290-90c9-b270bf690d25" />

This image represents the sniffer view.  
As you can see, the packets are divided into columns of:

* TCP / UDP or protocol  
* Port  
* IP addresses – Source IP, Destination IP  

---

## !*ANALYZE MALWARE*!

<img width="1486" height="1243" alt="image_2025-12-02_231010672" src="https://github.com/user-attachments/assets/9d4168e8-c1eb-41df-beb5-1e40fc054b25" />

This image shows the analysis page of the sniffer that you launched earlier.

You can see:
- A **graph of protocol distribution**, showing the most and least common protocols.
- A **traffic timeline graph**, showing how the number of packets changes over time — when traffic is high and when it is low.
