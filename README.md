# QNX Secure Sensor Gateway

This project implements a **Secure Sensor Gateway** on **QNX SDP 8.0** running on **x86_64 in VirtualBox**. It simulates sensor data, encrypts it using **OpenSSL (AES + CMAC)**, and sends it securely over **TCP/IP** to a remote PC for decryption and display.

---

## 🧩 Project Components

### 🔧 1. `sensor_simulator/`
- Simulates telemetry data (e.g., temperature, GPS, speed).
- Sends the data to the receiver using **native QNX IPC** (`name_attach`, `MsgSend`).
---------------------------------------------------------------------------------------------------------------

### 🔐 2. `sensor_receiver/`
- Receives the data via IPC.
- Encrypts it using **AES + CMAC (OpenSSL)**.
- Sends the encrypted message via **TCP socket** to a listening Python server (on the PC).
- Linked with:
  ```makefile
  LIBS += -lsocket
  LIBS += -L C:/Users/Administrator/qnx800/target/qnx/x86_64/usr/lib -lssl -lcrypto
---------------------------------------------------------------------------------------------------------------

  🐍 3. aes_server.py
- A Python TCP SSL server that:
- Listens on port 9000 using TLS 1.2
- Accepts incoming connections from the QNX system
- Verifies the CMAC tag appended to the encrypted message
- Decrypts the message using AES-128-CBC
- Displays the plaintext message in the PowerShell terminal
---------------------------------------------------------------------------------------------------------------

🧰 4. start_net.sh
- Shell script to bring up network on the QNX VM.
- Assigns static IP: 192.168.56.101 so that the PC can connect to the QNX target.
- this part can be ignored ..I did ony if connection from PC to QNX VM is needed.
---------------------------------------------------------------------------------------------------------------

  🏗️ Build & Deployment
✅ IFS Build (ifs.build)
Includes:
- sensor_simulator, sensor_receiver, hello_world apps
- hello_world app runs at VM startup
- /usr/lib/libssl.so.3 and /usr/lib/libcrypto.so.3 for OpenSSL support
---------------------------------------------------------------------------------------------------------------

🖥️ Runtime Flow
sensor_simulator (IPC) --> sensor_receiver (AES+CMAC) --> TCP --> aes_server.py (remote PC)
-------------------------------------------------------------------------------------------
How to run:
on QNX VM 
- run: sensor_receiver &
on remote PC on windows power shell
- run: python aes_server.py
on QNX VM you will see a message  "secure TLS CONNECTION established"
- now on QNX VM you can run: sensor_simualtor
- you will find measrements are sent from VM to the PC.
pls check the screenshots attached for the test.
