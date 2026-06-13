# 🛡 NetSentinel
## Rust Network Security Monitor Desktop Application

A cross-platform desktop security monitoring application built with Rust.

Goal:

Build a lightweight security tool similar to:

- Wireshark (packet visibility)
- CrowdStrike (endpoint monitoring)
- Sentry (events + alerts)

---

# 1. Technology Stack

## Language

- Rust

## Desktop Framework

- Tauri
- React / Svelte

## Async Runtime

- Tokio

## Packet Processing

Crates:

```toml
pcap
pnet
etherparse
```

## Database

- SQLite
- RocksDB

Rust crates:

```toml
sqlx
rusqlite
rocksdb
```

## AI Engine

```toml
candle
linfa
smartcore
```

---

# 2. High Level Architecture


```text

              Network Interface

                      |
                      v

            Packet Capture Engine
                    (Rust)

                      |
                      v

            Async Event Pipeline
                  Tokio

                      |
        --------------------------------

        |              |              |

        v              v              v


 Threat Engine   Traffic Engine   Process Engine


        |              |              |

        --------------------------------

                      |
                      v


                Local Storage

              SQLite / RocksDB


                      |

                      v


              Tauri Desktop UI

```

---

# 3. Repository Structure


```text

netsentinel/

├── Cargo.toml


├── apps/

│

│── desktop/

│     ├── src-tauri/

│     └── frontend/


├── crates/


│── packet-engine/

│
│   ├── capture.rs

│   ├── parser.rs

│   ├── tcp.rs

│   ├── udp.rs

│   └── dns.rs



│── threat-engine/

│
│   ├── detector.rs

│   ├── rules.rs

│   └── alerts.rs



│── process-monitor/

│
│   ├── windows.rs

│   ├── linux.rs

│   └── mac.rs



│── storage/

│
│   ├── database.rs

│   └── models.rs



│── ai-engine/

│
│   ├── model.rs

│   └── anomaly.rs



└── docs/

```

---

# PHASE 1
# Packet Capture Engine

Duration:

2 Weeks


## Goal

Capture all network traffic.


Input:

```
Network Card
```

Output:


```json

{
 "source_ip":"192.168.1.5",
 "destination":"142.250.1.1",
 "protocol":"TCP",
 "port":443
}

```

---

## Tasks


### Step 1

Create Rust workspace


```bash

cargo new netsentinel

```

---

### Step 2

Create packet module


```

packet-engine

```

Responsibilities:

- Open network adapter
- Capture packets
- Decode bytes


---

### Step 3

Implement TCP Parser


Extract:

- Source IP
- Destination IP
- Source Port
- Destination Port


---

### Step 4

UDP Parser


Detect:

- DNS
- Streaming
- Unknown UDP traffic


---

### Step 5

Create Event Model


```rust

struct NetworkEvent {

source_ip:String,

destination_ip:String,

port:u16,

protocol:String

}

```

---

# PHASE 2
# Async Processing Engine

Duration:

1 Week


Architecture:


```text

Packet Capture

      |

tokio channel

      |

Worker Pool

      |

Analyzers

```


Use:


```rust

tokio::mpsc

```

Tasks:


- Create event queue
- Multiple consumers
- Back pressure handling


---

# PHASE 3
# Process Monitoring


Duration:

2 Weeks


Goal:

Find which application created connection.


Example:


```json

{

"app":"chrome.exe",

"ip":"google.com",

"risk":"SAFE"

}

```


Rust crates:


```

sysinfo
windows-rs

```

---

Tasks:


Windows:

- Process ID
- Executable path
- Network socket


Linux:

- Read /proc
- Map socket inode


Mac:

- System APIs


---

# PHASE 4
# Threat Detection Engine


Duration:

3 Weeks


Architecture:


```text

Network Event

      |

Rules Engine

      |

Risk Score

      |

Alert

```


---

## Detection Rules


### Port Scan Detection


Condition:


```

same IP
+
100 ports
+
short time

=
ALERT

```


---


### Data Leak Detection


Monitor:


```

Normal Upload:

100MB


Current:

10GB


ALERT

```


---


### Suspicious Connection


Check:


- Unknown IP

- Bad reputation

- Strange country

- Strange port


---

# PHASE 5
# DNS Security Module


Duration:

1 Week


Capture:


```

google.com

github.com

unknown.xyz

```


Features:


- DNS history
- Domain reputation
- Malware domains


Database:


```sql

CREATE TABLE dns_history(

id INTEGER,

domain TEXT,

created_at TIMESTAMP

);

```

---

# PHASE 6
# Storage Engine


Database Tables:


## connections


```sql

CREATE TABLE connections(

id INTEGER PRIMARY KEY,

process TEXT,

remote_ip TEXT,

protocol TEXT,

created_at TIMESTAMP

);

```


---


## alerts


```sql

CREATE TABLE alerts(

id INTEGER,

severity TEXT,

message TEXT

);

```

---

# PHASE 7
# AI Anomaly Detection


Duration:

3 Weeks


Goal:


Learn normal behavior.


Example:


Normal:


```

Chrome upload:

1GB/day

```


Abnormal:


```

Chrome upload:

50GB at midnight

```


Generate:


```

Risk Score: 95%

Possible Data Theft

```


Models:


- Isolation Forest
- Clustering
- Time Series Detection


Rust:


```

linfa
smartcore

```

---

# PHASE 8
# Desktop Application


Framework:


Tauri


Pages:


## Dashboard


Show:


- Active connections
- Upload/download
- Threat count
- System status


---


## Network View


Table:


| Process | IP | Risk |
|-|-|-|
| Chrome | Google | SAFE |
| Unknown | xxx | HIGH |


---


## Alerts


Example:


```

HIGH

Unknown process sending data

```

---

# PHASE 9
# Plugin System


Advanced Feature


Create:


```rust

trait SecurityPlugin{


fn analyze(event:NetworkEvent)
    -> Option<Alert>;

}

```


Benefits:


Users create custom security rules.


---

# PHASE 10
# Packaging


Targets:


Windows:

```

.exe

```


Mac:

```

.dmg

```


Linux:

```

.AppImage

```


Using:


```

Tauri build

```

---

# Final Skills Covered


✔ Rust ownership

✔ Tokio async

✔ Networking

✔ TCP/IP

✔ Cybersecurity

✔ AI

✔ System programming

✔ Desktop apps

✔ Clean architecture


---

# Timeline


| Phase | Time |
|-|-|
| Packet Engine | 2 weeks |
| Async Core | 1 week |
| Process Monitor | 2 weeks |
| Threat Engine | 3 weeks |
| DNS Security | 1 week |
| AI Detection | 3 weeks |
| UI | 2 weeks |


Total:

12-14 Weeks
