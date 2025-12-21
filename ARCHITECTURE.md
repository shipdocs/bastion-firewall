# Douane Firewall - Architecture Documentation

This document provides detailed architectural diagrams and explanations of the Douane Firewall system.

## Table of Contents

- [System Overview](#system-overview)
- [Component Architecture](#component-architecture)
- [Data Flow](#data-flow)
- [Security Model](#security-model)
- [Threading Model](#threading-model)

## System Overview

Douane Firewall follows a **client-server architecture** with strict privilege separation between the root daemon and user-space GUI components.

```mermaid
graph TB
    subgraph "User Space (Normal User)"
        GUI[GUI Client<br/>douane-gui-client]
        CP[Control Panel<br/>douane-control-panel]
        ST[System Tray Icon]
    end

    subgraph "Root Space (Privileged)"
        DAEMON[Daemon Process<br/>douane-daemon]
        PP[Packet Processor]
        RE[Rules Engine]
        SW[Service Whitelist]
    end

    subgraph "Kernel Space"
        NF[Netfilter/iptables]
        NFQ[NFQUEUE]
    end

    GUI -->|Unix Socket| DAEMON
    CP -->|Unix Socket| DAEMON
    GUI --> ST
    DAEMON --> PP
    DAEMON --> RE
    PP --> SW
    PP -->|Verdict| NFQ
    NFQ -->|Packets| PP
    NF -->|Queue| NFQ

    style GUI fill:#90EE90
    style CP fill:#90EE90
    style DAEMON fill:#FFB6C1
    style NF fill:#87CEEB
```

## Component Architecture

### High-Level Component Diagram

```mermaid
graph LR
    subgraph "Douane Firewall Components"
        direction TB

        subgraph "User Interface Layer"
            GUI[GUI Client]
            CP[Control Panel]
            TRAY[System Tray]
        end

        subgraph "Core Layer (Root)"
            DAEMON[Daemon]
            CORE[Firewall Core]
            RULES[Rules Engine]
            CONFIG[Config Manager]
        end

        subgraph "Security Layer"
            WHITELIST[Service Whitelist]
            APPID[App Identifier]
            INBOUND[Inbound Firewall]
        end

        subgraph "System Integration"
            NETFILTER[Netfilter Queue]
            UFW[UFW Integration]
            SYSTEMD[Systemd Service]
        end
    end

    GUI --> DAEMON
    CP --> DAEMON
    DAEMON --> CORE
    CORE --> RULES
    CORE --> WHITELIST
    CORE --> APPID
    DAEMON --> CONFIG
    DAEMON --> NETFILTER
    INBOUND --> UFW
    SYSTEMD --> DAEMON

    style GUI fill:#90EE90
    style CP fill:#90EE90
    style DAEMON fill:#FFB6C1
    style CORE fill:#FFB6C1
    style NETFILTER fill:#87CEEB
```

### Module Dependencies

```mermaid
graph TD
    DAEMON[daemon.py]
    GUI[gui.py]
    CORE[firewall_core.py]
    RULES[rules.py]
    CONFIG[config.py]
    WHITELIST[service_whitelist.py]
    INBOUND[inbound_firewall.py]

    DAEMON --> CORE
    DAEMON --> CONFIG
    DAEMON --> RULES
    GUI --> CONFIG
    CORE --> WHITELIST
    CORE --> RULES
    INBOUND --> CONFIG

    style DAEMON fill:#FFB6C1
    style GUI fill:#90EE90
    style CORE fill:#FFB6C1
```

## Data Flow

### Packet Processing Flow

```mermaid
sequenceDiagram
    participant App as Application
    participant Kernel as Linux Kernel
    participant NFQ as NFQUEUE
    participant Daemon as Douane Daemon
    participant WL as Service Whitelist
    participant Rules as Rules Engine
    participant GUI as GUI Client
    participant User as User

    App->>Kernel: Outbound connection
    Kernel->>NFQ: Queue packet (iptables rule)
    NFQ->>Daemon: Packet data

    Daemon->>WL: Check whitelist
    alt In whitelist
        WL-->>Daemon: Auto-allow
        Daemon->>NFQ: ACCEPT verdict
        NFQ->>Kernel: Forward packet
    else Not in whitelist
        Daemon->>Rules: Check existing rules
        alt Rule exists
            Rules-->>Daemon: Allow/Deny
            Daemon->>NFQ: Verdict
        else No rule
            Daemon->>GUI: Request decision
            GUI->>User: Show popup
            User->>GUI: Allow/Deny
            GUI->>Daemon: User decision
            Daemon->>Rules: Save rule (if permanent)
            Daemon->>NFQ: Verdict
        end
    end

    NFQ->>Kernel: Forward/Drop packet
    Kernel->>App: Connection result
```

### GUI Communication Flow

```mermaid
sequenceDiagram
    participant Daemon as Daemon (Root)
    participant Socket as Unix Socket
    participant GUI as GUI Client (User)
    participant User as User

    Note over Daemon,GUI: Startup Phase
    Daemon->>Socket: Create /var/run/douane.sock
    Daemon->>Socket: Listen for connections
    GUI->>Socket: Connect
    Socket-->>Daemon: Connection established

    Note over Daemon,GUI: Decision Request Phase
    Daemon->>Socket: Send connection info (JSON)
    Socket->>GUI: Forward data
    GUI->>User: Display popup dialog
    User->>GUI: Click Allow/Deny
    GUI->>Socket: Send decision (JSON)
    Socket->>Daemon: Forward decision
    Daemon->>Daemon: Apply verdict

    Note over Daemon,GUI: Shutdown Phase
    GUI->>Socket: Disconnect
    Socket-->>Daemon: Connection closed
```

## Security Model

### Privilege Separation

```mermaid
graph TB
    subgraph "Security Boundaries"
        subgraph "User Process (UID 1000)"
            GUI[GUI Client]
            CP[Control Panel]
        end

        subgraph "Root Process (UID 0)"
            DAEMON[Daemon]
            PACKET[Packet Handler]
        end

        subgraph "Kernel Space"
            NETFILTER[Netfilter]
        end
    end

    GUI -->|Unix Socket<br/>Validated JSON| DAEMON
    CP -->|pkexec<br/>Authenticated| DAEMON
    DAEMON -->|Privileged<br/>Operations| PACKET
    PACKET <-->|System Calls| NETFILTER

    style GUI fill:#90EE90
    style CP fill:#90EE90
    style DAEMON fill:#FFB6C1
    style PACKET fill:#FFB6C1
    style NETFILTER fill:#87CEEB
```

### Security Phases

Douane implements **5 security phases** for defense-in-depth:

```mermaid
graph TD
    START[Packet Intercepted]

    START --> PHASE1{Phase 1:<br/>Localhost Check}
    PHASE1 -->|DNS to 127.0.0.53| ALLOW1[Auto-Allow]
    PHASE1 -->|Other localhost| PHASE2

    PHASE2{Phase 2:<br/>DHCP Validation}
    PHASE2 -->|Valid DHCP| ALLOW2[Auto-Allow]
    PHASE2 -->|Not DHCP| PHASE3

    PHASE3{Phase 3:<br/>App Identification}
    PHASE3 -->|Unknown App| DENY1[Deny]
    PHASE3 -->|Known App| PHASE4

    PHASE4{Phase 4:<br/>Name Matching}
    PHASE4 -->|Exact Match| PHASE5
    PHASE4 -->|No Match| DENY2[Deny]

    PHASE5{Phase 5:<br/>Port Restriction}
    PHASE5 -->|Valid Port| ALLOW3[Auto-Allow]
    PHASE5 -->|Invalid Port| ASK[Ask User]

    style ALLOW1 fill:#90EE90
    style ALLOW2 fill:#90EE90
    style ALLOW3 fill:#90EE90
    style DENY1 fill:#FFB6C1
    style DENY2 fill:#FFB6C1
    style ASK fill:#FFD700
```

### Trust Model

```mermaid
graph LR
    subgraph "Trusted"
        KERNEL[Kernel]
        SYSTEMD[systemd-resolved]
        DHCP[DHCP Client]
        NTP[NTP Client]
    end

    subgraph "Conditional Trust"
        BROWSER[Web Browsers]
        EMAIL[Email Clients]
        UPDATES[Package Managers]
    end

    subgraph "Untrusted"
        UNKNOWN[Unknown Apps]
        CUSTOM[Custom Scripts]
    end

    KERNEL -->|Always Allow| DECISION
    SYSTEMD -->|Always Allow| DECISION
    DHCP -->|Validated| DECISION
    NTP -->|Validated| DECISION

    BROWSER -->|Ask User| DECISION
    EMAIL -->|Ask User| DECISION
    UPDATES -->|Ask User| DECISION

    UNKNOWN -->|Ask User| DECISION
    CUSTOM -->|Ask User| DECISION

    DECISION[Decision Engine]

    style KERNEL fill:#90EE90
    style SYSTEMD fill:#90EE90
    style UNKNOWN fill:#FFB6C1
```

## Threading Model

### Daemon Threading Architecture

```mermaid
graph TB
    MAIN[Main Thread]

    MAIN --> PACKET_THREAD[Packet Processor Thread]
    MAIN --> GUI_THREAD[GUI Connection Thread]
    MAIN --> WATCHDOG[Watchdog Thread]

    PACKET_THREAD --> QUEUE[NFQUEUE Handler]
    PACKET_THREAD --> PROCESS[Packet Processing]

    GUI_THREAD --> LISTEN[Socket Listener]
    GUI_THREAD --> HANDLE[Request Handler]

    WATCHDOG --> MONITOR[Health Monitoring]
    WATCHDOG --> CLEANUP[Resource Cleanup]

    PROCESS -->|Lock| RULES_DB[(Rules Database)]
    HANDLE -->|Lock| RULES_DB

    style MAIN fill:#FFD700
    style PACKET_THREAD fill:#FFB6C1
    style GUI_THREAD fill:#90EE90
    style WATCHDOG fill:#87CEEB
    style RULES_DB fill:#DDA0DD
```

### Thread Safety

```mermaid
graph LR
    subgraph "Shared Resources"
        RULES[(Rules)]
        CONFIG[(Config)]
        PENDING[(Pending Decisions)]
    end

    subgraph "Thread 1: Packet Processor"
        T1_READ[Read Rules]
        T1_WRITE[Write Pending]
    end

    subgraph "Thread 2: GUI Handler"
        T2_READ[Read Pending]
        T2_WRITE[Write Rules]
    end

    T1_READ -->|Lock| RULES
    T1_WRITE -->|Lock| PENDING
    T2_READ -->|Lock| PENDING
    T2_WRITE -->|Lock| RULES

    RULES -.->|Protected by<br/>threading.Lock| LOCK1[🔒]
    CONFIG -.->|Protected by<br/>threading.Lock| LOCK2[🔒]
    PENDING -.->|Protected by<br/>threading.Lock| LOCK3[🔒]

    style RULES fill:#DDA0DD
    style CONFIG fill:#DDA0DD
    style PENDING fill:#DDA0DD
```

## Performance Considerations

### Packet Processing Pipeline

```mermaid
graph LR
    PACKET[Packet Arrives]

    PACKET --> CACHE{In Cache?}
    CACHE -->|Yes| FAST[Fast Path<br/>~0.1ms]
    CACHE -->|No| WHITELIST{Whitelisted?}

    WHITELIST -->|Yes| MEDIUM[Medium Path<br/>~1ms]
    WHITELIST -->|No| RULE{Has Rule?}

    RULE -->|Yes| MEDIUM
    RULE -->|No| SLOW[Slow Path<br/>~100ms]

    FAST --> VERDICT[Verdict]
    MEDIUM --> VERDICT
    SLOW --> GUI[GUI Popup]
    GUI --> VERDICT

    style FAST fill:#90EE90
    style MEDIUM fill:#FFD700
    style SLOW fill:#FFB6C1
```

### Optimization Strategies

1. **Decision Caching**: Cache recent decisions for 60 seconds
2. **Service Whitelist**: Skip user prompts for known system services
3. **Rule Indexing**: Use hash maps for O(1) rule lookups
4. **Thread Pooling**: Reuse threads for GUI connections
5. **Lazy Loading**: Load rules on-demand, not at startup

## Deployment Architecture

### Single Host Deployment

```mermaid
graph TB
    subgraph "Linux Host"
        subgraph "User Session"
            GUI[GUI Client]
            TRAY[System Tray]
        end

        subgraph "System Services"
            DAEMON[Douane Daemon]
            SYSTEMD[systemd]
        end

        subgraph "Firewall Stack"
            UFW[UFW]
            IPTABLES[iptables]
            NETFILTER[Netfilter]
        end

        subgraph "Storage"
            RULES[/etc/douane/rules.json]
            CONFIG[/etc/douane/config.json]
            LOGS[/var/log/douane-daemon.log]
        end
    end

    SYSTEMD -->|Manages| DAEMON
    DAEMON -->|Reads/Writes| RULES
    DAEMON -->|Reads| CONFIG
    DAEMON -->|Writes| LOGS
    DAEMON -->|Integrates| UFW
    UFW -->|Configures| IPTABLES
    IPTABLES -->|Uses| NETFILTER
    GUI -->|Connects| DAEMON
    TRAY -->|Launches| GUI

    style DAEMON fill:#FFB6C1
    style GUI fill:#90EE90
```

---

## Further Reading

- [IMPLEMENTATION.md](IMPLEMENTATION.md) - Technical implementation details
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development guidelines
- [README.md](README.md) - User documentation
- [FAQ.md](FAQ.md) - Frequently asked questions


