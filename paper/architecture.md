%% mermaid.live generation for png
graph TD;
classDef kernel fill:#ffe6e6,stroke:#c00,stroke-width:2px;
classDef user fill:#e6f2ff,stroke:#00529b,stroke-width:2px;
classDef io fill:#d4edda,stroke:#155724,stroke-width:2px;
classDef target fill:#fff3cd,stroke:#856404,stroke-width:2px;
classDef artifact fill:#d1ecf1,stroke:#0c5460,stroke-width:2px;

    subgraph User Mode [rx-tui.exe]
        TUI["<b>Terminal User Interface (TUI)</b><br/><i>- Status Dashboard<br/>- Start/Stop Control</i>"];
        INJECTOR["<b>Injection Suite</b><br/><i>- Module Stomp<br/>- VAD Evasion</i>"];
        TUI -- "Launches Tests" --> INJECTOR;
    end

    subgraph Kernel Mode [rxint.sys]
        DETECTOR["<b>Detector Class</b><br/>Central C++ Object"];

        subgraph Detection Heuristics
            TM["<b>Thread Monitor</b><br/>(OnThreadNotify)"];
            VAD["<b>VAD Scanner</b><br/>(Stateful Hashing)"];
        end

        subgraph Analysis & Output
            DUMP["<b>Memory Dumper</b><br/>(DumpPages)"];
            RESOLVER["<b>Import Resolver</b><br/>(EAT Parser)"];
        end

        DETECTOR --> TM;
        DETECTOR --> VAD;
        DETECTOR --> DUMP;
        DETECTOR --> RESOLVER;
    end

    IOCTL["IOCTL Interface<br/>(DeviceIoControl)"]:::io;
    TARGET["Target Process<br/>(e.g., gmod.exe)"]:::target;
    ARTIFACTS["<b>Forensic Artifacts</b><br/>- Raw Dump (.bin)<br/>- Import Report (.txt)"]:::artifact;

    TUI -- "Sends Commands (Start/Stop)" --> IOCTL;
    IOCTL -- "Controls" --> DETECTOR;

    INJECTOR -- "Injects Payload" --> TARGET;

    TARGET -- "CreateThread Event" --> TM;
    TM -- "<b>Hint of Stomp</b><br/>(Closes TOCTOU Race)" --> VAD;
    TM -- "Detects Classic Injection" --> DUMP;

    VAD -- "Detects Stomp / Evasion" --> DUMP;

    DUMP -- "Provides Raw Dump" --> RESOLVER;
    RESOLVER -- "Generates" --> ARTIFACTS;

    class TUI,INJECTOR user;
    class DETECTOR,TM,VAD,DUMP,RESOLVER kernel;
