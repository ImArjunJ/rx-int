# RX-INT: A Kernel Engine for Real-Time Detection of In-Memory Threats

[![Language](https://img.shields.io/badge/Language-C%2B%2B-blue.svg)](https://isocpp.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue.svg)](https://www.microsoft.com/en-us/windows)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

`RX-INT` is a kernel-mode engine for Windows that detects and dumps "fileless" threats in real-time allowing for a further analysis pipeline.

For further knowledge about the architecture, threat model, and full evaluation results, **[please read the research paper](https://github.com/ImArjunJ/rx-int/blob/master/paper/rxint.pdf)**.

---

#### Showcase

[![RX-INT Demo](https://img.youtube.com/vi/G_LxJ6QXiz4/0.jpg)](https://youtu.be/G_LxJ6QXiz4)

#### Prerequisites

- Windows 10/11 x64
- Administrator privileges
- Test Signing Mode must be enabled. Run this in an admin command prompt and reboot (you can load it however you'd like but this is the easiest way for a general windows user to do so):
  ```cmd
  bcdedit /set testsigning on
  ```

#### Usage

1.  Use a tool like OSR Driver Loader or the command line to load `rxint.sys`.
    ```cmd
    sc create rxint type= kernel binPath= C:\path\to\rxint.sys
    sc start rxint
    ```
2.  Launch `rx-tui.exe`.
3.  From the TUI, select the option to attach and provide the Process ID (PID) of the application you want to monitor.

### Citations

If you use this project in your research, please cite the paper:

```bibtex
@inproceedings{juneja2025rxint,
  title={{RX-INT}: A Kernel Engine for Real-Time Detection and Analysis of In-Memory Threats},
  author={Arjun Juneja},
  year={2025},
}
```
