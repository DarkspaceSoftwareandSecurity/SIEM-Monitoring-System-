# SIEM-Monitoring-System-
SIEM Monitoring System Documentation
Introduction
The SIEM Monitoring System is a tool designed to monitor system resources, file system activity, and network traffic in real-time. It integrates multiple functionalities, such as process monitoring, file changes tracking, network traffic analysis, and generating reports. This system provides a graphical user interface (GUI) with visualizations, logs, and report generation features, making it easier to monitor the system's health and detect potential security threats.
Dependencies
The following dependencies are required to run the SIEM Monitoring System:
1. **psutil**: A cross-platform library used for accessing system and process information like CPU usage, memory usage, etc.
    Installation: `pip install psutil`
2. **scapy**: A powerful Python-based network packet manipulation library used for packet capture and analysis.
    Installation: `pip install scapy`
3. **matplotlib**: A plotting library for creating static, animated, and interactive visualizations in Python.
    Installation: `pip install matplotlib`
4. **openpyxl**: A Python library used for reading and writing Excel (XLSX) files.
    Installation: `pip install openpyxl`
5. **watchdog**: A Python library that helps monitor file system changes in real-time.
    Installation: `pip install watchdog`
Use Cases
The SIEM Monitoring System can be used for various monitoring and security purposes, including:
1. **Real-time System Monitoring**: Monitor system health in terms of CPU and memory usage to ensure optimal performance. The system provides real-time updates on CPU usage, memory consumption, and other critical system resources.
2. **File System Activity Monitoring**: Track changes in files and directories on the system. The tool can log file creations, deletions, and modifications. This functionality helps in monitoring potentially malicious file activities and ensuring system integrity.
3. **Network Traffic Monitoring**: Capture and analyze network packets in real-time. It helps in identifying suspicious network traffic patterns, such as unexpected communication with external servers. Network traffic logs are captured and displayed for analysis.
4. **Report Generation**: The tool can generate reports detailing system resource usage, file activities, and network traffic. The reports are exported in Excel format for easy analysis and documentation, which is useful for audits and security reviews.
How to Use
1. **Starting the Monitoring**: Click on the 'Start Monitoring' button to begin monitoring system resources, files, and network traffic.
2. **Stopping the Monitoring**: Click on the 'Stop Monitoring' button to halt the monitoring process and stop capturing data.
3. **Generating Reports**: Once monitoring is active, you can generate network traffic reports by clicking on the 'Generate Network Report' button. The report will include details such as timestamps, IP addresses, packet sizes, and other relevant data.

4. ![Capture2](https://github.com/user-attachments/assets/5eee192c-47fc-4e05-a1d2-a2d03016a1f1)

5. reoprt looks like this
6. ![Capture](https://github.com/user-attachments/assets/515a3e1c-c1fa-4f4a-8c2c-581f732b098a)

7. you can build the script as a sandalone exe use pyinsaller 
