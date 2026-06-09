Ransomware Detection Tool
A real-time ransomware detection system built with Python and Flask that monitors file system activity and flags suspicious behavior associated with ransomware attacks.

About the Project
Ransomware is one of the most damaging forms of malware, encrypting victim files and demanding payment for recovery. This project simulates a lightweight detection layer that monitors file activity patterns — such as rapid file modifications, suspicious extensions, and mass rename operations — to detect potential ransomware behavior before significant damage occurs.
Built as a practical cybersecurity project to strengthen understanding of malware behavior, defensive security concepts, and real-time monitoring techniques.

Features
- Real-time file system monitoring
- Detection of suspicious file activity patterns
- Flask-based web dashboard for live alerts
- Logs flagged events with timestamps

Tech Stack
- Backend: Python, Flask
- Frontend: HTML, CSS (dashboard)

Installation
git clone https://github.com/Hacker0306/Ransomeware-Detection-Tool.git
cd Ransomeware-Detection-Tool
pip install -r requirements.txt
python server.py
Then open your browser and go to: http://localhost:5000

How It Works
1. The tool watches a specified directory for file system events
2. It analyzes patterns such as rapid modifications, bulk renames, or unknown extensions
3. Suspicious activity is flagged and displayed on the web dashboard in real time

Use Case
Designed for educational purposes to demonstrate how endpoint detection tools identify early-stage ransomware behavior. Useful for understanding defensive security, malware analysis, and security monitoring concepts.

Author
Siddharth Yadav  
Cybersecurity Enthusiast | Bug Bounty Researcher  
[LinkedIn](https://www.linkedin.com/in/siddharth-yadav-9a29bb25b/) | [GitHub](https://github.com/Hacker0306)
