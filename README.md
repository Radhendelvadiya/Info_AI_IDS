# 🛡️ AI Intrusion Detection System (AI IDS)

AI Intrusion Detection System (AI IDS) is a real-time network monitoring and intrusion detection platform built using Django, Scapy, and Machine Learning.  
The system captures live network packets, extracts relevant features, analyzes traffic using a trained ML model, and displays insights on a modern interactive dashboard.

This project demonstrates practical implementation of network security concepts combined with artificial intelligence.

---

## 🚀 Key Features

- 🔍 Real-time Packet Sniffing using Scapy  
- 🤖 Machine Learning-Based Intrusion Detection  
- 📊 Interactive Web Dashboard (Django)  
- 📈 Attack Distribution Visualization  
- 📡 Live Network Monitoring  
- 🧠 Trained ML Model (Pickle-based)  
- 🔐 Authentication System (Admin/User)  
- 🛠 Modular & Scalable Architecture  

---

## 🏗️ Project Architecture

Network Traffic  
↓  
Packet Sniffer (Scapy)  
↓  
Feature Extraction  
↓  
ML Model Prediction  
↓  
Data Processing  
↓  
Django Dashboard (Real-Time Monitoring)

---

## 🗂 Project Structure

Info_AI_IDS/  
├── ai_ids/                # Django project settings  
├── intrusion_app/         # Main IDS application  
│   ├── ai/                # ML model, training, dataset  
│   ├── capture/           # Packet sniffer & feature extractor  
│   ├── infoids/           # Monitoring logic  
│   ├── templates/         # Dashboard UI  
│   ├── static/            # CSS & JavaScript  
├── accounts/              # User authentication  
├── alerts/                # Alert management  
└── manage.py  

---

## 🛠 Technologies Used

- Python 3.x  
- Django  
- Scapy  
- Scikit-learn  
- HTML / CSS / JavaScript  
- SQLite (Default Database)  

---

## ⚙️ Installation Guide

1️⃣ Clone Repository

```bash
git clone [https://github.com/your-username/AI-Intrusion-Detection-System.git](https://github.com/Radhendelvadiya/Info_AI_IDS.git)
cd AI-Intrusion-Detection-System

2️⃣ Create Virtual Environment

python -m venv venv
venv\Scripts\activate


3️⃣ Install Dependencies

pip install -r requirements.txt


4️⃣ Install Npcap (Windows Only)

Npcap must be installed in WinPcap compatibility mode for packet sniffing to work.

5️⃣ Apply Migrations

python manage.py migrate


6️⃣ Start Django Server

python manage.py runserver


7️⃣ Start Packet Sniffer (Run as Administrator)

python -m intrusion_app.capture.packet_sniffer

<img width="1893" height="1016" alt="Screenshot 2026-01-16 151546" src="https://github.com/user-attachments/assets/04f45a3a-857f-4201-bcfb-85d95e5c996f" />
<img width="306" height="198" alt="Screenshot 2026-01-11 111802" src="https://github.com/user-attachments/assets/51486de9-e5e3-4f15-83be-d8e34b655d14" />

---

## 👨‍💻 Author

Developed with dedication and passion by Radhen Delvadiya 
Role: Network Security & AI Developer  

This project was built as a practical implementation of real-time intrusion detection using AI and network monitoring techniques. It reflects continuous learning, experimentation, and hands-on cybersecurity development.

---

## 🙌 Thank You for Visiting

Thank you for checking out this project!

If you run the project and explore its features, I truly appreciate your time and interest. I hope it helps you understand real-time packet monitoring and AI-based intrusion detection in a practical way.

---

## 🤝 Contributions

Contributions are welcome!

If you would like to improve this project:

- Fork the repository  
- Create a new branch  
- Make your improvements  
- Submit a Pull Request  

All contributions will be carefully reviewed.  
If the changes are effective, secure, and aligned with the project goals, they will be merged.

Constructive ideas, optimizations, feature enhancements, and security improvements are always appreciated.

---

## ⭐ Support

If you found this project helpful or interesting:

- Give it a ⭐ on GitHub  
- Share feedback  
- Suggest improvements  

Your support motivates further development and improvements.

---

🚀 Thank you for being part of this journey in building intelligent and secure network systems.

