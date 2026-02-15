🔐 Secure Payment Gateway (PCI-DSS Oriented)

A security-focused payment gateway simulation built using Flask that demonstrates real-world payment security controls, authentication mechanisms, and compliance-aligned design practices inspired by PCI-DSS standards.

This project focuses on how payments are secured, not just how payments work.

🚀 Key Security Features

Strong Authentication

bcrypt password hashing

Email-based OTP (MFA)

Account lockout after failed attempts

Session timeout & secure cookies

Payment Data Protection

AES-256 encryption for sensitive card data

Tokenization (no raw card data stored)

Masked PAN handling (PCI-DSS aligned)

Fraud & Risk Controls

Device & IP-based login risk evaluation

Brute-force attack protection

Suspicious login blocking

Audit & Monitoring

Centralized security logging

Transaction audit trail

Admin security log dashboard

🛠️ Tech Stack

Backend: Python, Flask

Database: PostgreSQL

Security: bcrypt, AES-256, OTP (Email MFA)

Frontend: HTML, Tailwind CSS

Architecture: Role-based access control (Admin / Merchant)

🎯 What This Project Demonstrates

Practical implementation of secure payment workflows

Defense-in-depth approach for web applications

Secure authentication & authorization design

Real-world cybersecurity concepts applied to fintech systems

🧠 Ideal For

Cybersecurity / AppSec roles

Payment security & fintech security discussions

Demonstrating PCI-DSS awareness in interviews

Academic & practical security projects

⚠️ Disclaimer

This is an educational security simulation.
It does not process real payments and should not be used in production environments.
