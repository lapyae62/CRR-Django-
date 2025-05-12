# 🕵️ Crime Report & Record System

A Django-based web application designed for efficient crime reporting and management by law enforcement personnel of different ranks. It supports regional tracking, officer assignments, and status change requests with admin oversight.

## 🚀 Features

- Secure authentication with custom user model
- Role-based dashboards for:
  - Lower-ranked officers (Constable, Sub-Inspector, Inspector)
  - Higher-ranked officers (Superintendent, Director General)
  - Admins
- Crime reporting and evidence upload
- Region-based report filtering
- Case assignment and update tracking
- Profile and rank/location change requests
- Admin approval workflow

## 🛠️ Tech Stack

- Python 3.13
- Django 5.1.4
- Oracle DB
- Bootstrap (v3 for modals and layout)
- JavaScript / jQuery for dynamic UI

## ⚙️ Setup Instructions

1. Clone the repo:
   ```bash
   git clone https://github.com/YOUR_USERNAME/crime-report-system.git
   cd crime-report-system
