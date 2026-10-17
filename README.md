# 🏖️ Casa Vista Resort Management System (CVRMS) — Backend API

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Framework](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)
![Database](https://img.shields.io/badge/PostgreSQL-316192?style=flat&logo=postgresql&logoColor=white)
![Deployment](https://img.shields.io/badge/Vercel-000000?style=flat&logo=vercel&logoColor=white)

A production-ready RESTful backend API built with **FastAPI** and **AsyncPG** for the **Casa Vista Resort Management System (CVRMS)**. This service powers the resort's mobile and web applications, supporting room accommodations, sports court reservations (Pickleball & Basketball), cashless payments, Point-of-Sale (POS) retail operations, and real-time financial auditing.

---

## ✨ Key Features

- **🔐 Authentication & Security**
  - Email OTP Verification via SMTP (`5-minute` expiration window).
  - Compact PBKDF2-HMAC-SHA256 password hashing & zero-DDL metadata packing.
  - Google Sign-In profile synchronization (`/customers/sync-google`).
  - Role-based access control via `X-Staff-Token`, `X-Customer-Id`, and HTTP Basic Auth.
  - Password-protected Swagger UI (`/docs`) and ReDoc (`/redoc`) documentation.

- **🏨 Accommodations & Sports Amenities**
  - **Rooms Management**: Standard and Deluxe suites with real-time housekeeping statuses (`Ready`, `Occupied`, `Cleaning`, `Maintenance`).
  - **Sports Courts**: Pickleball and Basketball court reservations with automated daytime (`06:00–18:00`) and nighttime (`18:00–22:00`) dynamic rate calculation and paddle rental inventory tracking (up to 16 paddles per slot).
  - **Collision & Policy Enforcement**: Prevents overlapping bookings, enforces Exclusive Whole-Resort Buyout locks, and manages `15-minute` pending payment holds.

- **💳 Payments & Refunds**
  - Exclusive arc validation linking transactions strictly to either a **Booking** or a **POS Order**.
  - Supports **Cash** and **Maya** cashless payments with duplicate reference number prevention.
  - Automated `24-hour` cancellation refund policy validation.

- **🛒 Point-of-Sale (POS) Module**
  - Retail catalog management (`pos.pos_item`) and multi-item counter order processing (`pos.pos_order`).

- **📊 Relational & Financial Reports**
  - Real-time SQL audit endpoints for active bookings, room occupancy, POS sales ledgers, payment audits, and net P&L revenue summaries.

---

## 📁 Repository Structure

```text
├── .gitignore                        # Git ignore rules
├── LICENSE                           # Repository license
├── SWU-007_CVRMS_Documentation.docx  # System documentation & specification
├── main.py                           # FastAPI application, schemas, and route handlers
├── requirements.txt                  # Python dependencies
├── vercel.json                       # Vercel serverless deployment configuration
└── README.md                         # Project documentation
```

---

## ⚙️ Environment Variables

Create a `.env` file in the root directory (or configure these in your **Vercel Project Settings**) with the following variables:

```env
# PostgreSQL / Supabase Connection
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=your_db_host
DB_PORT=6543
DB_NAME=postgres

# Admin & Staff Security Credentials
ADMIN_USERNAME=your_admin_username
ADMIN_PASSWORD=your_admin_password
STAFF_API_TOKEN=your_secret_staff_token

# SMTP Configuration (For Email OTP Verification)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_google_app_password
```

---

## 🚀 Getting Started (Local Development)

### 1. Clone the repository
```bash
git clone https://github.com/JohnMichael100/<your-repo-name>.git
cd <your-repo-name>
```

### 2. Create and activate a virtual environment
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS / Linux:
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the development server
```bash
uvicorn main:app --reload
```

The API will be available at `http://127.0.0.1:8000`.

---

## 📚 API Documentation & Endpoints Overview

> **Note:** Interactive API docs at `/docs` and `/redoc` are protected by HTTP Basic Authentication using `ADMIN_USERNAME` and `ADMIN_PASSWORD`.

| Category | Method | Endpoint | Access | Description |
| :--- | :--- | :--- | :--- | :--- |
| **System** | `GET` | `/` | Public | Health check & API metadata |
| **Auth** | `POST` | `/auth/send-verification-code` | Public | Send 6-digit OTP code via email |
| **Auth** | `POST` | `/auth/verify-code` | Public | Verify email OTP code |
| **Auth** | `POST` | `/auth/register` | Public | Register a new customer account |
| **Auth** | `POST` | `/auth/login` | Public | Authenticate customer via email/username/ID |
| **Customers** | `GET` | `/customers` | Staff/Admin | List all customer profiles |
| **Customers** | `GET` | `/customers/{customer_id}` | Customer/Staff | Retrieve specific customer profile |
| **Customers** | `POST` | `/customers/sync-google` | Public | Upsert customer profile from Google OAuth |
| **Staff** | `GET/POST` | `/staff` | Public / Staff | View or register resort staff members |
| **Rooms** | `GET/POST/PUT` | `/rooms` | Public / Staff | Browse rooms or update room status/details |
| **Courts** | `GET` | `/courts/calculate-price` | Public | Calculate daytime/nighttime court & paddle fees |
| **Courts** | `GET` | `/courts/{court_id}/availability` | Public | Check reserved time slots for a specific date |
| **Bookings** | `GET/POST` | `/bookings` | Public / Auth | List or create room/court reservations |
| **Bookings** | `PUT` | `/bookings/{booking_id}/status` | Customer/Staff | Update booking status or cancel reservation |
| **Payments** | `POST` | `/payments` | Customer/Staff | Record Cash/Maya payment or process refund |
| **POS** | `GET/POST` | `/pos/items` | Public / Staff | View or add POS retail items |
| **POS** | `POST` | `/pos/orders` | Public | Create a new POS retail order |
| **Reports** | `GET` | `/reports/active-bookings-detail` | Public | Relational report of active bookings |
| **Reports** | `GET` | `/reports/room-occupancy-audit` | Public | Housekeeping and guest occupancy audit |
| **Reports** | `GET` | `/reports/pos-sales-ledger` | Public | Itemized POS transactions ledger |
| **Reports** | `GET` | `/reports/financial-payments-audit`| Public | Consolidated booking & POS payments audit |
| **Reports** | `GET` | `/reports/revenue-pnl` | Staff/Admin | Gross/Net operating revenue & refund summary |

---

## ☁️ Deployment (Vercel)

This repository includes a `vercel.json` configuration for zero-config serverless deployment on **Vercel**:
1. Import the GitHub repository into Vercel.
2. Add all required environment variables under **Settings → Environment Variables**.
3. Deploy the project.

---

## 📄 License

Distributed under the License included in the `LICENSE` file. See `SWU-007_CVRMS_Documentation.docx` for full architectural specifications.