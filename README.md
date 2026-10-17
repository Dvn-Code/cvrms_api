Casa Vista Resort Management System (CVRMS) API

A backend API developed using Python, FastAPI, and PostgreSQL for the Casa Vista Resort Management System. It manages customer accounts, room accommodations, sports court reservations, payments, and point-of-sale (POS) transactions.

Features

1. Authentication and Customer Management

- Customer registration and login.
- Email verification using OTP codes.
- Google account synchronization.
- Customer profile management.
- Password hashing and verification.
- Role-based access checks for customers and staff.

2. Accommodation Management

- View available room records.
- Create and update room information.
- Manage room rates, capacity, room types, and housekeeping status.
- Support bookings involving multiple rooms.

3. Sports Court Management

- Manage pickleball and basketball courts.
- Calculate court reservation fees based on daytime and nighttime rates.
- Check court reservation schedules.
- Manage pickleball paddle rentals.
- Prevent overlapping court reservations.

4. Booking Management

- Create room and sports court reservations.
- View booking records and active bookings.
- Update booking statuses.
- Temporarily hold pending bookings for 15 minutes.
- Validate reservation dates, operating hours, and availability.
- Support booking cancellation and payment confirmation.

5. Payment Management

- Process cash and Maya payments.
- Record payment and refund transactions.
- Validate payment references to prevent duplicate transactions.
- Generate payment records for bookings and POS orders.

6. Point-of-Sale (POS)

- Manage retail items and product prices.
- Create customer orders.
- Calculate order totals and item subtotals.
- Retrieve order details and purchased items.

7. Reports and Financial Monitoring

- Active booking details.
- Room occupancy audit.
- POS sales ledger.
- Financial payment audit.
- Revenue and profit-and-loss (P&L) summary.

Technologies Used

- Python – Main programming language.
- FastAPI – Backend API framework.
- PostgreSQL – Database management system.
- asyncpg – Asynchronous PostgreSQL database driver.
- Pydantic – Request validation and response schemas.
- python-dotenv – Environment variable configuration.
- SMTP – Email delivery for verification codes.
- Swagger UI and ReDoc – API documentation interfaces.

Project Requirements

Make sure the following are installed or available:

- Python 3.10 or later (Python 3.11+ is recommended).
- A PostgreSQL database with the required "resort" and "pos" schemas and tables.
- A configured SMTP account for email verification.
- A ".env" file containing the required configuration values.

Installation and Setup

1. Clone or Download the Project

Download the project source code or clone its Git repository.

git clone <your-repository-url>
cd <your-project-folder>

Replace the placeholders with your actual repository URL and project folder.

2. Create a Virtual Environment

python -m venv venv

Activate it on Windows:

venv\Scripts\activate

3. Install Dependencies

pip install fastapi "uvicorn[standard]" asyncpg python-dotenv "pydantic[email]"

4. Configure Environment Variables

Create a ".env" file in the same directory as your Python API file.

DB_USER=your_database_username
DB_PASSWORD=your_database_password
DB_HOST=your_database_host
DB_PORT=6543
DB_NAME=postgres

ADMIN_USERNAME=your_admin_username
ADMIN_PASSWORD=your_admin_password
STAFF_API_TOKEN=your_staff_api_token

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_email_app_password

Replace the example values with your actual credentials. The database port and name above match the code's defaults and can be changed to match your PostgreSQL configuration.

Important: Never commit your ".env" file or expose database passwords, administrator credentials, SMTP credentials, or API tokens in a public repository.

5. Run the API

If your Python file is named "main.py", execute:

uvicorn main:app --reload

The API will usually run at:

"http://127.0.0.1:8000"

If your Python file has a different name, replace "main" with the filename without ".py".

API Documentation

The API provides interactive documentation for testing endpoints.

Documentation| URL
Swagger UI| "http://127.0.0.1:8000/docs"
ReDoc| "http://127.0.0.1:8000/redoc"
OpenAPI Schema| "http://127.0.0.1:8000/openapi.json"

Note: These documentation endpoints require HTTP Basic Authentication using the configured administrator credentials.

Main API Endpoints

Method| Endpoint| Description
GET| "/"| Check API status
POST| "/auth/send-verification-code"| Send an email verification code
POST| "/auth/verify-code"| Verify an email code
POST| "/auth/register"| Register a customer account
POST| "/auth/login"| Log in to a customer account
GET| "/customers"| Retrieve customer records
GET| "/customers/{customer_id}"| Retrieve a customer profile
POST| "/customers"| Create a customer record
PUT| "/customers/{customer_id}"| Update a customer record
DELETE| "/customers/{customer_id}"| Delete a customer record
GET| "/staff"| Retrieve staff records
POST| "/staff"| Create a staff record
GET| "/rooms"| Retrieve room records
POST| "/rooms"| Create a room
PUT| "/rooms/{room_id}"| Update a room
GET| "/courts"| Retrieve sports courts
GET| "/courts/calculate-price"| Calculate court reservation fees
GET| "/courts/{court_id}/availability"| Check court reservations
POST| "/courts"| Create a sports court
GET| "/bookings"| Retrieve bookings
GET| "/bookings/active"| Retrieve active bookings
POST| "/bookings"| Create a booking
PUT| "/bookings/{booking_id}/status"| Update booking status
POST| "/payments"| Record a payment or refund
GET| "/pos/items"| Retrieve POS items
POST| "/pos/items"| Create a POS item
POST| "/pos/orders"| Create a POS order
GET| "/pos/orders/{order_id}"| Retrieve a POS order
GET| "/reports/active-bookings-detail"| View booking details
GET| "/reports/room-occupancy-audit"| Audit room occupancy
GET| "/reports/pos-sales-ledger"| View POS sales
GET| "/reports/financial-payments-audit"| Audit payment transactions
GET| "/reports/revenue-pnl"| View revenue summary

Authentication

The API supports several authentication mechanisms:

- Customer login: Uses an email address, username, or customer ID with a password.
- Staff authentication: Uses the configured staff API token or administrator credentials for protected endpoints.
- Google synchronization: Creates or updates customer records using Google account information.

Some endpoints are public, while others require authentication or staff authorization.

Database Structure

The API uses two PostgreSQL schemas:

"resort"

- "customer"
- "staff"
- "room"
- "court"
- "booking"
- "booking_room"
- "payment"

"pos"

- "pos_item"
- "pos_order"
- "pos_order_item"

The database must contain the required tables, columns, constraints, and relationships before the API can operate correctly.

Booking and Payment Rules

- Room bookings require check-in and check-out dates.
- Court reservations require start and end times.
- Sports courts operate between 6:00 AM and 10:00 PM.
- Pending bookings have a 15-minute payment hold.
- Maya payments require a transaction reference number.
- A booking must reference either accommodation rooms or a sports court.
- A payment must reference either a booking or a POS order.

Troubleshooting

Database connection error

- Check the database host, port, username, password, and database name in ".env".
- Confirm that the PostgreSQL server is accessible.

Email verification fails

- Check the SMTP configuration.
- For Gmail, use an App Password where required.
- Confirm that the SMTP account supports authenticated email sending.

Unauthorized response (401)

- Check the credentials or required authentication headers.
- Confirm that the relevant environment variables are configured.

Conflict response (409)

- Check for duplicate records, payment references, or overlapping reservations.

Security Notes

- Keep credentials and secrets in environment variables.
- Use HTTPS when deploying the API publicly.
- Use a strong password-hashing algorithm and appropriate password policies.
- Protect customer data and restrict access to sensitive endpoints.
- Implement proper session or token authentication before production deployment.

Project Purpose

CVRMS aims to simplify resort operations by integrating customer management, accommodation reservations, sports facility bookings, cashless payments, retail transactions, and financial reporting into a centralized system.

Project: Casa Vista Resort Management System (CVRMS)
Backend: FastAPI
Database: PostgreSQL
Version: 2.0.0