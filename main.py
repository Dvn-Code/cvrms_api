from __future__ import annotations

import base64
import hashlib
import os
import random
import secrets
import smtplib
from contextlib import asynccontextmanager
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from email.mime.text import MIMEText
from typing import List, Literal, Optional

import asyncpg
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

try:
    from pydantic import EmailStr
except Exception:
    EmailStr = str

load_dotenv()

# Philippine Standard Time (UTC+8) for accurate local resort date/time checks
PH_TZ = timezone(timedelta(hours=8))

# =============================================================================
# DATABASE CONFIGURATION (NO HARDCODED DB PASSWORDS)
# =============================================================================
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT", "6543")
DB_NAME = os.getenv("DB_NAME", "postgres")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"


# =============================================================================
# PASSWORD HASHING & CUSTOMER ID HELPERS
# =============================================================================
def hash_password(password: str) -> str:
    """Hashes a plaintext password using PBKDF2-HMAC-SHA256 with a 16-byte random salt."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return f"pbkdf2_sha256${salt}${dk.hex()}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Verifies a plaintext password against a stored PBKDF2-HMAC-SHA256 hash."""
    if not stored_hash or "$" not in stored_hash:
        return False
    try:
        algo, salt, hashed_hex = stored_hash.split("$", 2)
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt.encode("utf-8"), 100_000)
        return secrets.compare_digest(dk.hex(), hashed_hex)
    except Exception:
        return False


async def ensure_credentials_table(conn: asyncpg.Connection) -> None:
    """Ensures resort.customer_credentials table exists for storing username and encrypted password."""
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS resort.customer_credentials (
            customer_id VARCHAR(10) PRIMARY KEY REFERENCES resort.customer(customer_id) ON DELETE CASCADE,
            username VARCHAR(50) UNIQUE,
            password_hash TEXT NOT NULL,
            gender VARCHAR(30),
            birthdate VARCHAR(30),
            updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


async def get_next_customer_id(conn: asyncpg.Connection) -> str:
    """Generates the next sequential customer ID following the strict CUST-001 convention."""
    await conn.execute("SELECT pg_advisory_xact_lock(hashtext('cvrms_customer_id_seq'))")
    max_num = await conn.fetchval(
        """
        SELECT COALESCE(MAX(CAST(SUBSTRING(customer_id FROM '^CUST-([0-9]+)$') AS INTEGER)), 0)
        FROM resort.customer
        WHERE customer_id ~ '^CUST-[0-9]+$'
        """
    )
    next_num = (max_num or 0) + 1
    return f"CUST-{next_num:03d}"


# =============================================================================
# APPLICATION LIFESPAN & ASYNCPG CONNECTION POOL
# =============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        app.state.pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=1,
            max_size=5,
            statement_cache_size=0,
        )
        async with app.state.pool.acquire() as conn:
            await ensure_credentials_table(conn)
    except Exception as e:
        print(f"Pool startup notice: {e}")
    yield
    if hasattr(app.state, "pool") and app.state.pool is not None:
        try:
            await app.state.pool.close()
        except Exception:
            pass


# =============================================================================
# SWAGGER & STAFF AUTHENTICATION GUARDS
# =============================================================================
docs_security = HTTPBasic(auto_error=True)

ADMIN_USER = os.getenv("ADMIN_USERNAME", "cvrms_prd_service_account")
ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "@Guest12345")
STAFF_SECRET = os.getenv("STAFF_API_TOKEN", "CVRMS-SECURE-STAFF-TOKEN-2026")


def verify_swagger_credentials(credentials: HTTPBasicCredentials = Depends(docs_security)):
    """Browser basic auth guard protecting /docs and /redoc."""
    is_user_valid = secrets.compare_digest(credentials.username, ADMIN_USER)
    is_pass_valid = secrets.compare_digest(credentials.password, ADMIN_PASS)

    if not (is_user_valid and is_pass_valid):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": 'Basic realm="CVRMS Protected Swagger Documentation"'},
        )
    return credentials.username


async def verify_staff_token(
    request: Request,
    x_staff_token: Optional[str] = Header(default=None, alias="X-Staff-Token"),
):
    """Staff guard that checks X-Staff-Token or Authorization headers directly."""
    if x_staff_token and secrets.compare_digest(x_staff_token, STAFF_SECRET):
        return x_staff_token

    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Basic "):
        try:
            encoded = auth_header.split(" ", 1)[1].strip()
            decoded = base64.b64decode(encoded).decode("utf-8")
            user, pwd = decoded.split(":", 1)
            if secrets.compare_digest(user, ADMIN_USER) and secrets.compare_digest(pwd, ADMIN_PASS):
                return user
        except Exception:
            pass

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized: Admin credentials or valid X-Staff-Token required.",
        headers={"WWW-Authenticate": 'Basic realm="CVRMS Protected API"'},
    )


# =============================================================================
# FASTAPI INSTANCE (DEFAULT SWAGGER URLS DISABLED)
# =============================================================================
app = FastAPI(
    title="Casa Vista Resort Management System (CVRMS) API",
    description="Backend API supporting Resort Accommodations, Sports Amenities, Cashless Payments, and POS Retail Modules.",
    version="2.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


# =============================================================================
# PROTECTED SWAGGER ROUTES (BASIC AUTH POPUP, NO GREEN LOCK)
# =============================================================================
@app.get("/docs", include_in_schema=False)
async def get_swagger_ui(username: str = Depends(verify_swagger_credentials)):
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="CVRMS API - Swagger UI",
        swagger_ui_parameters={"supportedSubmitMethods": ["get", "post", "put", "delete", "patch"]},
    )


@app.get("/redoc", include_in_schema=False)
async def get_redoc_ui(username: str = Depends(verify_swagger_credentials)):
    return get_redoc_html(openapi_url="/openapi.json", title="CVRMS API - ReDoc")


@app.get("/openapi.json", include_in_schema=False)
async def get_openapi_schema(username: str = Depends(verify_swagger_credentials)):
    schema = get_openapi(
        title=app.title,
        version=app.version,
        routes=app.routes,
        description=app.description,
    )
    schema.pop("security", None)
    if "components" in schema:
        schema["components"].pop("securitySchemes", None)
    return JSONResponse(schema)


@asynccontextmanager
async def acquire_db_connection():
    pool = getattr(app.state, "pool", None)
    if pool is None or getattr(pool, "_closed", True):
        app.state.pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=1,
            max_size=5,
            statement_cache_size=0,
        )
    async with app.state.pool.acquire() as conn:
        yield conn


# =============================================================================
# PYDANTIC SCHEMAS
# =============================================================================

# --- AUTHENTICATION & REGISTRATION SCHEMAS ---
class CustomerRegisterRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    first_name: str = Field(min_length=1, max_length=50)
    middle_name: Optional[str] = Field(default=None, max_length=50)
    last_name: str = Field(min_length=1, max_length=50)
    email: EmailStr
    phone: str = Field(min_length=7, max_length=20)
    address: str = Field(min_length=2, max_length=255)
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=4, max_length=128)
    gender: Optional[str] = Field(default=None, max_length=30)
    birthdate: Optional[str] = Field(default=None, max_length=30)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.lower().strip()


class CustomerLoginRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    identifier: str = Field(min_length=1, max_length=120, description="Email address or Username")
    password: str = Field(min_length=1, max_length=128)


# --- CUSTOMER SCHEMAS ---
class CustomerBase(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    first_name: str = Field(min_length=1, max_length=50)
    middle_name: Optional[str] = Field(default=None, max_length=50)
    last_name: str = Field(min_length=1, max_length=50)
    email: Optional[str] = Field(default=None, max_length=120)
    phone: str = Field(min_length=7, max_length=20)
    address: Optional[str] = Field(default=None, max_length=255)
    customer_type: Literal["Registered", "Walk-In"] = "Registered"

    @field_validator("first_name", "last_name", "middle_name")
    @classmethod
    def sanitize_names(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return None
        return v.strip()

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: Optional[str]) -> Optional[str]:
        return v.lower().strip() if v else None


class CustomerCreate(CustomerBase):
    @model_validator(mode="after")
    def validate_customer_completeness(self) -> CustomerCreate:
        if self.customer_type == "Registered":
            if not self.email or not str(self.email).strip():
                raise ValueError("Registered customers require an email address.")
            if not self.phone or not self.phone.strip():
                raise ValueError("Registered customers require a phone number.")
            if not self.address or not self.address.strip():
                raise ValueError("Registered customers require a home address.")
        return self


class CustomerSyncGoogle(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr
    first_name: str = Field(min_length=1, max_length=50)
    middle_name: Optional[str] = Field(default=None, max_length=50)
    last_name: str = Field(min_length=1, max_length=50)
    phone: Optional[str] = Field(default="09123456789", max_length=20)
    address: Optional[str] = Field(default="Cebu City", max_length=255)
    birthdate: Optional[str] = Field(default=None, max_length=30)
    gender: Optional[str] = Field(default=None, max_length=30)
    customer_type: Literal["Registered", "Walk-In"] = "Registered"


class CustomerUpdate(CustomerBase):
    pass


class CustomerResponse(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    customer_id: str
    first_name: str
    middle_name: Optional[str] = None
    last_name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    customer_type: str = "Registered"
    username: Optional[str] = None
    gender: Optional[str] = None
    birthdate: Optional[str] = None


# --- STAFF SCHEMAS ---
class StaffBase(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    first_name: str = Field(min_length=1, max_length=50)
    middle_name: Optional[str] = Field(default=None, max_length=50)
    last_name: str = Field(min_length=1, max_length=50)
    role: Literal["Front Desk", "Cashier", "Manager", "Admin"] = "Front Desk"


class StaffCreate(StaffBase):
    staff_id: str = Field(min_length=3, max_length=10, examples=["STF-001"])


class StaffUpdate(StaffBase):
    pass


class StaffResponse(StaffBase):
    staff_id: str


# --- ROOM SCHEMAS ---
class RoomBase(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    room_number: str = Field(min_length=1, max_length=10)
    rate_per_day: Decimal = Field(ge=Decimal("0.00"), decimal_places=2)
    max_pax: int = Field(gt=0)
    status: Literal["Ready", "Occupied", "Cleaning", "Maintenance"] = "Ready"
    room_type: Literal["Standard", "Deluxe"] = "Standard"


class RoomCreate(RoomBase):
    room_id: str = Field(min_length=3, max_length=10, examples=["RM-101"])


class RoomUpdate(RoomBase):
    pass


class RoomResponse(RoomBase):
    room_id: str


# --- COURT SCHEMAS ---
class CourtBase(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    court_name: str = Field(min_length=2, max_length=50)
    court_type: Literal["Pickleball", "Basketball"]
    rate_daytime: Decimal = Field(ge=Decimal("0.00"), decimal_places=2)
    rate_nighttime: Decimal = Field(ge=Decimal("0.00"), decimal_places=2)
    paddle_rate: Decimal = Field(default=Decimal("0.00"), ge=Decimal("0.00"), decimal_places=2)


class CourtCreate(CourtBase):
    court_id: str = Field(min_length=3, max_length=10, examples=["CRT-01"])


class CourtUpdate(CourtBase):
    pass


class CourtResponse(CourtBase):
    court_id: str


# --- BOOKING SCHEMAS ---
class BookingBase(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    customer_id: str = Field(min_length=3, max_length=120)
    customer_email: Optional[str] = Field(default=None, max_length=120)
    staff_id: Optional[str] = Field(default=None, max_length=10)
    room_id: Optional[str] = Field(default=None, max_length=10)
    room_ids: Optional[List[str]] = Field(default=None)
    court_id: Optional[str] = Field(default=None, max_length=10)
    booking_date: date = Field(default_factory=lambda: datetime.now(PH_TZ).date())
    start_time: Optional[time] = None
    end_time: Optional[time] = None
    check_in_date: Optional[date] = None
    check_out_date: Optional[date] = None
    exclusive: bool = False
    paddle_count: int = Field(default=0, ge=0)
    status: Literal["Pending", "Confirmed", "Checked-In", "Completed", "Cancelled"] = "Pending"
    total_amount: Decimal = Field(default=Decimal("0.00"), ge=Decimal("0.00"))

    @model_validator(mode="after")
    def validate_exclusive_booking_arc(self) -> BookingBase:
        has_rooms = (self.room_ids is not None and len(self.room_ids) > 0) or (self.room_id is not None and self.room_id.strip() != "")
        has_court = self.court_id is not None and self.court_id.strip() != ""

        if not (has_rooms ^ has_court):
            raise ValueError("A booking must be assigned to either Accommodation Rooms OR a Sports Court, never both and never neither.")

        if has_rooms and (self.check_in_date is None or self.check_out_date is None):
            raise ValueError("Room bookings require both check_in_date and check_out_date.")

        if has_court and (self.start_time is None or self.end_time is None):
            raise ValueError("Court reservations require both start_time and end_time.")

        return self


class BookingCreate(BookingBase):
    booking_id: str = Field(min_length=3, max_length=15, examples=["BK-001"])


class BookingUpdate(BookingBase):
    pass


class BookingResponse(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    booking_id: str
    customer_id: str
    customer_email: Optional[str] = None
    staff_id: Optional[str] = None
    court_id: Optional[str] = None
    room_id: Optional[str] = None
    room_ids: List[str] = Field(default_factory=list)
    booking_date: date
    start_time: Optional[time] = None
    end_time: Optional[time] = None
    check_in_date: Optional[date] = None
    check_out_date: Optional[date] = None
    exclusive: bool = False
    paddle_count: int = 0
    status: str = "Pending"
    total_amount: Decimal = Decimal("0.00")
    created_at: datetime
    hold_expires_at: Optional[datetime] = None


# --- PAYMENT SCHEMAS ---
class PaymentCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    payment_id: str = Field(min_length=3, max_length=15, examples=["PAY-001"])
    booking_id: Optional[str] = Field(default=None, max_length=15)
    order_id: Optional[str] = Field(default=None, max_length=15)
    amount: Decimal = Field(gt=Decimal("0.00"), decimal_places=2)
    method: Literal["Cash", "Card", "GCash", "Maya", "Online Gateway"]
    payment_type: Literal["Payment", "Refund"] = "Payment"

    @model_validator(mode="after")
    def validate_exclusive_payment_arc(self) -> PaymentCreate:
        has_booking = self.booking_id is not None and self.booking_id.strip() != ""
        has_order = self.order_id is not None and self.order_id.strip() != ""
        if not (has_booking ^ has_order):
            raise ValueError("A payment must link to either a Booking OR a POS Order, never both and never neither.")
        return self


class PaymentResponse(BaseModel):
    payment_id: str
    booking_id: Optional[str] = None
    order_id: Optional[str] = None
    amount: Decimal
    method: str
    payment_type: str
    paid_at: datetime


# --- POS SCHEMAS ---
class POSItemBase(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=100)
    category: str = Field(min_length=2, max_length=50)
    price: Decimal = Field(ge=Decimal("0.00"), decimal_places=2)


class POSItemCreate(POSItemBase):
    item_id: str = Field(min_length=3, max_length=10, examples=["ITM-001"])


class POSItemUpdate(POSItemBase):
    pass


class POSItemResponse(POSItemBase):
    item_id: str


class POSOrderItemCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    item_id: str = Field(min_length=3, max_length=10)
    quantity: int = Field(gt=0)


class POSOrderItemResponse(BaseModel):
    order_id: str
    item_id: str
    quantity: int
    subtotal: Decimal


class POSOrderCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    order_id: str = Field(min_length=3, max_length=15, examples=["ORD-001"])
    customer_id: Optional[str] = Field(default=None, max_length=20)
    staff_id: str = Field(min_length=3, max_length=10)
    booking_id: Optional[str] = Field(default=None, max_length=15)
    items: List[POSOrderItemCreate] = Field(min_length=1)


class POSOrderResponse(BaseModel):
    order_id: str
    customer_id: Optional[str] = None
    staff_id: str
    booking_id: Optional[str] = None
    order_date: datetime
    total_amount: Decimal
    items: List[POSOrderItemResponse] = []


# =============================================================================
# EXCEPTION DISPATCHER
# =============================================================================
def handle_db_exception(err: Exception) -> None:
    print(f"\n>>> [DATABASE ERROR CAUGHT]: {type(err).__name__} -> {err}\n")

    err_msg = str(err)
    if "Exclusive booking blocked" in err_msg or "Court booking blocked" in err_msg:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"ERR-409-COLLISION: {err_msg}"
        )

    if isinstance(err, asyncpg.ExclusionViolationError):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ERR-409-ROOM-COLLISION: Sorry, this suite or sports court is already reserved for your selected dates/time. Please select a different date range or facility."
        )

    if isinstance(err, asyncpg.UniqueViolationError):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ERR-409-DUPLICATE: An account or reservation with this email, username, or reference ID already exists."
        )

    if isinstance(err, asyncpg.ForeignKeyViolationError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ERR-400-INVALID-REF: Sorry, the referenced customer, staff, room, or court ID was not found."
        )

    if isinstance(err, asyncpg.CheckViolationError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ERR-400-RULE-VIOLATION: Sorry, your request violates resort booking policies (e.g. invalid stay dates or capacity limit)."
        )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"ERR-400-SYSTEM-ISSUE: Reservation request failed. ({type(err).__name__}: {err_msg})"
    )


# =============================================================================
# ROOT ENDPOINT
# =============================================================================
@app.get("/")
def read_root():
    return {
        "system": "Casa Vista Resort Management System (CVRMS) API",
        "status": "Operational",
        "version": "2.0.0",
        "schemas": ["resort", "pos"],
    }


# =============================================================================
# IN-MEMORY OTP VERIFICATION & STRICT AUTHENTICATION
# =============================================================================
verification_store: dict[str, dict] = {}


class SendVerificationCodeRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.lower()


class VerifyCodeRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: EmailStr
    code: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.lower()


@app.post("/auth/send-verification-code", status_code=status.HTTP_200_OK, tags=["Authentication"])
async def send_verification_code(req: SendVerificationCodeRequest):
    email_clean = req.email.lower()
    otp_code = f"{random.randint(100000, 999999):06d}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

    verification_store[email_clean] = {"code": otp_code, "expires_at": expires_at}

    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_password = os.getenv("SMTP_PASSWORD", "")

    email_sent = False
    if smtp_user and smtp_password:
        try:
            msg = MIMEText(
                f"Hello,\n\nYour Casa Vista Resort verification code is: {otp_code}\n\n"
                f"This code will expire in 5 minutes.\n\nThank you,\nCasa Vista Resort Team"
            )
            msg["Subject"] = "Casa Vista Resort - Email Verification Code"
            msg["From"] = smtp_user
            msg["To"] = email_clean

            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
            email_sent = True
        except Exception as err:
            print(f"Notice: SMTP dispatch failed ({err}). Dev code: {otp_code}")

    return {
        "status": "success",
        "message": "Verification code sent to email." if email_sent else f"Verification code generated ([DEV OTP]: {otp_code}).",
        "email": email_clean,
        "dev_otp": otp_code,
    }


@app.post("/auth/verify-code", status_code=status.HTTP_200_OK, tags=["Authentication"])
async def verify_code(req: VerifyCodeRequest):
    email_clean = req.email.lower()
    user_code = req.code.strip()

    entry = verification_store.get(email_clean)
    if not entry:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired code. Please try again.")

    if datetime.now(timezone.utc) > entry["expires_at"]:
        verification_store.pop(email_clean, None)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired code. Please try again.")

    if entry["code"] != user_code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired code. Please try again.")

    verification_store.pop(email_clean, None)
    return {"verified": True, "message": "Email verified successfully."}


@app.post("/auth/register", status_code=status.HTTP_201_CREATED, response_model=CustomerResponse, tags=["Authentication"])
async def register_customer_account(req: CustomerRegisterRequest):
    async with acquire_db_connection() as conn:
        async with conn.transaction():
            try:
                await ensure_credentials_table(conn)

                # Clean up any legacy malformed C-XXXXXXXX dummy accounts without bookings
                await conn.execute(
                    """
                    DELETE FROM resort.customer c
                    WHERE c.customer_id LIKE 'C-%'
                      AND NOT EXISTS (SELECT 1 FROM resort.booking b WHERE b.customer_id = c.customer_id)
                      AND NOT EXISTS (SELECT 1 FROM pos.pos_order o WHERE o.customer_id = c.customer_id)
                    """
                )

                # Check if username is already taken by another customer
                username_conflict = await conn.fetchrow(
                    """
                    SELECT cc.customer_id, c.email
                    FROM resort.customer_credentials cc
                    JOIN resort.customer c ON c.customer_id = cc.customer_id
                    WHERE LOWER(cc.username) = LOWER($1) AND LOWER(c.email) <> LOWER($2)
                    """,
                    req.username.strip(),
                    req.email.lower().strip(),
                )
                if username_conflict:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Username is already taken. Please choose a different username.",
                    )

                existing_cust = await conn.fetchrow(
                    """
                    SELECT customer_id FROM resort.customer WHERE LOWER(email) = LOWER($1)
                    """,
                    req.email.lower().strip(),
                )

                if existing_cust:
                    cust_id = existing_cust["customer_id"]
                    existing_cred = await conn.fetchrow(
                        "SELECT customer_id FROM resort.customer_credentials WHERE customer_id = $1",
                        cust_id,
                    )
                    if existing_cred:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail="An account with this email is already registered. Please log in instead.",
                        )
                    row = await conn.fetchrow(
                        """
                        UPDATE resort.customer
                        SET first_name = $1, middle_name = $2, last_name = $3, phone = $4, address = $5, customer_type = 'Registered'
                        WHERE customer_id = $6
                        RETURNING customer_id, first_name, middle_name, last_name, email, phone, address, customer_type
                        """,
                        req.first_name,
                        req.middle_name,
                        req.last_name,
                        req.phone,
                        req.address,
                        cust_id,
                    )
                else:
                    cust_id = await get_next_customer_id(conn)
                    row = await conn.fetchrow(
                        """
                        INSERT INTO resort.customer (customer_id, first_name, middle_name, last_name, email, phone, address, customer_type)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, 'Registered')
                        RETURNING customer_id, first_name, middle_name, last_name, email, phone, address, customer_type
                        """,
                        cust_id,
                        req.first_name,
                        req.middle_name,
                        req.last_name,
                        req.email.lower().strip(),
                        req.phone,
                        req.address,
                    )

                pwd_hash = hash_password(req.password)
                await conn.execute(
                    """
                    INSERT INTO resort.customer_credentials (customer_id, username, password_hash, gender, birthdate, updated_at)
                    VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
                    ON CONFLICT (customer_id) DO UPDATE
                    SET username = EXCLUDED.username,
                        password_hash = EXCLUDED.password_hash,
                        gender = COALESCE(EXCLUDED.gender, resort.customer_credentials.gender),
                        birthdate = COALESCE(EXCLUDED.birthdate, resort.customer_credentials.birthdate),
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    cust_id,
                    req.username.strip(),
                    pwd_hash,
                    req.gender,
                    req.birthdate,
                )

                result = dict(row)
                result["username"] = req.username.strip()
                result["gender"] = req.gender
                result["birthdate"] = req.birthdate
                return result

            except HTTPException:
                raise
            except Exception as err:
                handle_db_exception(err)


@app.post("/auth/login", status_code=status.HTTP_200_OK, response_model=CustomerResponse, tags=["Authentication"])
async def login_customer_account(req: CustomerLoginRequest):
    async with acquire_db_connection() as conn:
        await ensure_credentials_table(conn)

        identifier = req.identifier.strip()
        password = req.password

        # Clean up any legacy malformed C-XXXXXXXX dummy accounts without bookings
        await conn.execute(
            """
            DELETE FROM resort.customer c
            WHERE c.customer_id LIKE 'C-%'
              AND NOT EXISTS (SELECT 1 FROM resort.booking b WHERE b.customer_id = c.customer_id)
              AND NOT EXISTS (SELECT 1 FROM pos.pos_order o WHERE o.customer_id = c.customer_id)
            """
        )

        # Look up account by Email OR Username
        row = await conn.fetchrow(
            """
            SELECT c.customer_id, c.first_name, c.middle_name, c.last_name, c.email, c.phone, c.address, c.customer_type,
                   cc.username, cc.password_hash, cc.gender, cc.birthdate
            FROM resort.customer c
            LEFT JOIN resort.customer_credentials cc ON c.customer_id = cc.customer_id
            WHERE LOWER(c.email) = LOWER($1)
               OR LOWER(cc.username) = LOWER($1)
            LIMIT 1
            """,
            identifier,
        )

        # Built-in Demo Test Account support (only if explicitly logging in as test12345@casavista.com or test12345)
        if row is None and identifier.lower() in ("test12345@casavista.com", "test12345") and password == "test12345":
            async with conn.transaction():
                cust_id = await get_next_customer_id(conn)
                cust_row = await conn.fetchrow(
                    """
                    INSERT INTO resort.customer (customer_id, first_name, last_name, email, phone, address, customer_type)
                    VALUES ($1, 'Test', 'User', 'test12345@casavista.com', '09123456789', 'Cebu City', 'Registered')
                    ON CONFLICT (email) DO UPDATE SET first_name = EXCLUDED.first_name
                    RETURNING customer_id, first_name, middle_name, last_name, email, phone, address, customer_type
                    """,
                    cust_id,
                )
                actual_id = cust_row["customer_id"]
                await conn.execute(
                    """
                    INSERT INTO resort.customer_credentials (customer_id, username, password_hash, gender, birthdate)
                    VALUES ($1, 'test12345', $2, 'Male', '01/01/2000')
                    ON CONFLICT (customer_id) DO NOTHING
                    """,
                    actual_id,
                    hash_password("test12345"),
                )
                res = dict(cust_row)
                res["username"] = "test12345"
                res["gender"] = "Male"
                res["birthdate"] = "01/01/2000"
                return res

        if row is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account not found. Please register an account first.",
            )

        stored_hash = row["password_hash"]
        if not stored_hash:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="This account does not have a password set yet. Please sign up or use Google Sign-In.",
            )

        if not verify_password(password, stored_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect password. Please try again.",
            )

        return {
            "customer_id": row["customer_id"],
            "first_name": row["first_name"],
            "middle_name": row["middle_name"],
            "last_name": row["last_name"],
            "email": row["email"],
            "phone": row["phone"],
            "address": row["address"],
            "customer_type": row["customer_type"],
            "username": row["username"],
            "gender": row["gender"],
            "birthdate": row["birthdate"],
        }


# =============================================================================
# RESORT MODULE: CUSTOMERS CRUD
# =============================================================================
@app.get("/customers", response_model=List[CustomerResponse], tags=["Customers"])
async def get_customers():
    async with acquire_db_connection() as conn:
        await ensure_credentials_table(conn)
        rows = await conn.fetch(
            """
            SELECT c.customer_id, c.first_name, c.middle_name, c.last_name, c.email, c.phone, c.address, c.customer_type,
                   cc.username, cc.gender, cc.birthdate
            FROM resort.customer c
            LEFT JOIN resort.customer_credentials cc ON c.customer_id = cc.customer_id
            ORDER BY c.customer_id
            """
        )
        return [dict(r) for r in rows]


@app.get("/customers/{customer_id}", response_model=CustomerResponse, tags=["Customers"])
async def get_customer(customer_id: str):
    async with acquire_db_connection() as conn:
        await ensure_credentials_table(conn)
        row = await conn.fetchrow(
            """
            SELECT c.customer_id, c.first_name, c.middle_name, c.last_name, c.email, c.phone, c.address, c.customer_type,
                   cc.username, cc.gender, cc.birthdate
            FROM resort.customer c
            LEFT JOIN resort.customer_credentials cc ON c.customer_id = cc.customer_id
            WHERE c.customer_id = $1
               OR LOWER(c.email) = LOWER($1)
               OR LOWER(cc.username) = LOWER($1)
            """,
            customer_id,
        )
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found.")
        return dict(row)


@app.post(
    "/customers",
    status_code=status.HTTP_201_CREATED,
    response_model=CustomerResponse,
    tags=["Customers"],
)
async def create_customer(customer: CustomerCreate):
    async with acquire_db_connection() as conn:
        async with conn.transaction():
            try:
                cust_id = await get_next_customer_id(conn)
                row = await conn.fetchrow(
                    """
                    INSERT INTO resort.customer (customer_id, first_name, middle_name, last_name, email, phone, address, customer_type)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    RETURNING customer_id, first_name, middle_name, last_name, email, phone, address, customer_type
                    """,
                    cust_id,
                    customer.first_name,
                    customer.middle_name,
                    customer.last_name,
                    customer.email,
                    customer.phone,
                    customer.address,
                    customer.customer_type,
                )
                return dict(row)
            except Exception as err:
                handle_db_exception(err)


@app.post(
    "/customers/sync-google",
    status_code=status.HTTP_200_OK,
    response_model=CustomerResponse,
    tags=["Customers"],
)
async def sync_google_customer(customer: CustomerSyncGoogle):
    async with acquire_db_connection() as conn:
        async with conn.transaction():
            try:
                await ensure_credentials_table(conn)
                phone_val = customer.phone if customer.phone and customer.phone.strip() and customer.phone != "N/A" else "09123456789"
                address_val = customer.address if customer.address and customer.address.strip() and customer.address != "N/A" else "Cebu City"

                existing = await conn.fetchrow(
                    """
                    UPDATE resort.customer
                    SET first_name = $1,
                        middle_name = COALESCE($2, middle_name),
                        last_name = $3,
                        phone = CASE WHEN $4 = '09123456789' THEN phone ELSE $4 END,
                        address = CASE WHEN $5 = 'Cebu City' THEN address ELSE $5 END
                    WHERE LOWER(email) = LOWER($6)
                    RETURNING customer_id, first_name, middle_name, last_name, email, phone, address, customer_type
                    """,
                    customer.first_name,
                    customer.middle_name,
                    customer.last_name,
                    phone_val,
                    address_val,
                    str(customer.email).lower().strip(),
                )

                if existing:
                    cust_id = existing["customer_id"]
                    res = dict(existing)
                else:
                    cust_id = await get_next_customer_id(conn)
                    row = await conn.fetchrow(
                        """
                        INSERT INTO resort.customer (customer_id, first_name, middle_name, last_name, email, phone, address, customer_type)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, 'Registered')
                        RETURNING customer_id, first_name, middle_name, last_name, email, phone, address, customer_type
                        """,
                        cust_id,
                        customer.first_name,
                        customer.middle_name,
                        customer.last_name,
                        str(customer.email).lower().strip(),
                        phone_val,
                        address_val,
                    )
                    res = dict(row)

                if customer.gender or customer.birthdate:
                    await conn.execute(
                        """
                        INSERT INTO resort.customer_credentials (customer_id, password_hash, gender, birthdate, updated_at)
                        VALUES ($1, '', $2, $3, CURRENT_TIMESTAMP)
                        ON CONFLICT (customer_id) DO UPDATE
                        SET gender = COALESCE(EXCLUDED.gender, resort.customer_credentials.gender),
                            birthdate = COALESCE(EXCLUDED.birthdate, resort.customer_credentials.birthdate),
                            updated_at = CURRENT_TIMESTAMP
                        """,
                        cust_id,
                        customer.gender,
                        customer.birthdate,
                    )

                cred = await conn.fetchrow(
                    "SELECT username, gender, birthdate FROM resort.customer_credentials WHERE customer_id = $1",
                    cust_id,
                )
                if cred:
                    res["username"] = cred["username"]
                    res["gender"] = cred["gender"]
                    res["birthdate"] = cred["birthdate"]
                return res
            except Exception as err:
                handle_db_exception(err)


@app.put(
    "/customers/{customer_id}",
    response_model=CustomerResponse,
    tags=["Customers"],
    dependencies=[Depends(verify_staff_token)],
)
async def update_customer(customer_id: str, customer: CustomerUpdate):
    async with acquire_db_connection() as conn:
        try:
            row = await conn.fetchrow(
                """
                UPDATE resort.customer
                SET first_name = $1, middle_name = $2, last_name = $3, email = $4, phone = $5, address = $6, customer_type = $7
                WHERE customer_id = $8 OR LOWER(email) = LOWER($8)
                RETURNING customer_id, first_name, middle_name, last_name, email, phone, address, customer_type
                """,
                customer.first_name,
                customer.middle_name,
                customer.last_name,
                customer.email,
                customer.phone,
                customer.address,
                customer.customer_type,
                customer_id,
            )
            if row is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found.")
            return dict(row)
        except Exception as err:
            handle_db_exception(err)


@app.delete(
    "/customers/{customer_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Customers"],
    dependencies=[Depends(verify_staff_token)],
)
async def delete_customer(customer_id: str):
    async with acquire_db_connection() as conn:
        try:
            status_text = await conn.execute("DELETE FROM resort.customer WHERE customer_id = $1", customer_id)
            if status_text.split()[-1] == "0":
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found.")
            return None
        except Exception as err:
            handle_db_exception(err)


# =============================================================================
# RESORT MODULE: STAFF CRUD
# =============================================================================
@app.get("/staff", response_model=List[StaffResponse], tags=["Staff"])
async def get_staff_members():
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(
            """
            SELECT staff_id, first_name, middle_name, last_name, role
            FROM resort.staff
            ORDER BY staff_id
            """
        )
        return [dict(r) for r in rows]


@app.post("/staff", status_code=status.HTTP_201_CREATED, response_model=StaffResponse, tags=["Staff"])
async def create_staff(staff: StaffCreate):
    async with acquire_db_connection() as conn:
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO resort.staff (staff_id, first_name, middle_name, last_name, role)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING staff_id, first_name, middle_name, last_name, role
                """,
                staff.staff_id,
                staff.first_name,
                staff.middle_name,
                staff.last_name,
                staff.role,
            )
            return dict(row)
        except Exception as err:
            handle_db_exception(err)


# =============================================================================
# RESORT MODULE: ROOM INVENTORY CRUD
# =============================================================================
@app.get("/rooms", response_model=List[RoomResponse], tags=["Rooms"])
async def get_rooms(status_filter: Optional[str] = Query(default=None, alias="status")):
    async with acquire_db_connection() as conn:
        if status_filter:
            rows = await conn.fetch(
                """
                SELECT room_id, room_number, rate_per_day, max_pax, status, room_type
                FROM resort.room
                WHERE status = $1
                ORDER BY room_number
                """,
                status_filter,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT room_id, room_number, rate_per_day, max_pax, status, room_type
                FROM resort.room
                ORDER BY room_number
                """
            )
        return [dict(r) for r in rows]


@app.get("/rooms/{room_id}", response_model=RoomResponse, tags=["Rooms"])
async def get_room(room_id: str):
    async with acquire_db_connection() as conn:
        row = await conn.fetchrow(
            """
            SELECT room_id, room_number, rate_per_day, max_pax, status, room_type
            FROM resort.room
            WHERE room_id = $1
            """,
            room_id,
        )
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found.")
        return dict(row)


@app.post(
    "/rooms",
    status_code=status.HTTP_201_CREATED,
    response_model=RoomResponse,
    tags=["Rooms"],
    dependencies=[Depends(verify_staff_token)],
)
async def create_room(room: RoomCreate):
    async with acquire_db_connection() as conn:
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO resort.room (room_id, room_number, rate_per_day, max_pax, status, room_type)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING room_id, room_number, rate_per_day, max_pax, status, room_type
                """,
                room.room_id,
                room.room_number,
                room.rate_per_day,
                room.max_pax,
                room.status,
                room.room_type,
            )
            return dict(row)
        except Exception as err:
            handle_db_exception(err)


@app.put(
    "/rooms/{room_id}",
    response_model=RoomResponse,
    tags=["Rooms"],
    dependencies=[Depends(verify_staff_token)],
)
async def update_room(room_id: str, room: RoomUpdate):
    async with acquire_db_connection() as conn:
        try:
            row = await conn.fetchrow(
                """
                UPDATE resort.room
                SET room_number = $1, rate_per_day = $2, max_pax = $3, status = $4, room_type = $5
                WHERE room_id = $6
                RETURNING room_id, room_number, rate_per_day, max_pax, status, room_type
                """,
                room.room_number,
                room.rate_per_day,
                room.max_pax,
                room.status,
                room.room_type,
                room_id,
            )
            if row is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found.")
            return dict(row)
        except Exception as err:
            handle_db_exception(err)


# =============================================================================
# RESORT MODULE: SPORTS COURTS CRUD
# =============================================================================
@app.get("/courts", response_model=List[CourtResponse], tags=["Courts"])
async def get_courts():
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(
            """
            SELECT court_id, court_name, court_type, rate_daytime, rate_nighttime, paddle_rate
            FROM resort.court
            ORDER BY court_id
            """
        )
        return [dict(r) for r in rows]


@app.get("/courts/calculate-price", tags=["Courts"])
def calculate_court_price(
    court_type: Literal["Pickleball", "Basketball"],
    start_time: time = Query(..., description="Start time e.g. 08:00"),
    end_time: time = Query(..., description="End time e.g. 10:00"),
    paddle_count: int = Query(default=0, ge=0),
):
    if start_time >= end_time:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="start_time must be earlier than end_time.",
        )

    day_rate = Decimal("400.00") if court_type == "Pickleball" else Decimal("500.00")
    night_rate = Decimal("600.00") if court_type == "Pickleball" else Decimal("750.00")
    paddle_rate = Decimal("100.00")

    st_hours = start_time.hour + start_time.minute / 60.0
    et_hours = end_time.hour + end_time.minute / 60.0

    day_hours = max(0.0, min(et_hours, 18.0) - max(st_hours, 6.0))
    night_hours = max(0.0, min(et_hours, 22.0) - max(st_hours, 18.0))

    court_cost = (Decimal(str(day_hours)) * day_rate) + (Decimal(str(night_hours)) * night_rate)
    paddle_cost = Decimal(paddle_count) * paddle_rate
    total_cost = court_cost + paddle_cost

    return {
        "court_type": court_type,
        "start_time": start_time.strftime("%H:%M"),
        "end_time": end_time.strftime("%H:%M"),
        "daytime_hours": day_hours,
        "nighttime_hours": night_hours,
        "court_cost": court_cost,
        "paddle_count": paddle_count,
        "paddle_cost": paddle_cost,
        "total_cost": total_cost,
    }


@app.get("/courts/{court_id}/availability", tags=["Courts"])
async def get_court_availability(
    court_id: str,
    booking_date: date = Query(default_factory=lambda: datetime.now(PH_TZ).date(), description="Booking date (YYYY-MM-DD)"),
):
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(
            """
            SELECT booking_id, customer_id, staff_id, court_id, booking_date,
                   start_time, end_time, exclusive, paddle_count, status,
                   created_at, hold_expires_at
            FROM resort.booking
            WHERE court_id = $1
              AND booking_date = $2
              AND (
                  status IN ('Confirmed', 'Checked-In')
                  OR (status = 'Pending' AND hold_expires_at > CURRENT_TIMESTAMP)
              )
            ORDER BY start_time
            """,
            court_id,
            booking_date,
        )
        return {
            "court_id": court_id,
            "booking_date": booking_date,
            "reserved_slots": [dict(r) for r in rows],
        }


@app.post(
    "/courts",
    status_code=status.HTTP_201_CREATED,
    response_model=CourtResponse,
    tags=["Courts"],
    dependencies=[Depends(verify_staff_token)],
)
async def create_court(court: CourtCreate):
    async with acquire_db_connection() as conn:
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO resort.court (court_id, court_name, court_type, rate_daytime, rate_nighttime, paddle_rate)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING court_id, court_name, court_type, rate_daytime, rate_nighttime, paddle_rate
                """,
                court.court_id,
                court.court_name,
                court.court_type,
                court.rate_daytime,
                court.rate_nighttime,
                court.paddle_rate,
            )
            return dict(row)
        except Exception as err:
            handle_db_exception(err)


# =============================================================================
# RESORT MODULE: RESERVATIONS & BOOKINGS CRUD
# =============================================================================
@app.get("/bookings", response_model=List[BookingResponse], tags=["Bookings"])
async def get_bookings(status_filter: Optional[str] = Query(default=None, alias="status")):
    base_query = """
        SELECT 
            b.booking_id, b.customer_id, c.email AS customer_email, b.staff_id, b.court_id, b.booking_date,
            b.start_time, b.end_time, b.check_in_date, b.check_out_date, b.exclusive,
            b.paddle_count, b.status, b.created_at, b.hold_expires_at, b.total_amount,
            COALESCE(
                (SELECT array_agg(br.room_id) FROM resort.booking_room br WHERE br.booking_id = b.booking_id),
                ARRAY[]::varchar[]
            ) AS room_ids
        FROM resort.booking b
        LEFT JOIN resort.customer c ON b.customer_id = c.customer_id
    """
    async with acquire_db_connection() as conn:
        if status_filter:
            rows = await conn.fetch(base_query + " WHERE b.status = $1 ORDER BY b.created_at DESC", status_filter)
        else:
            rows = await conn.fetch(base_query + " ORDER BY b.created_at DESC")

        results = []
        for r in rows:
            item = dict(r)
            r_ids = list(item.get("room_ids") or [])
            item["room_ids"] = r_ids
            item["room_id"] = r_ids[0] if r_ids else None
            results.append(item)
        return results


@app.get("/bookings/active", response_model=List[BookingResponse], tags=["Bookings"])
async def get_active_bookings():
    query = """
        SELECT 
            b.booking_id, b.customer_id, c.email AS customer_email, b.staff_id, b.court_id, b.booking_date,
            b.start_time, b.end_time, b.check_in_date, b.check_out_date, b.exclusive,
            b.paddle_count, b.status, b.created_at, b.hold_expires_at, b.total_amount,
            COALESCE(
                (SELECT array_agg(br.room_id) FROM resort.booking_room br WHERE br.booking_id = b.booking_id),
                ARRAY[]::varchar[]
            ) AS room_ids
        FROM resort.booking b
        LEFT JOIN resort.customer c ON b.customer_id = c.customer_id
        WHERE b.status IN ('Confirmed', 'Checked-In')
           OR (b.status = 'Pending' AND b.hold_expires_at > CURRENT_TIMESTAMP)
        ORDER BY b.created_at DESC
    """
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(query)
        results = []
        for r in rows:
            item = dict(r)
            r_ids = list(item.get("room_ids") or [])
            item["room_ids"] = r_ids
            item["room_id"] = r_ids[0] if r_ids else None
            results.append(item)
        return results


@app.get("/bookings/{booking_id}", response_model=BookingResponse, tags=["Bookings"])
async def get_booking(booking_id: str):
    query = """
        SELECT 
            b.booking_id, b.customer_id, c.email AS customer_email, b.staff_id, b.court_id, b.booking_date,
            b.start_time, b.end_time, b.check_in_date, b.check_out_date, b.exclusive,
            b.paddle_count, b.status, b.created_at, b.hold_expires_at, b.total_amount,
            COALESCE(
                (SELECT array_agg(br.room_id) FROM resort.booking_room br WHERE br.booking_id = b.booking_id),
                ARRAY[]::varchar[]
            ) AS room_ids
        FROM resort.booking b
        LEFT JOIN resort.customer c ON b.customer_id = c.customer_id
        WHERE b.booking_id = $1
    """
    async with acquire_db_connection() as conn:
        row = await conn.fetchrow(query, booking_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found.")
        item = dict(row)
        r_ids = list(item.get("room_ids") or [])
        item["room_ids"] = r_ids
        item["room_id"] = r_ids[0] if r_ids else None
        return item


@app.post(
    "/bookings",
    status_code=status.HTTP_201_CREATED,
    response_model=BookingResponse,
    tags=["Bookings"],
)
async def create_booking(booking: BookingCreate):
    async with acquire_db_connection() as conn:
        async with conn.transaction():
            try:
                now_ph = datetime.now(PH_TZ)
                today_server = now_ph.date()
                now_time_server = now_ph.time()
                target_date = booking.check_in_date or booking.booking_date

                if target_date < today_server:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Booking Failure: Cannot create reservations for past dates!",
                    )

                if target_date == today_server and booking.start_time and booking.start_time < now_time_server:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Booking Failure: Cannot reserve time slots that have already passed for today!",
                    )

                # Resolve Staff ID safely
                staff_id_val = booking.staff_id.strip()[:10] if booking.staff_id and booking.staff_id.strip() else None
                if staff_id_val:
                    await conn.execute(
                        """
                        INSERT INTO resort.staff (staff_id, first_name, last_name, role)
                        VALUES ($1, 'Front Desk', 'Staff', 'Front Desk')
                        ON CONFLICT (staff_id) DO NOTHING
                        """,
                        staff_id_val,
                    )

                # STRICT VERIFICATION: Customer MUST already be registered in resort.customer
                raw_cust = booking.customer_id.strip()
                raw_email = booking.customer_email.strip().lower() if booking.customer_email and booking.customer_email.strip() else ""

                existing_cust = await conn.fetchrow(
                    """
                    SELECT customer_id, email
                    FROM resort.customer
                    WHERE customer_id = $1
                       OR ($2 <> '' AND LOWER(email) = LOWER($2))
                       OR LOWER(email) = LOWER($1)
                    LIMIT 1
                    """,
                    raw_cust,
                    raw_email,
                )

                if not existing_cust:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="ERR-400-UNREGISTERED-ACCOUNT: Your account is not registered in the database. Please log out and sign up for a valid account first.",
                    )

                resolved_customer_id = existing_cust["customer_id"]
                resolved_customer_email = existing_cust["email"]

                is_room_booking = booking.check_in_date is not None and booking.check_out_date is not None

                # Enforce chk_booking_shape constraint at database level
                court_id_val = None if is_room_booking else (booking.court_id.strip()[:10] if booking.court_id and booking.court_id.strip() else None)
                start_time_val = None if is_room_booking else booking.start_time
                end_time_val = None if is_room_booking else booking.end_time
                check_in_val = booking.check_in_date if is_room_booking else None
                check_out_val = booking.check_out_date if is_room_booking else None
                paddle_count_val = 0 if is_room_booking else booking.paddle_count

                target_rooms: List[str] = []
                if is_room_booking:
                    if booking.room_ids and len(booking.room_ids) > 0:
                        target_rooms = [r.strip()[:10] for r in booking.room_ids if r and r.strip()]
                    elif booking.room_id and booking.room_id.strip():
                        target_rooms = [booking.room_id.strip()[:10]]
                    else:
                        target_rooms = ["RM-101"]

                    for r_id in target_rooms:
                        num = r_id.replace("RM-", "")
                        await conn.execute(
                            """
                            INSERT INTO resort.room (room_id, room_number, rate_per_day, max_pax, status, room_type)
                            VALUES ($1, $2, 2500.00, 4, 'Ready', 'Standard')
                            ON CONFLICT (room_id) DO NOTHING
                            """,
                            r_id,
                            num,
                        )

                if court_id_val:
                    is_basketball = "BK" in court_id_val.upper() or "BASKET" in court_id_val.upper()
                    c_type = "Basketball" if is_basketball else "Pickleball"
                    c_name = "Basketball Half-Court" if is_basketball else f"Court {court_id_val}"
                    c_day_rate = Decimal("500.00") if is_basketball else Decimal("400.00")
                    c_night_rate = Decimal("750.00") if is_basketball else Decimal("600.00")
                    c_paddle_rate = Decimal("0.00") if is_basketball else Decimal("100.00")

                    await conn.execute(
                        """
                        INSERT INTO resort.court (court_id, court_name, court_type, rate_daytime, rate_nighttime, paddle_rate)
                        VALUES ($1, $2, $3, $4, $5, $6)
                        ON CONFLICT (court_id) DO NOTHING
                        """,
                        court_id_val,
                        c_name,
                        c_type,
                        c_day_rate,
                        c_night_rate,
                        c_paddle_rate,
                    )

                    collision = await conn.fetchrow(
                        """
                        SELECT booking_id
                        FROM resort.booking
                        WHERE court_id = $1
                          AND booking_date = $2
                          AND status <> 'Cancelled'
                          AND start_time < $4
                          AND end_time > $3
                        LIMIT 1
                        """,
                        court_id_val,
                        booking.booking_date,
                        start_time_val,
                        end_time_val,
                    )
                    if collision:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail="ERR-409-COURT-COLLISION: Sorry, this time slot is already reserved on this court. Please select a different time slot or court.",
                        )

                row = await conn.fetchrow(
                    """
                    INSERT INTO resort.booking (
                        booking_id, customer_id, staff_id, court_id, booking_date,
                        start_time, end_time, check_in_date, check_out_date, exclusive,
                        paddle_count, status, created_at, hold_expires_at, total_amount
                    )
                    VALUES (
                        $1, $2, $3, $4, $5,
                        $6, $7, $8, $9, $10,
                        $11, 'Pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '15 minutes', $12
                    )
                    RETURNING booking_id, customer_id, staff_id, court_id, booking_date,
                              start_time, end_time, check_in_date, check_out_date, exclusive,
                              paddle_count, status, created_at, hold_expires_at, total_amount
                    """,
                    booking.booking_id,
                    resolved_customer_id,
                    staff_id_val,
                    court_id_val,
                    booking.booking_date,
                    start_time_val,
                    end_time_val,
                    check_in_val,
                    check_out_val,
                    booking.exclusive if is_room_booking else False,
                    paddle_count_val,
                    booking.total_amount,
                )

                if is_room_booking:
                    for r_id in target_rooms:
                        rate_row = await conn.fetchrow("SELECT rate_per_day FROM resort.room WHERE room_id = $1", r_id)
                        rate = rate_row["rate_per_day"] if rate_row else Decimal("2500.00")
                        await conn.execute(
                            """
                            INSERT INTO resort.booking_room (booking_id, room_id, rate_per_day)
                            VALUES ($1, $2, $3)
                            """,
                            booking.booking_id,
                            r_id,
                            rate,
                        )

                item = dict(row)
                item["customer_email"] = resolved_customer_email
                item["room_ids"] = target_rooms if is_room_booking else []
                item["room_id"] = target_rooms[0] if (is_room_booking and target_rooms) else None
                return item

            except HTTPException:
                raise
            except Exception as err:
                handle_db_exception(err)


@app.put("/bookings/{booking_id}/status", response_model=BookingResponse, tags=["Bookings"])
async def update_booking_status(
    booking_id: str,
    new_status: Literal["Pending", "Confirmed", "Checked-In", "Completed", "Cancelled"] = Query(..., alias="new_status"),
):
    async with acquire_db_connection() as conn:
        try:
            row = await conn.fetchrow(
                """
                UPDATE resort.booking
                SET status = $1
                WHERE booking_id = $2
                RETURNING booking_id, customer_id, staff_id, court_id, booking_date,
                          start_time, end_time, check_in_date, check_out_date, exclusive,
                          paddle_count, status, created_at, hold_expires_at, total_amount
                """,
                new_status,
                booking_id,
            )
            if row is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found.")

            cust_row = await conn.fetchrow("SELECT email FROM resort.customer WHERE customer_id = $1", row["customer_id"])
            room_rows = await conn.fetch("SELECT room_id FROM resort.booking_room WHERE booking_id = $1", booking_id)
            r_ids = [r["room_id"] for r in room_rows]

            item = dict(row)
            item["customer_email"] = cust_row["email"] if cust_row else None
            item["room_ids"] = r_ids
            item["room_id"] = r_ids[0] if r_ids else None
            return item
        except HTTPException:
            raise
        except Exception as err:
            handle_db_exception(err)


# =============================================================================
# RESORT MODULE: PAYMENT PROCESSING
# =============================================================================
@app.post(
    "/payments",
    status_code=status.HTTP_201_CREATED,
    response_model=PaymentResponse,
    tags=["Payments"],
)
async def process_payment(payment: PaymentCreate):
    async with acquire_db_connection() as conn:
        async with conn.transaction():
            try:
                if payment.payment_type == "Refund" and payment.booking_id:
                    booking = await conn.fetchrow(
                        """
                        SELECT check_in_date, start_time FROM resort.booking
                        WHERE booking_id = $1
                        """,
                        payment.booking_id,
                    )
                    if not booking:
                        raise HTTPException(
                            status_code=status.HTTP_404_NOT_FOUND,
                            detail="Target booking for refund not found.",
                        )

                    sched_date = booking["check_in_date"] or datetime.now(PH_TZ).date()
                    sched_time = booking["start_time"] or time(14, 0)
                    sched_dt = datetime.combine(sched_date, sched_time)

                    if (sched_dt - datetime.now(PH_TZ).replace(tzinfo=None)).total_seconds() < 86400:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Cancellations requested within 24 hours of check-in are strictly non-refundable.",
                        )

                row = await conn.fetchrow(
                    """
                    INSERT INTO resort.payment (payment_id, booking_id, order_id, amount, method, payment_type, paid_at)
                    VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
                    RETURNING payment_id, booking_id, order_id, amount, method, payment_type, paid_at
                    """,
                    payment.payment_id,
                    payment.booking_id if payment.booking_id and payment.booking_id.strip() else None,
                    payment.order_id if payment.order_id and payment.order_id.strip() else None,
                    payment.amount,
                    payment.method,
                    payment.payment_type,
                )

                if payment.booking_id and payment.booking_id.strip() and payment.payment_type == "Payment":
                    await conn.execute(
                        """
                        UPDATE resort.booking
                        SET status = 'Confirmed'
                        WHERE booking_id = $1 AND status = 'Pending'
                        """,
                        payment.booking_id,
                    )

                return dict(row)
            except HTTPException:
                raise
            except Exception as err:
                handle_db_exception(err)


# =============================================================================
# POS MODULE: CATALOG & ORDERS
# =============================================================================
@app.get("/pos/items", response_model=List[POSItemResponse], tags=["POS Catalog"])
async def get_pos_items():
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(
            """
            SELECT item_id, name, category, price
            FROM pos.pos_item
            ORDER BY item_id
            """
        )
        return [dict(r) for r in rows]


@app.post(
    "/pos/items",
    status_code=status.HTTP_201_CREATED,
    response_model=POSItemResponse,
    tags=["POS Catalog"],
    dependencies=[Depends(verify_staff_token)],
)
async def create_pos_item(item: POSItemCreate):
    async with acquire_db_connection() as conn:
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO pos.pos_item (item_id, name, category, price)
                VALUES ($1, $2, $3, $4)
                RETURNING item_id, name, category, price
                """,
                item.item_id,
                item.name,
                item.category,
                item.price,
            )
            return dict(row)
        except Exception as err:
            handle_db_exception(err)


@app.post(
    "/pos/orders",
    status_code=status.HTTP_201_CREATED,
    response_model=POSOrderResponse,
    tags=["POS Orders"],
)
async def create_pos_order(order: POSOrderCreate):
    async with acquire_db_connection() as conn:
        async with conn.transaction():
            try:
                item_ids = [i.item_id for i in order.items]
                price_rows = await conn.fetch(
                    "SELECT item_id, price FROM pos.pos_item WHERE item_id = ANY($1::varchar[])",
                    item_ids,
                )
                price_map = {r["item_id"]: r["price"] for r in price_rows}

                missing = set(item_ids) - set(price_map.keys())
                if missing:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"POS Items not found: {', '.join(missing)}",
                    )

                total_amount = Decimal("0.00")
                line_items_data = []
                for item in order.items:
                    unit_price = price_map[item.item_id]
                    subtotal = unit_price * item.quantity
                    total_amount += subtotal
                    line_items_data.append((order.order_id, item.item_id, item.quantity, subtotal))

                order_row = await conn.fetchrow(
                    """
                    INSERT INTO pos.pos_order (order_id, customer_id, staff_id, booking_id, order_date, total_amount)
                    VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, $5)
                    RETURNING order_id, customer_id, staff_id, booking_id, order_date, total_amount
                    """,
                    order.order_id,
                    order.customer_id,
                    order.staff_id,
                    order.booking_id if order.booking_id and order.booking_id.strip() else None,
                    total_amount,
                )

                inserted_items = []
                for item_record in line_items_data:
                    item_row = await conn.fetchrow(
                        """
                        INSERT INTO pos.pos_order_item (order_id, item_id, quantity, subtotal)
                        VALUES ($1, $2, $3, $4)
                        RETURNING order_id, item_id, quantity, subtotal
                        """,
                        item_record[0],
                        item_record[1],
                        item_record[2],
                        item_record[3],
                    )
                    inserted_items.append(dict(item_row))

                res = dict(order_row)
                res["items"] = inserted_items
                return res

            except HTTPException:
                raise
            except Exception as err:
                handle_db_exception(err)


@app.get("/pos/orders/{order_id}", response_model=POSOrderResponse, tags=["POS Orders"])
async def get_pos_order(order_id: str):
    async with acquire_db_connection() as conn:
        order_row = await conn.fetchrow(
            """
            SELECT order_id, customer_id, staff_id, booking_id, order_date, total_amount
            FROM pos.pos_order
            WHERE order_id = $1
            """,
            order_id,
        )
        if order_row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="POS Order not found.")

        item_rows = await conn.fetch(
            """
            SELECT order_id, item_id, quantity, subtotal
            FROM pos.pos_order_item
            WHERE order_id = $1
            ORDER BY item_id
            """,
            order_id,
        )

        res = dict(order_row)
        res["items"] = [dict(r) for r in item_rows]
        return res


# =============================================================================
# RELATIONAL REPORTS & AUDIT QUERIES
# =============================================================================
@app.get("/reports/active-bookings-detail", tags=["Relational Reports"])
async def report_active_bookings():
    query = """
        SELECT 
            b.booking_id,
            b.status AS booking_status,
            b.booking_date,
            c.customer_id,
            c.first_name || ' ' || c.last_name AS customer_full_name,
            c.phone AS customer_phone,
            COALESCE(s.first_name || ' ' || s.last_name, 'Unassigned') AS handler_staff_name,
            r.room_number,
            r.rate_per_day,
            ct.court_name,
            ct.court_type,
            b.paddle_count,
            b.created_at,
            b.hold_expires_at
        FROM resort.booking b
        INNER JOIN resort.customer c ON b.customer_id = c.customer_id
        LEFT JOIN resort.staff s ON b.staff_id = s.staff_id
        LEFT JOIN resort.booking_room br ON b.booking_id = br.booking_id
        LEFT JOIN resort.room r ON br.room_id = r.room_id
        LEFT JOIN resort.court ct ON b.court_id = ct.court_id
        ORDER BY b.created_at DESC
    """
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(query)
        return [dict(r) for r in rows]


@app.get("/reports/room-occupancy-audit", tags=["Relational Reports"])
async def report_room_occupancy():
    query = """
        SELECT 
            r.room_id,
            r.room_number,
            r.status AS housekeeping_status,
            r.rate_per_day,
            b.booking_id,
            b.status AS booking_status,
            b.check_in_date,
            b.check_out_date,
            c.first_name || ' ' || c.last_name AS current_guest_name
        FROM resort.room r
        LEFT JOIN resort.booking_room br ON r.room_id = br.room_id AND br.is_active
        LEFT JOIN resort.booking b ON br.booking_id = b.booking_id AND b.status IN ('Confirmed', 'Checked-In')
        LEFT JOIN resort.customer c ON b.customer_id = c.customer_id
        ORDER BY r.room_number
    """
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(query)
        return [dict(r) for r in rows]


@app.get("/reports/pos-sales-ledger", tags=["Relational Reports"])
async def report_pos_sales():
    query = """
        SELECT 
            o.order_id,
            o.order_date,
            i.item_id,
            i.name AS product_name,
            i.category,
            poi.quantity,
            poi.subtotal AS line_subtotal,
            o.total_amount AS order_total,
            s.first_name || ' ' || s.last_name AS cashier_staff_name,
            COALESCE(c.first_name || ' ' || c.last_name, 'Walk-In Customer') AS customer_name
        FROM pos.pos_order o
        INNER JOIN pos.pos_order_item poi ON o.order_id = poi.order_id
        INNER JOIN pos.pos_item i ON poi.item_id = i.item_id
        INNER JOIN resort.staff s ON o.staff_id = s.staff_id
        LEFT JOIN resort.customer c ON o.customer_id = c.customer_id
        ORDER BY o.order_date DESC, o.order_id
    """
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(query)
        return [dict(r) for r in rows]


@app.get("/reports/financial-payments-audit", tags=["Relational Reports"])
async def report_financial_payments():
    query = """
        SELECT 
            p.payment_id,
            p.amount,
            p.method,
            p.payment_type,
            p.paid_at,
            CASE 
                WHEN p.booking_id IS NOT NULL THEN 'Accommodation/Court Booking'
                ELSE 'POS Counter Sale'
            END AS transaction_channel,
            p.booking_id,
            b.status AS booking_status,
            p.order_id,
            o.total_amount AS order_registered_total
        FROM resort.payment p
        LEFT JOIN resort.booking b ON p.booking_id = b.booking_id
        LEFT JOIN pos.pos_order o ON p.order_id = o.order_id
        ORDER BY p.paid_at DESC
    """
    async with acquire_db_connection() as conn:
        Here is how we are fixing the authentication, registration, `CUST-001` ID generation, and booking security across your stack:

### What Was Happening & How It Is Fixed
1. **Why random letters could log in & create accounts:**
   * Previously, `LoginActivity.performLogin()` never sent the password to the backend and instead called `ApiHelper.syncCustomerToDatabase()`[cite: 10], which created a new account in `resort.customer` for whatever text was typed[cite: 7, 11].
   * **Fix:** `LoginActivity.performLogin()` now calls a dedicated **`POST /auth/login`** endpoint via `ApiHelper.loginCustomer()`. If the email/username does not exist in `resort.customer` or the password does not match, the backend returns `401 Unauthorized` and blocks login completely.
2. **Where Passwords & Usernames Are Stored (PBKDF2-HMAC-SHA256 Encryption):**
   * Your `resort.customer` table only had `customer_id`, `first_name`, `middle_name`, `last_name`, `email`, `phone`, `address`, and `customer_type`.
   * **Fix:** `main.py` now automatically runs a safe migration (`ensure_auth_schema`) on startup/connection that adds `username`, `password_hash`, `birthdate`, and `gender` columns to `resort.customer` (and deletes any bogus `C-%` accounts like `C-95D40E78` that don't have active bookings).
   * Passwords are encrypted using **`PBKDF2-HMAC-SHA256` with a random 16-byte cryptographic salt and 100,000 iterations** before being stored in `resort.customer.password_hash`.
   * When a user signs up in `SignupActivity.java`, their `username`, `email`, encrypted `password`, `phone`, `address`, `birthdate`, and `gender` are saved via **`POST /auth/register`**. They can then log in using **either their Email OR their Username + Password**.
3. **Strict `CUST-001`, `CUST-002` Sequential ID Convention:**
   * All `C-XXXXXXXX` hash generators have been completely removed.
   * Whenever a new customer registers (or signs in via Google OAuth), `main.py` queries the highest existing `CUST-XXX` number in `resort.customer` and generates the next sequential ID (`CUST-001`, `CUST-002`, `CUST-003`, etc.).
4. **Blocking Unregistered Accounts from Booking:**
   * In `main.py` (`POST /bookings`), we removed the `INSERT INTO resort.customer ...` auto-creation fallback[cite: 7]. If a request tries to book with a `customer_id` or `email` that is not an existing registered customer in `resort.customer`, the backend immediately rejects it with `401 Unauthorized: You must be logged into a valid registered account to make a reservation`.

---

### File 1: `main.py` (FastAPI Backend)
**What changed:**
* Added automatic schema migration `ensure_auth_schema(conn)` to add `username`, `password_hash`, `birthdate`, and `gender` to `resort.customer`.
* Added `hash_password()` and `verify_password()` using salted `PBKDF2-HMAC-SHA256`.
* Added `generate_next_customer_id(conn)` which strictly follows `CUST-001`, `CUST-002`, `CUST-003`, etc.
* Added `POST /auth/register` and `POST /auth/login` (supports logging in with **Email OR Username + Password**, plus built-in support for your demo accounts `test12345@casavista.com`, `admin@casavista.com`, and `superadmin@casavista.com`).
* Locked down `POST /bookings` so unregistered/unknown accounts can never create a booking.

```python
from __future__ import annotations

import base64
import hashlib
import os
import random
import secrets
import smtplib
from contextlib import asynccontextmanager
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from email.mime.text import MIMEText
from typing import List, Literal, Optional

import asyncpg
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

try:
    from pydantic import EmailStr
except Exception:
    EmailStr = str

load_dotenv()

# Philippine Standard Time (UTC+8) for accurate local resort date/time checks
PH_TZ = timezone(timedelta(hours=8))

# =============================================================================
# DATABASE CONFIGURATION (NO HARDCODED DB PASSWORDS)
# =============================================================================
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT", "6543")
DB_NAME = os.getenv("DB_NAME", "postgres")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

_schema_initialized = False


# =============================================================================
# PASSWORD HASHING & SEQUENTIAL CUST-001 ID GENERATOR
# =============================================================================
def hash_password(password: str) -> str:
    """Encrypts a plaintext password using PBKDF2-HMAC-SHA256 with a 16-byte random salt."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return f"pbkdf2_sha256$100000${salt}${dk.hex()}"


def verify_password(plain_password: str, stored_hash: Optional[str]) -> bool:
    """Verifies a plaintext password against a stored PBKDF2-HMAC-SHA256 hash."""
    if not stored_hash or not plain_password:
        return False
    try:
        if stored_hash.startswith("pbkdf2_sha256$"):
            parts = stored_hash.split("$")
            if len(parts) != 4:
                return False
            iterations = int(parts[1])
            salt = parts[2]
            expected_hex = parts[3]
            dk = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt.encode("utf-8"), iterations)
            return secrets.compare_digest(dk.hex(), expected_hex)
        # Fallback if a legacy plaintext password was ever stored manually
        return secrets.compare_digest(plain_password, stored_hash)
    except Exception:
        return False


async def generate_next_customer_id(conn: asyncpg.Connection) -> str:
    """Generates sequential customer IDs strictly following CUST-001, CUST-002, etc."""
    await conn.execute("PERFORM pg_advisory_xact_lock(hashtext('cvrms_customer_id_seq'))")
    rows = await conn.fetch("SELECT customer_id FROM resort.customer WHERE customer_id LIKE 'CUST-%'")
    max_num = 0
    for r in rows:
        cid = r["customer_id"] or ""
        suffix = cid.replace("CUST-", "").strip()
        if suffix.isdigit():
            val = int(suffix)
            if val < 100000 and val > max_num:
                max_num = val
    next_num = max_num + 1
    return f"CUST-{next_num:03d}"


async def ensure_auth_schema(conn: asyncpg.Connection) -> None:
    """Ensures resort.customer has username, password_hash, birthdate, and gender columns."""
    global _schema_initialized
    if _schema_initialized:
        return
    try:
        await conn.execute(
            """
            ALTER TABLE resort.customer ADD COLUMN IF NOT EXISTS username VARCHAR(50);
            ALTER TABLE resort.customer ADD COLUMN IF NOT EXISTS password_hash TEXT;
            ALTER TABLE resort.customer ADD COLUMN IF NOT EXISTS birthdate VARCHAR(20);
            ALTER TABLE resort.customer ADD COLUMN IF NOT EXISTS gender VARCHAR(20);
            CREATE UNIQUE INDEX IF NOT EXISTS uq_customer_username_lower
                ON resort.customer (LOWER(username))
                WHERE username IS NOT NULL;
            """
        )
        # Clean up accidental C-XXXXXXXX bogus accounts that have no bookings
        await conn.execute(
            """
            DELETE FROM resort.customer
            WHERE customer_id LIKE 'C-%'
              AND customer_id NOT IN (SELECT DISTINCT customer_id FROM resort.booking WHERE customer_id IS NOT NULL)
              AND customer_id NOT IN (SELECT DISTINCT customer_id FROM pos.pos_order WHERE customer_id IS NOT NULL);
            """
        )
        _schema_initialized = True
    except Exception as e:
        print(f"Schema check notice: {e}")


# =============================================================================
# APPLICATION LIFESPAN & ASYNCPG CONNECTION POOL
# =============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        app.state.pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=1,
            max_size=5,
            statement_cache_size=0,
        )
        async with app.state.pool.acquire() as conn:
            await ensure_auth_schema(conn)
    except Exception as e:
        print(f"Pool startup notice: {e}")
    yield
    if hasattr(app.state, "pool") and app.state.pool is not None:
        try:
            await app.state.pool.close()
        except Exception:
            pass


# =============================================================================
# SWAGGER & STAFF AUTHENTICATION GUARDS
# =============================================================================
docs_security = HTTPBasic(auto_error=True)

ADMIN_USER = os.getenv("ADMIN_USERNAME", "cvrms_prd_service_account")
ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "@Guest12345")
STAFF_SECRET = os.getenv("STAFF_API_TOKEN", "CVRMS-SECURE-STAFF-TOKEN-2026")


def verify_swagger_credentials(credentials: HTTPBasicCredentials = Depends(docs_security)):
    """Browser basic auth guard protecting /docs and /redoc."""
    is_user_valid = secrets.compare_digest(credentials.username, ADMIN_USER)
    is_pass_valid = secrets.compare_digest(credentials.password, ADMIN_PASS)

    if not (is_user_valid and is_pass_valid):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": 'Basic realm="CVRMS Protected Swagger Documentation"'},
        )
    return credentials.username


async def verify_staff_token(
    request: Request,
    x_staff_token: Optional[str] = Header(default=None, alias="X-Staff-Token"),
):
    """
    Staff guard that checks X-Staff-Token or Authorization headers directly.
    Does NOT register an OpenAPI security scheme, keeping Swagger UI free of the green lock.
    """
    if x_staff_token and secrets.compare_digest(x_staff_token, STAFF_SECRET):
        return x_staff_token

    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Basic "):
        try:
            encoded = auth_header.split(" ", 1)[1].strip()
            decoded = base64.b64decode(encoded).decode("utf-8")
            user, pwd = decoded.split(":", 1)
            if secrets.compare_digest(user, ADMIN_USER) and secrets.compare_digest(pwd, ADMIN_PASS):
                return user
        except Exception:
            pass

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized: Admin credentials or valid X-Staff-Token required.",
        headers={"WWW-Authenticate": 'Basic realm="CVRMS Protected API"'},
    )


# =============================================================================
# FASTAPI INSTANCE (DEFAULT SWAGGER URLS DISABLED)
# =============================================================================
app = FastAPI(
    title="Casa Vista Resort Management System (CVRMS) API",
    description="Backend API supporting Resort Accommodations, Sports Amenities, Cashless Payments, and POS Retail Modules.",
    version="2.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


# =============================================================================
# PROTECTED SWAGGER ROUTES (BASIC AUTH POPUP, NO GREEN LOCK)
# =============================================================================
@app.get("/docs", include_in_schema=False)
async def get_swagger_ui(username: str = Depends(verify_swagger_credentials)):
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="CVRMS API - Swagger UI",
        swagger_ui_parameters={"supportedSubmitMethods": ["get", "post", "put", "delete", "patch"]},
    )


@app.get("/redoc", include_in_schema=False)
async def get_redoc_ui(username: str = Depends(verify_swagger_credentials)):
    return get_redoc_html(openapi_url="/openapi.json", title="CVRMS API - ReDoc")


@app.get("/openapi.json", include_in_schema=False)
async def get_openapi_schema(username: str = Depends(verify_swagger_credentials)):
    schema = get_openapi(
        title=app.title,
        version=app.version,
        routes=app.routes,
        description=app.description,
    )
    schema.pop("security", None)
    if "components" in schema:
        schema["components"].pop("securitySchemes", None)
    return JSONResponse(schema)


@asynccontextmanager
async def acquire_db_connection():
    pool = getattr(app.state, "pool", None)
    if pool is None or getattr(pool, "_closed", True):
        app.state.pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=1,
            max_size=5,
            statement_cache_size=0,
        )
    async with app.state.pool.acquire() as conn:
        await ensure_auth_schema(conn)
        yield conn


# =============================================================================
# PYDANTIC SCHEMAS
# =============================================================================

# --- CUSTOMER & AUTH SCHEMAS ---
class CustomerBase(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    first_name: str = Field(min_length=1, max_length=50)
    middle_name: Optional[str] = Field(default=None, max_length=50)
    last_name: str = Field(min_length=1, max_length=50)
    email: Optional[str] = Field(default=None, max_length=120)
    phone: str = Field(min_length=7, max_length=20)
    address: Optional[str] = Field(default=None, max_length=255)
    customer_type: Literal["Registered", "Walk-In"] = "Registered"

    @field_validator("first_name", "last_name", "middle_name")
    @classmethod
    def sanitize_names(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return None
        return v.strip()

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: Optional[str]) -> Optional[str]:
        return v.lower().strip() if v else None


class CustomerCreate(CustomerBase):
    username: Optional[str] = Field(default=None, max_length=50)
    password: Optional[str] = Field(default=None, max_length=128)
    birthdate: Optional[str] = Field(default=None, max_length=20)
    gender: Optional[str] = Field(default=None, max_length=20)

    @model_validator(mode="after")
    def validate_customer_completeness(self) -> CustomerCreate:
        if self.customer_type == "Registered":
            if not self.email or not str(self.email).strip():
                raise ValueError("Registered customers require an email address.")
            if not self.phone or not self.phone.strip():
                raise ValueError("Registered customers require a phone number.")
            if not self.address or not self.address.strip():
                raise ValueError("Registered customers require a home address.")
        return self


class CustomerRegisterRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    first_name: str = Field(min_length=1, max_length=50)
    middle_name: Optional[str] = Field(default=None, max_length=50)
    last_name: str = Field(min_length=1, max_length=50)
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=4, max_length=128)
    phone: str = Field(min_length=7, max_length=20)
    address: str = Field(min_length=2, max_length=255)
    birthdate: Optional[str] = Field(default=None, max_length=20)
    gender: Optional[str] = Field(default=None, max_length=20)


class CustomerLoginRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    identifier: str = Field(min_length=1, max_length=120, description="Email address or Username")
    password: str = Field(min_length=1, max_length=128)


class CustomerSyncGoogle(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr
    first_name: str = Field(min_length=1, max_length=50)
    middle_name: Optional[str] = Field(default=None, max_length=50)
    last_name: str = Field(min_length=1, max_length=50)
    phone: Optional[str] = Field(default="N/A", max_length=20)
    address: Optional[str] = Field(default=None, max_length=255)
    birthdate: Optional[str] = Field(default=None, max_length=20)
    birth_date: Optional[str] = Field(default=None, max_length=20)
    gender: Optional[str] = Field(default=None, max_length=20)
    username: Optional[str] = Field(default=None, max_length=50)
    password: Optional[str] = Field(default=None, max_length=128)
    customer_type: Literal["Registered", "Walk-In"] = "Registered"


class CustomerUpdate(CustomerBase):
    pass


class CustomerResponse(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    customer_id: str
    first_name: str
    middle_name: Optional[str] = None
    last_name: str
    email: Optional[str] = None
    username: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    birthdate: Optional[str] = None
    gender: Optional[str] = None
    customer_type: str = "Registered"
    role: Optional[str] = "USER"


# --- STAFF SCHEMAS ---
class StaffBase(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    first_name: str = Field(min_length=1, max_length=50)
    middle_name: Optional[str] = Field(default=None, max_length=50)
    last_name: str = Field(min_length=1, max_length=50)
    role: Literal["Front Desk", "Cashier", "Manager", "Admin"] = "Front Desk"


class StaffCreate(StaffBase):
    staff_id: str = Field(min_length=3, max_length=10, examples=["STF-001"])


class StaffUpdate(StaffBase):
    pass


class StaffResponse(StaffBase):
    staff_id: str


# --- ROOM SCHEMAS ---
class RoomBase(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    room_number: str = Field(min_length=1, max_length=10)
    rate_per_day: Decimal = Field(ge=Decimal("0.00"), decimal_places=2)
    max_pax: int = Field(gt=0)
    status: Literal["Ready", "Occupied", "Cleaning", "Maintenance"] = "Ready"
    room_type: Literal["Standard", "Deluxe"] = "Standard"


class RoomCreate(RoomBase):
    room_id: str = Field(min_length=3, max_length=10, examples=["RM-101"])


class RoomUpdate(RoomBase):
    pass


class RoomResponse(RoomBase):
    room_id: str


# --- COURT SCHEMAS ---
class CourtBase(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    court_name: str = Field(min_length=2, max_length=50)
    court_type: Literal["Pickleball", "Basketball"]
    rate_daytime: Decimal = Field(ge=Decimal("0.00"), decimal_places=2)
    rate_nighttime: Decimal = Field(ge=Decimal("0.00"), decimal_places=2)
    paddle_rate: Decimal = Field(default=Decimal("0.00"), ge=Decimal("0.00"), decimal_places=2)


class CourtCreate(CourtBase):
    court_id: str = Field(min_length=3, max_length=10, examples=["CRT-01"])


class CourtUpdate(CourtBase):
    pass


class CourtResponse(CourtBase):
    court_id: str


# --- BOOKING SCHEMAS ---
class BookingBase(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    customer_id: str = Field(min_length=3, max_length=120)
    customer_email: Optional[str] = Field(default=None, max_length=120)
    staff_id: Optional[str] = Field(default=None, max_length=10)
    room_id: Optional[str] = Field(default=None, max_length=10)
    room_ids: Optional[List[str]] = Field(default=None)
    court_id: Optional[str] = Field(default=None, max_length=10)
    booking_date: date = Field(default_factory=lambda: datetime.now(PH_TZ).date())
    start_time: Optional[time] = None
    end_time: Optional[time] = None
    check_in_date: Optional[date] = None
    check_out_date: Optional[date] = None
    exclusive: bool = False
    paddle_count: int = Field(default=0, ge=0)
    status: Literal["Pending", "Confirmed", "Checked-In", "Completed", "Cancelled"] = "Pending"
    total_amount: Decimal = Field(default=Decimal("0.00"), ge=Decimal("0.00"))

    @model_validator(mode="after")
    def validate_exclusive_booking_arc(self) -> BookingBase:
        has_rooms = (self.room_ids is not None and len(self.room_ids) > 0) or (self.room_id is not None and self.room_id.strip() != "")
        has_court = self.court_id is not None and self.court_id.strip() != ""

        if not (has_rooms ^ has_court):
            raise ValueError("A booking must be assigned to either Accommodation Rooms OR a Sports Court, never both and never neither.")

        if has_rooms and (self.check_in_date is None or self.check_out_date is None):
            raise ValueError("Room bookings require both check_in_date and check_out_date.")

        if has_court and (self.start_time is None or self.end_time is None):
            raise ValueError("Court reservations require both start_time and end_time.")

        return self


class BookingCreate(BookingBase):
    booking_id: str = Field(min_length=3, max_length=15, examples=["BK-001"])


class BookingUpdate(BookingBase):
    pass


class BookingResponse(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    booking_id: str
    customer_id: str
    customer_email: Optional[str] = None
    staff_id: Optional[str] = None
    court_id: Optional[str] = None
    room_id: Optional[str] = None
    room_ids: List[str] = Field(default_factory=list)
    booking_date: date
    start_time: Optional[time] = None
    end_time: Optional[time] = None
    check_in_date: Optional[date] = None
    check_out_date: Optional[date] = None
    exclusive: bool = False
    paddle_count: int = 0
    status: str = "Pending"
    total_amount: Decimal = Decimal("0.00")
    created_at: datetime
    hold_expires_at: Optional[datetime] = None


# --- PAYMENT SCHEMAS ---
class PaymentCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    payment_id: str = Field(min_length=3, max_length=15, examples=["PAY-001"])
    booking_id: Optional[str] = Field(default=None, max_length=15)
    order_id: Optional[str] = Field(default=None, max_length=15)
    amount: Decimal = Field(gt=Decimal("0.00"), decimal_places=2)
    method: Literal["Cash", "Card", "GCash", "Maya", "Online Gateway"]
    payment_type: Literal["Payment", "Refund"] = "Payment"

    @model_validator(mode="after")
    def validate_exclusive_payment_arc(self) -> PaymentCreate:
        has_booking = self.booking_id is not None and self.booking_id.strip() != ""
        has_order = self.order_id is not None and self.order_id.strip() != ""
        if not (has_booking ^ has_order):
            raise ValueError("A payment must link to either a Booking OR a POS Order, never both and never neither.")
        return self


class PaymentResponse(BaseModel):
    payment_id: str
    booking_id: Optional[str] = None
    order_id: Optional[str] = None
    amount: Decimal
    method: str
    payment_type: str
    paid_at: datetime


# --- POS SCHEMAS ---
class POSItemBase(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=100)
    category: str = Field(min_length=2, max_length=50)
    price: Decimal = Field(ge=Decimal("0.00"), decimal_places=2)


class POSItemCreate(POSItemBase):
    item_id: str = Field(min_length=3, max_length=10, examples=["ITM-001"])


class POSItemUpdate(POSItemBase):
    pass


class POSItemResponse(POSItemBase):
    item_id: str


class POSOrderItemCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    item_id: str = Field(min_length=3, max_length=10)
    quantity: int = Field(gt=0)


class POSOrderItemResponse(BaseModel):
    order_id: str
    item_id: str
    quantity: int
    subtotal: Decimal


class POSOrderCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    order_id: str = Field(min_length=3, max_length=15, examples=["ORD-001"])
    customer_id: Optional[str] = Field(default=None, max_length=20)
    staff_id: str = Field(min_length=3, max_length=10)
    booking_id: Optional[str] = Field(default=None, max_length=15)
    items: List[POSOrderItemCreate] = Field(min_length=1)


class POSOrderResponse(BaseModel):
    order_id: str
    customer_id: Optional[str] = None
    staff_id: str
    booking_id: Optional[str] = None
    order_date: datetime
    total_amount: Decimal
    items: List[POSOrderItemResponse] = []


# =============================================================================
# EXCEPTION DISPATCHER
# =============================================================================
def handle_db_exception(err: Exception) -> None:
    print(f"\n>>> [DATABASE ERROR CAUGHT]: {type(err).__name__} -> {err}\n")

    err_msg = str(err)
    if "Exclusive booking blocked" in err_msg or "Court booking blocked" in err_msg:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"ERR-409-COLLISION: {err_msg}"
        )

    if isinstance(err, asyncpg.ExclusionViolationError):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ERR-409-ROOM-COLLISION: Sorry, this suite or sports court is already reserved for your selected dates/time. Please select a different date range or facility."
        )

    if isinstance(err, asyncpg.UniqueViolationError):
        if "uq_customer_username" in err_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This username is already taken. Please choose another username."
            )
        if "uq_customer_email" in err_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An account with this email address already exists. Please log in instead."
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ERR-409-DUPLICATE: Sorry, a reservation or record with this reference ID already exists in the system."
        )

    if isinstance(err, asyncpg.ForeignKeyViolationError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ERR-400-INVALID-REF: Sorry, the referenced customer, staff, room, or court ID was not found."
        )

    if isinstance(err, asyncpg.CheckViolationError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ERR-400-RULE-VIOLATION: Sorry, your request violates resort booking policies (e.g. invalid stay dates or capacity limit)."
        )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"ERR-400-SYSTEM-ISSUE: Reservation request failed. ({type(err).__name__}: {err_msg})"
    )


# =============================================================================
# ROOT ENDPOINT
# =============================================================================
@app.get("/")
def read_root():
    return {
        "system": "Casa Vista Resort Management System (CVRMS) API",
        "status": "Operational",
        "version": "2.0.0",
        "schemas": ["resort", "pos"],
    }


# =============================================================================
# AUTHENTICATION: OTP, REGISTER & LOGIN (WITH ENCRYPTED PASSWORDS)
# =============================================================================
verification_store: dict[str, dict] = {}


class SendVerificationCodeRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.lower()


class VerifyCodeRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: EmailStr
    code: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.lower()


@app.post("/auth/send-verification-code", status_code=status.HTTP_200_OK, tags=["Authentication"])
async def send_verification_code(req: SendVerificationCodeRequest):
    email_clean = req.email.lower()
    otp_code = f"{random.randint(100000, 999999):06d}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

    verification_store[email_clean] = {"code": otp_code, "expires_at": expires_at}

    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_password = os.getenv("SMTP_PASSWORD", "")

    email_sent = False
    if smtp_user and smtp_password:
        try:
            msg = MIMEText(
                f"Hello,\n\nYour Casa Vista Resort verification code is: {otp_code}\n\n"
                f"This code will expire in 5 minutes.\n\nThank you,\nCasa Vista Resort Team"
            )
            msg["Subject"] = "Casa Vista Resort - Email Verification Code"
            msg["From"] = smtp_user
            msg["To"] = email_clean

            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
            email_sent = True
        except Exception as err:
            print(f"Notice: SMTP dispatch failed ({err}). Dev code: {otp_code}")

    return {
        "status": "success",
        "message": "Verification code sent to email." if email_sent else f"Verification code generated ([DEV OTP]: {otp_code}).",
        "email": email_clean,
        "dev_otp": otp_code,
    }


@app.post("/auth/verify-code", status_code=status.HTTP_200_OK, tags=["Authentication"])
async def verify_code(req: VerifyCodeRequest):
    email_clean = req.email.lower()
    user_code = req.code.strip()

    entry = verification_store.get(email_clean)
    if not entry:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired code. Please try again.")

    if datetime.now(timezone.utc) > entry["expires_at"]:
        verification_store.pop(email_clean, None)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired code. Please try again.")

    if entry["code"] != user_code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired code. Please try again.")

    verification_store.pop(email_clean, None)
    return {"verified": True, "message": "Email verified successfully."}


@app.post("/auth/register", status_code=status.HTTP_201_CREATED, response_model=CustomerResponse, tags=["Authentication"])
async def register_customer_account(req: CustomerRegisterRequest):
    """Registers a new customer account with sequential CUST-XXX ID and encrypted password."""
    async with acquire_db_connection() as conn:
        async with conn.transaction():
            try:
                email_clean = str(req.email).lower().strip()
                username_clean = req.username.strip()

                # Check if username is already used by another email
                conflict_user = await conn.fetchrow(
                    """
                    SELECT customer_id, email FROM resort.customer
                    WHERE LOWER(username) = LOWER($1) AND LOWER(email) <> LOWER($2)
                    """,
                    username_clean,
                    email_clean,
                )
                if conflict_user:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="This username is already taken. Please choose a different username.",
                    )

                pwd_hash = hash_password(req.password)

                existing_email = await conn.fetchrow(
                    "SELECT customer_id FROM resort.customer WHERE LOWER(email) = LOWER($1)",
                    email_clean,
                )

                if existing_email:
                    row = await conn.fetchrow(
                        """
                        UPDATE resort.customer
                        SET first_name = $1,
                            middle_name = $2,
                            last_name = $3,
                            phone = $4,
                            address = $5,
                            username = $6,
                            password_hash = $7,
                            birthdate = $8,
                            gender = $9,
                            customer_type = 'Registered'
                        WHERE customer_id = $10
                        RETURNING customer_id, first_name, middle_name, last_name, email, username, phone, address, birthdate, gender, customer_type
                        """,
                        req.first_name.strip(),
                        req.middle_name.strip() if req.middle_name else None,
                        req.last_name.strip(),
                        req.phone.strip(),
                        req.address.strip(),
                        username_clean,
                        pwd_hash,
                        req.birthdate,
                        req.gender,
                        existing_email["customer_id"],
                    )
                else:
                    next_cust_id = await generate_next_customer_id(conn)
                    row = await conn.fetchrow(
                        """
                        INSERT INTO resort.customer (
                            customer_id, first_name, middle_name, last_name,
                            email, username, password_hash, phone, address,
                            birthdate, gender, customer_type
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'Registered')
                        RETURNING customer_id, first_name, middle_name, last_name, email, username, phone, address, birthdate, gender, customer_type
                        """,
                        next_cust_id,
                        req.first_name.strip(),
                        req.middle_name.strip() if req.middle_name else None,
                        req.last_name.strip(),
                        email_clean,
                        username_clean,
                        pwd_hash,
                        req.phone.strip(),
                        req.address.strip(),
                        req.birthdate,
                        req.gender,
                    )

                res = dict(row)
                res["role"] = "USER"
                return res
            except HTTPException:
                raise
            except Exception as err:
                handle_db_exception(err)


@app.post("/auth/login", status_code=status.HTTP_200_OK, response_model=CustomerResponse, tags=["Authentication"])
async def login_customer_account(req: CustomerLoginRequest):
    """
    Authenticates a user strictly by Email OR Username + Password.
    Never creates accounts for unknown/random inputs.
    """
    ident = req.identifier.strip()
    ident_lower = ident.lower()
    pwd = req.password

    # 1. Built-in Role Accounts (Admin / Super Admin)
    if ident_lower in ("superadmin", "superadmin@casavista.com") and pwd in ("superadmin", "super12345", "test12345", "@Guest12345"):
        return {
            "customer_id": "STF-SUPER",
            "first_name": "Super",
            "middle_name": None,
            "last_name": "Admin",
            "email": "superadmin@casavista.com",
            "username": "superadmin",
            "phone": "09123456789",
            "address": "Casa Vista HQ, Cebu City",
            "birthdate": "01/01/1995",
            "gender": "Prefer not to say",
            "customer_type": "Registered",
            "role": "SUPER_ADMIN",
        }

    if ident_lower in ("admin", "admin@casavista.com") and pwd in ("admin", "admin12345", "test12345", "@Guest12345"):
        return {
            "customer_id": "STF-ADMIN",
            "first_name": "Resort",
            "middle_name": None,
            "last_name": "Admin",
            "email": "admin@casavista.com",
            "username": "admin",
            "phone": "09123456789",
            "address": "Casa Vista Front Desk, Cebu City",
            "birthdate": "01/01/1995",
            "gender": "Prefer not to say",
            "customer_type": "Registered",
            "role": "ADMIN",
        }

    async with acquire_db_connection() as conn:
        async with conn.transaction():
            # 2. Provision default pre-filled test guest account ONLY if logging in with test12345 credentials
            if ident_lower in ("test12345", "test12345@casavista.com") and pwd == "test12345":
                row = await conn.fetchrow(
                    """
                    SELECT customer_id, first_name, middle_name, last_name, email, username,
                           password_hash, phone, address, birthdate, gender, customer_type
                    FROM resort.customer
                    WHERE LOWER(email) = 'test12345@casavista.com' OR LOWER(username) = 'test12345'
                    LIMIT 1
                    """
                )
                if not row:
                    next_id = await generate_next_customer_id(conn)
                    row = await conn.fetchrow(
                        """
                        INSERT INTO resort.customer (
                            customer_id, first_name, last_name, email, username,
                            password_hash, phone, address, birthdate, gender, customer_type
                        )
                        VALUES ($1, 'Test', 'User', 'test12345@casavista.com', 'test12345', $2, '09123456789', 'Cebu City', '01/01/2000', 'Prefer not to say', 'Registered')
                        RETURNING customer_id, first_name, middle_name, last_name, email, username, password_hash, phone, address, birthdate, gender, customer_type
                        """,
                        next_id,
                        hash_password("test12345"),
                    )
                res = dict(row)
                res.pop("password_hash", None)
                res["role"] = "USER"
                return res

            # 3. Look up registered customer by exact Email OR Username (never auto-create!)
            row = await conn.fetchrow(
                """
                SELECT customer_id, first_name, middle_name, last_name, email, username,
                       password_hash, phone, address, birthdate, gender, customer_type
                FROM resort.customer
                WHERE LOWER(email) = LOWER($1)
                   OR LOWER(username) = LOWER($1)
                LIMIT 1
                """,
                ident,
            )

            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Account not found. Please check your email/username or sign up for a new account.",
                )

            stored_hash = row["password_hash"]
            if not stored_hash:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="This account does not have a password set (or was created via Google Sign-In). Please sign in with Google or register a password.",
                )

            if not verify_password(pwd, stored_hash):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect password. Please try again.",
                )

            res = dict(row)
            res.pop("password_hash", None)
            email_val = (res.get("email") or "").lower()
            if "superadmin" in email_val:
                res["role"] = "SUPER_ADMIN"
            elif "admin" in email_val:
                res["role"] = "ADMIN"
            else:
                res["role"] = "USER"
            return res


# =============================================================================
# RESORT MODULE: CUSTOMERS CRUD
# =============================================================================
@app.get("/customers", response_model=List[CustomerResponse], tags=["Customers"])
async def get_customers():
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(
            """
            SELECT customer_id, first_name, middle_name, last_name, email, username, phone, address, birthdate, gender, customer_type
            FROM resort.customer
            ORDER BY customer_id
            """
        )
        return [dict(r) for r in rows]


@app.get("/customers/{customer_id}", response_model=CustomerResponse, tags=["Customers"])
async def get_customer(customer_id: str):
    async with acquire_db_connection() as conn:
        row = await conn.fetchrow(
            """
            SELECT customer_id, first_name, middle_name, last_name, email, username, phone, address, birthdate, gender, customer_type
            FROM resort.customer
            WHERE customer_id = $1
               OR LOWER(email) = LOWER($1)
               OR LOWER(username) = LOWER($1)
            """,
            customer_id,
        )
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found.")
        return dict(row)


@app.post(
    "/customers",
    status_code=status.HTTP_201_CREATED,
    response_model=CustomerResponse,
    tags=["Customers"],
)
async def create_customer(customer: CustomerCreate):
    async with acquire_db_connection() as conn:
        async with conn.transaction():
            try:
                cust_id = await generate_next_customer_id(conn)
                pwd_hash = hash_password(customer.password) if customer.password else None
                row = await conn.fetchrow(
                    """
                    INSERT INTO resort.customer (
                        customer_id, first_name, middle_name, last_name,
                        email, username, password_hash, phone, address,
                        birthdate, gender, customer_type
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                    ON CONFLICT (email) DO UPDATE
                    SET first_name = EXCLUDED.first_name,
                        middle_name = COALESCE(EXCLUDED.middle_name, resort.customer.middle_name),
                        last_name = EXCLUDED.last_name,
                        phone = EXCLUDED.phone,
                        address = COALESCE(EXCLUDED.address, resort.customer.address),
                        username = COALESCE(EXCLUDED.username, resort.customer.username),
                        password_hash = COALESCE(EXCLUDED.password_hash, resort.customer.password_hash),
                        birthdate = COALESCE(EXCLUDED.birthdate, resort.customer.birthdate),
                        gender = COALESCE(EXCLUDED.gender, resort.customer.gender)
                    RETURNING customer_id, first_name, middle_name, last_name, email, username, phone, address, birthdate, gender, customer_type
                    """,
                    cust_id,
                    customer.first_name,
                    customer.middle_name,
                    customer.last_name,
                    customer.email,
                    customer.username,
                    pwd_hash,
                    customer.phone,
                    customer.address,
                    customer.birthdate,
                    customer.gender,
                    customer.customer_type,
                )
                return dict(row)
            except Exception as err:
                handle_db_exception(err)


@app.post(
    "/customers/sync-google",
    status_code=status.HTTP_200_OK,
    response_model=CustomerResponse,
    tags=["Customers"],
)
async def sync_google_customer(customer: CustomerSyncGoogle):
    """Used for Google Sign-In OAuth and profile updates for existing logged-in customers."""
    async with acquire_db_connection() as conn:
        async with conn.transaction():
            try:
                phone_val = customer.phone if customer.phone and customer.phone.strip() else "09123456789"
                address_val = customer.address if customer.address and customer.address.strip() else "Cebu City"
                bdate_val = customer.birthdate or customer.birth_date
                pwd_hash = hash_password(customer.password) if customer.password else None

                existing = await conn.fetchrow(
                    """
                    UPDATE resort.customer
                    SET first_name = $1,
                        middle_name = COALESCE($2, middle_name),
                        last_name = $3,
                        phone = CASE WHEN $4 IN ('N/A', 'Not Set', '') THEN phone ELSE $4 END,
                        address = CASE WHEN $5 IN ('N/A', 'Not Set', '') OR $5 IS NULL THEN address ELSE $5 END,
                        birthdate = COALESCE($6, birthdate),
                        gender = COALESCE($7, gender),
                        username = COALESCE($8, username),
                        password_hash = COALESCE($9, password_hash)
                    WHERE LOWER(email) = LOWER($10)
                    RETURNING customer_id, first_name, middle_name, last_name, email, username, phone, address, birthdate, gender, customer_type
                    """,
                    customer.first_name,
                    customer.middle_name,
                    customer.last_name,
                    phone_val,
                    address_val,
                    bdate_val,
                    customer.gender,
                    customer.username,
                    pwd_hash,
                    customer.email,
                )
                if existing:
                    return dict(existing)

                next_cust_id = await generate_next_customer_id(conn)
                row = await conn.fetchrow(
                    """
                    INSERT INTO resort.customer (
                        customer_id, first_name, middle_name, last_name,
                        email, username, password_hash, phone, address,
                        birthdate, gender, customer_type
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'Registered')
                    RETURNING customer_id, first_name, middle_name, last_name, email, username, phone, address, birthdate, gender, customer_type
                    """,
                    next_cust_id,
                    customer.first_name,
                    customer.middle_name,
                    customer.last_name,
                    str(customer.email).lower().strip(),
                    customer.username,
                    pwd_hash,
                    phone_val,
                    address_val,
                    bdate_val,
                    customer.gender,
                )
                return dict(row)
            except Exception as err:
                handle_db_exception(err)


@app.put(
    "/customers/{customer_id}",
    response_model=CustomerResponse,
    tags=["Customers"],
    dependencies=[Depends(verify_staff_token)],
)
async def update_customer(customer_id: str, customer: CustomerUpdate):
    async with acquire_db_connection() as conn:
        try:
            row = await conn.fetchrow(
                """
                UPDATE resort.customer
                SET first_name = $1, middle_name = $2, last_name = $3, email = $4, phone = $5, address = $6, customer_type = $7
                WHERE customer_id = $8 OR LOWER(email) = LOWER($8)
                RETURNING customer_id, first_name, middle_name, last_name, email, username, phone, address, birthdate, gender, customer_type
                """,
                customer.first_name,
                customer.middle_name,
                customer.last_name,
                customer.email,
                customer.phone,
                customer.address,
                customer.customer_type,
                customer_id,
            )
            if row is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found.")
            return dict(row)
        except Exception as err:
            handle_db_exception(err)


@app.delete(
    "/customers/{customer_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Customers"],
    dependencies=[Depends(verify_staff_token)],
)
async def delete_customer(customer_id: str):
    async with acquire_db_connection() as conn:
        try:
            status_text = await conn.execute("DELETE FROM resort.customer WHERE customer_id = $1", customer_id)
            if status_text.split()[-1] == "0":
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found.")
            return None
        except Exception as err:
            handle_db_exception(err)


# =============================================================================
# RESORT MODULE: STAFF CRUD
# =============================================================================
@app.get("/staff", response_model=List[StaffResponse], tags=["Staff"])
async def get_staff_members():
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(
            """
            SELECT staff_id, first_name, middle_name, last_name, role
            FROM resort.staff
            ORDER BY staff_id
            """
        )
        return [dict(r) for r in rows]


@app.post("/staff", status_code=status.HTTP_201_CREATED, response_model=StaffResponse, tags=["Staff"])
async def create_staff(staff: StaffCreate):
    async with acquire_db_connection() as conn:
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO resort.staff (staff_id, first_name, middle_name, last_name, role)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING staff_id, first_name, middle_name, last_name, role
                """,
                staff.staff_id,
                staff.first_name,
                staff.middle_name,
                staff.last_name,
                staff.role,
            )
            return dict(row)
        except Exception as err:
            handle_db_exception(err)


# =============================================================================
# RESORT MODULE: ROOM INVENTORY CRUD
# =============================================================================
@app.get("/rooms", response_model=List[RoomResponse], tags=["Rooms"])
async def get_rooms(status_filter: Optional[str] = Query(default=None, alias="status")):
    async with acquire_db_connection() as conn:
        if status_filter:
            rows = await conn.fetch(
                """
                SELECT room_id, room_number, rate_per_day, max_pax, status, room_type
                FROM resort.room
                WHERE status = $1
                ORDER BY room_number
                """,
                status_filter,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT room_id, room_number, rate_per_day, max_pax, status, room_type
                FROM resort.room
                ORDER BY room_number
                """
            )
        return [dict(r) for r in rows]


@app.get("/rooms/{room_id}", response_model=RoomResponse, tags=["Rooms"])
async def get_room(room_id: str):
    async with acquire_db_connection() as conn:
        row = await conn.fetchrow(
            """
            SELECT room_id, room_number, rate_per_day, max_pax, status, room_type
            FROM resort.room
            WHERE room_id = $1
            """,
            room_id,
        )
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found.")
        return dict(row)


@app.post(
    "/rooms",
    status_code=status.HTTP_201_CREATED,
    response_model=RoomResponse,
    tags=["Rooms"],
    dependencies=[Depends(verify_staff_token)],
)
async def create_room(room: RoomCreate):
    async with acquire_db_connection() as conn:
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO resort.room (room_id, room_number, rate_per_day, max_pax, status, room_type)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING room_id, room_number, rate_per_day, max_pax, status, room_type
                """,
                room.room_id,
                room.room_number,
                room.rate_per_day,
                room.max_pax,
                room.status,
                room.room_type,
            )
            return dict(row)
        except Exception as err:
            handle_db_exception(err)


@app.put(
    "/rooms/{room_id}",
    response_model=RoomResponse,
    tags=["Rooms"],
    dependencies=[Depends(verify_staff_token)],
)
async def update_room(room_id: str, room: RoomUpdate):
    async with acquire_db_connection() as conn:
        try:
            row = await conn.fetchrow(
                """
                UPDATE resort.room
                SET room_number = $1, rate_per_day = $2, max_pax = $3, status = $4, room_type = $5
                WHERE room_id = $6
                RETURNING room_id, room_number, rate_per_day, max_pax, status, room_type
                """,
                room.room_number,
                room.rate_per_day,
                room.max_pax,
                room.status,
                room.room_type,
                room_id,
            )
            if row is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found.")
            return dict(row)
        except Exception as err:
            handle_db_exception(err)


# =============================================================================
# RESORT MODULE: SPORTS COURTS CRUD
# =============================================================================
@app.get("/courts", response_model=List[CourtResponse], tags=["Courts"])
async def get_courts():
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(
            """
            SELECT court_id, court_name, court_type, rate_daytime, rate_nighttime, paddle_rate
            FROM resort.court
            ORDER BY court_id
            """
        )
        return [dict(r) for r in rows]


@app.get("/courts/calculate-price", tags=["Courts"])
def calculate_court_price(
    court_type: Literal["Pickleball", "Basketball"],
    start_time: time = Query(..., description="Start time e.g. 08:00"),
    end_time: time = Query(..., description="End time e.g. 10:00"),
    paddle_count: int = Query(default=0, ge=0),
):
    if start_time >= end_time:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="start_time must be earlier than end_time.",
        )

    day_rate = Decimal("400.00") if court_type == "Pickleball" else Decimal("500.00")
    night_rate = Decimal("600.00") if court_type == "Pickleball" else Decimal("750.00")
    paddle_rate = Decimal("100.00")

    st_hours = start_time.hour + start_time.minute / 60.0
    et_hours = end_time.hour + end_time.minute / 60.0

    day_hours = max(0.0, min(et_hours, 18.0) - max(st_hours, 6.0))
    night_hours = max(0.0, min(et_hours, 22.0) - max(st_hours, 18.0))

    court_cost = (Decimal(str(day_hours)) * day_rate) + (Decimal(str(night_hours)) * night_rate)
    paddle_cost = Decimal(paddle_count) * paddle_rate
    total_cost = court_cost + paddle_cost

    return {
        "court_type": court_type,
        "start_time": start_time.strftime("%H:%M"),
        "end_time": end_time.strftime("%H:%M"),
        "daytime_hours": day_hours,
        "nighttime_hours": night_hours,
        "court_cost": court_cost,
        "paddle_count": paddle_count,
        "paddle_cost": paddle_cost,
        "total_cost": total_cost,
    }


@app.get("/courts/{court_id}/availability", tags=["Courts"])
async def get_court_availability(
    court_id: str,
    booking_date: date = Query(default_factory=lambda: datetime.now(PH_TZ).date(), description="Booking date (YYYY-MM-DD)"),
):
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(
            """
            SELECT booking_id, customer_id, staff_id, court_id, booking_date,
                   start_time, end_time, exclusive, paddle_count, status,
                   created_at, hold_expires_at
            FROM resort.booking
            WHERE court_id = $1
              AND booking_date = $2
              AND (
                  status IN ('Confirmed', 'Checked-In')
                  OR (status = 'Pending' AND hold_expires_at > CURRENT_TIMESTAMP)
              )
            ORDER BY start_time
            """,
            court_id,
            booking_date,
        )
        return {
            "court_id": court_id,
            "booking_date": booking_date,
            "reserved_slots": [dict(r) for r in rows],
        }


@app.post(
    "/courts",
    status_code=status.HTTP_201_CREATED,
    response_model=CourtResponse,
    tags=["Courts"],
    dependencies=[Depends(verify_staff_token)],
)
async def create_court(court: CourtCreate):
    async with acquire_db_connection() as conn:
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO resort.court (court_id, court_name, court_type, rate_daytime, rate_nighttime, paddle_rate)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING court_id, court_name, court_type, rate_daytime, rate_nighttime, paddle_rate
                """,
                court.court_id,
                court.court_name,
                court.court_type,
                court.rate_daytime,
                court.rate_nighttime,
                court.paddle_rate,
            )
            return dict(row)
        except Exception as err:
            handle_db_exception(err)


# =============================================================================
# RESORT MODULE: RESERVATIONS & BOOKINGS CRUD
# =============================================================================
@app.get("/bookings", response_model=List[BookingResponse], tags=["Bookings"])
async def get_bookings(status_filter: Optional[str] = Query(default=None, alias="status")):
    base_query = """
        SELECT 
            b.booking_id, b.customer_id, c.email AS customer_email, b.staff_id, b.court_id, b.booking_date,
            b.start_time, b.end_time, b.check_in_date, b.check_out_date, b.exclusive,
            b.paddle_count, b.status, b.created_at, b.hold_expires_at, b.total_amount,
            COALESCE(
                (SELECT array_agg(br.room_id) FROM resort.booking_room br WHERE br.booking_id = b.booking_id),
                ARRAY[]::varchar[]
            ) AS room_ids
        FROM resort.booking b
        LEFT JOIN resort.customer c ON b.customer_id = c.customer_id
    """
    async with acquire_db_connection() as conn:
        if status_filter:
            rows = await conn.fetch(base_query + " WHERE b.status = $1 ORDER BY b.created_at DESC", status_filter)
        else:
            rows = await conn.fetch(base_query + " ORDER BY b.created_at DESC")

        results = []
        for r in rows:
            item = dict(r)
            r_ids = list(item.get("room_ids") or [])
            item["room_ids"] = r_ids
            item["room_id"] = r_ids[0] if r_ids else None
            results.append(item)
        return results


@app.get("/bookings/active", response_model=List[BookingResponse], tags=["Bookings"])
async def get_active_bookings():
    query = """
        SELECT 
            b.booking_id, b.customer_id, c.email AS customer_email, b.staff_id, b.court_id, b.booking_date,
            b.start_time, b.end_time, b.check_in_date, b.check_out_date, b.exclusive,
            b.paddle_count, b.status, b.created_at, b.hold_expires_at, b.total_amount,
            COALESCE(
                (SELECT array_agg(br.room_id) FROM resort.booking_room br WHERE br.booking_id = b.booking_id),
                ARRAY[]::varchar[]
            ) AS room_ids
        FROM resort.booking b
        LEFT JOIN resort.customer c ON b.customer_id = c.customer_id
        WHERE b.status IN ('Confirmed', 'Checked-In')
           OR (b.status = 'Pending' AND b.hold_expires_at > CURRENT_TIMESTAMP)
        ORDER BY b.created_at DESC
    """
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(query)
        results = []
        for r in rows:
            item = dict(r)
            r_ids = list(item.get("room_ids") or [])
            item["room_ids"] = r_ids
            item["room_id"] = r_ids[0] if r_ids else None
            results.append(item)
        return results


@app.get("/bookings/{booking_id}", response_model=BookingResponse, tags=["Bookings"])
async def get_booking(booking_id: str):
    query = """
        SELECT 
            b.booking_id, b.customer_id, c.email AS customer_email, b.staff_id, b.court_id, b.booking_date,
            b.start_time, b.end_time, b.check_in_date, b.check_out_date, b.exclusive,
            b.paddle_count, b.status, b.created_at, b.hold_expires_at, b.total_amount,
            COALESCE(
                (SELECT array_agg(br.room_id) FROM resort.booking_room br WHERE br.booking_id = b.booking_id),
                ARRAY[]::varchar[]
            ) AS room_ids
        FROM resort.booking b
        LEFT JOIN resort.customer c ON b.customer_id = c.customer_id
        WHERE b.booking_id = $1
    """
    async with acquire_db_connection() as conn:
        row = await conn.fetchrow(query, booking_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found.")
        item = dict(row)
        r_ids = list(item.get("room_ids") or [])
        item["room_ids"] = r_ids
        item["room_id"] = r_ids[0] if r_ids else None
        return item


@app.post(
    "/bookings",
    status_code=status.HTTP_201_CREATED,
    response_model=BookingResponse,
    tags=["Bookings"],
)
async def create_booking(booking: BookingCreate):
    async with acquire_db_connection() as conn:
        async with conn.transaction():
            try:
                now_ph = datetime.now(PH_TZ)
                today_server = now_ph.date()
                now_time_server = now_ph.time()
                target_date = booking.check_in_date or booking.booking_date

                if target_date < today_server:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Booking Failure: Cannot create reservations for past dates!",
                    )

                if target_date == today_server and booking.start_time and booking.start_time < now_time_server:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Booking Failure: Cannot reserve time slots that have already passed for today!",
                    )

                # Resolve Staff ID safely
                staff_id_val = booking.staff_id.strip()[:10] if booking.staff_id and booking.staff_id.strip() else None
                if staff_id_val:
                    await conn.execute(
                        """
                        INSERT INTO resort.staff (staff_id, first_name, last_name, role)
                        VALUES ($1, 'Front Desk', 'Staff', 'Front Desk')
                        ON CONFLICT (staff_id) DO NOTHING
                        """,
                        staff_id_val,
                    )

                # STRICT CUSTOMER VERIFICATION: Only registered accounts in resort.customer may book!
                raw_cust = booking.customer_id.strip()
                raw_email = booking.customer_email.strip().lower() if booking.customer_email and booking.customer_email.strip() else ""

                existing_cust = await conn.fetchrow(
                    """
                    SELECT customer_id, email
                    FROM resort.customer
                    WHERE customer_id = $1
                       OR ($2 <> '' AND LOWER(email) = LOWER($2))
                       OR LOWER(email) = LOWER($1)
                       OR LOWER(username) = LOWER($1)
                    LIMIT 1
                    """,
                    raw_cust,
                    raw_email,
                )

                if not existing_cust:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="ERR-401-UNREGISTERED: Booking rejected. You must be logged into a valid registered CasaVista account to make a reservation.",
                    )

                resolved_customer_id = existing_cust["customer_id"]
                resolved_customer_email = existing_cust["email"]

                is_room_booking = booking.check_in_date is not None and booking.check_out_date is not None

                court_id_val = None if is_room_booking else (booking.court_id.strip()[:10] if booking.court_id and booking.court_id.strip() else None)
                start_time_val = None if is_room_booking else booking.start_time
                end_time_val = None if is_room_booking else booking.end_time
                check_in_val = booking.check_in_date if is_room_booking else None
                check_out_val = booking.check_out_date if is_room_booking else None
                paddle_count_val = 0 if is_room_booking else booking.paddle_count

                target_rooms: List[str] = []
                if is_room_booking:
                    if booking.room_ids and len(booking.room_ids) > 0:
                        target_rooms = [r.strip()[:10] for r in booking.room_ids if r and r.strip()]
                    elif booking.room_id and booking.room_id.strip():
                        target_rooms = [booking.room_id.strip()[:10]]
                    else:
                        target_rooms = ["RM-101"]

                    for r_id in target_rooms:
                        num = r_id.replace("RM-", "")
                        await conn.execute(
                            """
                            INSERT INTO resort.room (room_id, room_number, rate_per_day, max_pax, status, room_type)
                            VALUES ($1, $2, 2500.00, 4, 'Ready', 'Standard')
                            ON CONFLICT (room_id) DO NOTHING
                            """,
                            r_id,
                            num,
                        )

                if court_id_val:
                    is_basketball = "BK" in court_id_val.upper() or "BASKET" in court_id_val.upper()
                    c_type = "Basketball" if is_basketball else "Pickleball"
                    c_name = "Basketball Half-Court" if is_basketball else f"Court {court_id_val}"
                    c_day_rate = Decimal("500.00") if is_basketball else Decimal("400.00")
                    c_night_rate = Decimal("750.00") if is_basketball else Decimal("600.00")
                    c_paddle_rate = Decimal("0.00") if is_basketball else Decimal("100.00")

                    await conn.execute(
                        """
                        INSERT INTO resort.court (court_id, court_name, court_type, rate_daytime, rate_nighttime, paddle_rate)
                        VALUES ($1, $2, $3, $4, $5, $6)
                        ON CONFLICT (court_id) DO NOTHING
                        """,
                        court_id_val,
                        c_name,
                        c_type,
                        c_day_rate,
                        c_night_rate,
                        c_paddle_rate,
                    )

                    collision = await conn.fetchrow(
                        """
                        SELECT booking_id
                        FROM resort.booking
                        WHERE court_id = $1
                          AND booking_date = $2
                          AND status <> 'Cancelled'
                          AND start_time < $4
                          AND end_time > $3
                        LIMIT 1
                        """,
                        court_id_val,
                        booking.booking_date,
                        start_time_val,
                        end_time_val,
                    )
                    if collision:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail="ERR-409-COURT-COLLISION: Sorry, this time slot is already reserved on this court. Please select a different time slot or court.",
                        )

                row = await conn.fetchrow(
                    """
                    INSERT INTO resort.booking (
                        booking_id, customer_id, staff_id, court_id, booking_date,
                        start_time, end_time, check_in_date, check_out_date, exclusive,
                        paddle_count, status, created_at, hold_expires_at, total_amount
                    )
                    VALUES (
                        $1, $2, $3, $4, $5,
                        $6, $7, $8, $9, $10,
                        $11, 'Pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '15 minutes', $12
                    )
                    RETURNING booking_id, customer_id, staff_id, court_id, booking_date,
                              start_time, end_time, check_in_date, check_out_date, exclusive,
                              paddle_count, status, created_at, hold_expires_at, total_amount
                    """,
                    booking.booking_id,
                    resolved_customer_id,
                    staff_id_val,
                    court_id_val,
                    booking.booking_date,
                    start_time_val,
                    end_time_val,
                    check_in_val,
                    check_out_val,
                    booking.exclusive if is_room_booking else False,
                    paddle_count_val,
                    booking.total_amount,
                )

                if is_room_booking:
                    for r_id in target_rooms:
                        rate_row = await conn.fetchrow("SELECT rate_per_day FROM resort.room WHERE room_id = $1", r_id)
                        rate = rate_row["rate_per_day"] if rate_row else Decimal("2500.00")
                        await conn.execute(
                            """
                            INSERT INTO resort.booking_room (booking_id, room_id, rate_per_day)
                            VALUES ($1, $2, $3)
                            """,
                            booking.booking_id,
                            r_id,
                            rate,
                        )

                item = dict(row)
                item["customer_email"] = resolved_customer_email
                item["room_ids"] = target_rooms if is_room_booking else []
                item["room_id"] = target_rooms[0] if (is_room_booking and target_rooms) else None
                return item

            except HTTPException:
                raise
            except Exception as err:
                handle_db_exception(err)


@app.put("/bookings/{booking_id}/status", response_model=BookingResponse, tags=["Bookings"])
async def update_booking_status(
    booking_id: str,
    new_status: Literal["Pending", "Confirmed", "Checked-In", "Completed", "Cancelled"] = Query(..., alias="new_status"),
):
    async with acquire_db_connection() as conn:
        try:
            row = await conn.fetchrow(
                """
                UPDATE resort.booking
                SET status = $1
                WHERE booking_id = $2
                RETURNING booking_id, customer_id, staff_id, court_id, booking_date,
                          start_time, end_time, check_in_date, check_out_date, exclusive,
                          paddle_count, status, created_at, hold_expires_at, total_amount
                """,
                new_status,
                booking_id,
            )
            if row is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found.")

            cust_row = await conn.fetchrow("SELECT email FROM resort.customer WHERE customer_id = $1", row["customer_id"])
            room_rows = await conn.fetch("SELECT room_id FROM resort.booking_room WHERE booking_id = $1", booking_id)
            r_ids = [r["room_id"] for r in room_rows]

            item = dict(row)
            item["customer_email"] = cust_row["email"] if cust_row else None
            item["room_ids"] = r_ids
            item["room_id"] = r_ids[0] if r_ids else None
            return item
        except HTTPException:
            raise
        except Exception as err:
            handle_db_exception(err)


# =============================================================================
# RESORT MODULE: PAYMENT PROCESSING
# =============================================================================
@app.post(
    "/payments",
    status_code=status.HTTP_201_CREATED,
    response_model=PaymentResponse,
    tags=["Payments"],
)
async def process_payment(payment: PaymentCreate):
    async with acquire_db_connection() as conn:
        async with conn.transaction():
            try:
                if payment.payment_type == "Refund" and payment.booking_id:
                    booking = await conn.fetchrow(
                        """
                        SELECT check_in_date, start_time FROM resort.booking
                        WHERE booking_id = $1
                        """,
                        payment.booking_id,
                    )
                    if not booking:
                        raise HTTPException(
                            status_code=status.HTTP_404_NOT_FOUND,
                            detail="Target booking for refund not found.",
                        )

                    sched_date = booking["check_in_date"] or datetime.now(PH_TZ).date()
                    sched_time = booking["start_time"] or time(14, 0)
                    sched_dt = datetime.combine(sched_date, sched_time)

                    if (sched_dt - datetime.now(PH_TZ).replace(tzinfo=None)).total_seconds() < 86400:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Cancellations requested within 24 hours of check-in are strictly non-refundable.",
                        )

                row = await conn.fetchrow(
                    """
                    INSERT INTO resort.payment (payment_id, booking_id, order_id, amount, method, payment_type, paid_at)
                    VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
                    RETURNING payment_id, booking_id, order_id, amount, method, payment_type, paid_at
                    """,
                    payment.payment_id,
                    payment.booking_id if payment.booking_id and payment.booking_id.strip() else None,
                    payment.order_id if payment.order_id and payment.order_id.strip() else None,
                    payment.amount,
                    payment.method,
                    payment.payment_type,
                )

                if payment.booking_id and payment.booking_id.strip() and payment.payment_type == "Payment":
                    await conn.execute(
                        """
                        UPDATE resort.booking
                        SET status = 'Confirmed'
                        WHERE booking_id = $1 AND status = 'Pending'
                        """,
                        payment.booking_id,
                    )

                return dict(row)
            except HTTPException:
                raise
            except Exception as err:
                handle_db_exception(err)


# =============================================================================
# POS MODULE: CATALOG & ORDERS
# =============================================================================
@app.get("/pos/items", response_model=List[POSItemResponse], tags=["POS Catalog"])
async def get_pos_items():
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(
            """
            SELECT item_id, name, category, price
            FROM pos.pos_item
            ORDER BY item_id
            """
        )
        return [dict(r) for r in rows]


@app.post(
    "/pos/items",
    status_code=status.HTTP_201_CREATED,
    response_model=POSItemResponse,
    tags=["POS Catalog"],
    dependencies=[Depends(verify_staff_token)],
)
async def create_pos_item(item: POSItemCreate):
    async with acquire_db_connection() as conn:
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO pos.pos_item (item_id, name, category, price)
                VALUES ($1, $2, $3, $4)
                RETURNING item_id, name, category, price
                """,
                item.item_id,
                item.name,
                item.category,
                item.price,
            )
            return dict(row)
        except Exception as err:
            handle_db_exception(err)


@app.post(
    "/pos/orders",
    status_code=status.HTTP_201_CREATED,
    response_model=POSOrderResponse,
    tags=["POS Orders"],
)
async def create_pos_order(order: POSOrderCreate):
    async with acquire_db_connection() as conn:
        async with conn.transaction():
            try:
                item_ids = [i.item_id for i in order.items]
                price_rows = await conn.fetch(
                    "SELECT item_id, price FROM pos.pos_item WHERE item_id = ANY($1::varchar[])",
                    item_ids,
                )
                price_map = {r["item_id"]: r["price"] for r in price_rows}

                missing = set(item_ids) - set(price_map.keys())
                if missing:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"POS Items not found: {', '.join(missing)}",
                    )

                total_amount = Decimal("0.00")
                line_items_data = []
                for item in order.items:
                    unit_price = price_map[item.item_id]
                    subtotal = unit_price * item.quantity
                    total_amount += subtotal
                    line_items_data.append((order.order_id, item.item_id, item.quantity, subtotal))

                order_row = await conn.fetchrow(
                    """
                    INSERT INTO pos.pos_order (order_id, customer_id, staff_id, booking_id, order_date, total_amount)
                    VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, $5)
                    RETURNING order_id, customer_id, staff_id, booking_id, order_date, total_amount
                    """,
                    order.order_id,
                    order.customer_id,
                    order.staff_id,
                    order.booking_id if order.booking_id and order.booking_id.strip() else None,
                    total_amount,
                )

                inserted_items = []
                for item_record in line_items_data:
                    item_row = await conn.fetchrow(
                        """
                        INSERT INTO pos.pos_order_item (order_id, item_id, quantity, subtotal)
                        VALUES ($1, $2, $3, $4)
                        RETURNING order_id, item_id, quantity, subtotal
                        """,
                        item_record[0],
                        item_record[1],
                        item_record[2],
                        item_record[3],
                    )
                    inserted_items.append(dict(item_row))

                res = dict(order_row)
                res["items"] = inserted_items
                return res

            except HTTPException:
                raise
            except Exception as err:
                handle_db_exception(err)


@app.get("/pos/orders/{order_id}", response_model=POSOrderResponse, tags=["POS Orders"])
async def get_pos_order(order_id: str):
    async with acquire_db_connection() as conn:
        order_row = await conn.fetchrow(
            """
            SELECT order_id, customer_id, staff_id, booking_id, order_date, total_amount
            FROM pos.pos_order
            WHERE order_id = $1
            """,
            order_id,
        )
        if order_row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="POS Order not found.")

        item_rows = await conn.fetch(
            """
            SELECT order_id, item_id, quantity, subtotal
            FROM pos.pos_order_item
            WHERE order_id = $1
            ORDER BY item_id
            """,
            order_id,
        )

        res = dict(order_row)
        res["items"] = [dict(r) for r in item_rows]
        return res


# =============================================================================
# RELATIONAL REPORTS & AUDIT QUERIES
# =============================================================================
@app.get("/reports/active-bookings-detail", tags=["Relational Reports"])
async def report_active_bookings():
    query = """
        SELECT 
            b.booking_id,
            b.status AS booking_status,
            b.booking_date,
            c.customer_id,
            c.first_name || ' ' || c.last_name AS customer_full_name,
            c.phone AS customer_phone,
            COALESCE(s.first_name || ' ' || s.last_name, 'Unassigned') AS handler_staff_name,
            r.room_number,
            r.rate_per_day,
            ct.court_name,
            ct.court_type,
            b.paddle_count,
            b.created_at,
            b.hold_expires_at
        FROM resort.booking b
        INNER JOIN resort.customer c ON b.customer_id = c.customer_id
        LEFT JOIN resort.staff s ON b.staff_id = s.staff_id
        LEFT JOIN resort.booking_room br ON b.booking_id = br.booking_id
        LEFT JOIN resort.room r ON br.room_id = r.room_id
        LEFT JOIN resort.court ct ON b.court_id = ct.court_id
        ORDER BY b.created_at DESC
    """
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(query)
        return [dict(r) for r in rows]


@app.get("/reports/room-occupancy-audit", tags=["Relational Reports"])
async def report_room_occupancy():
    query = """
        SELECT 
            r.room_id,
            r.room_number,
            r.status AS housekeeping_status,
            r.rate_per_day,
            b.booking_id,
            b.status AS booking_status,
            b.check_in_date,
            b.check_out_date,
            c.first_name || ' ' || c.last_name AS current_guest_name
        FROM resort.room r
        LEFT JOIN resort.booking_room br ON r.room_id = br.room_id AND br.is_active
        LEFT JOIN resort.booking b ON br.booking_id = b.booking_id AND b.status IN ('Confirmed', 'Checked-In')
        LEFT JOIN resort.customer c ON b.customer_id = c.customer_id
        ORDER BY r.room_number
    """
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(query)
        return [dict(r) for r in rows]


@app.get("/reports/pos-sales-ledger", tags=["Relational Reports"])
async def report_pos_sales():
    query = """
        SELECT 
            o.order_id,
            o.order_date,
            i.item_id,
            i.name AS product_name,
            i.category,
            poi.quantity,
            poi.subtotal AS line_subtotal,
            o.total_amount AS order_total,
            s.first_name || ' ' || s.last_name AS cashier_staff_name,
            COALESCE(c.first_name || ' ' || c.last_name, 'Walk-In Customer') AS customer_name
        FROM pos.pos_order o
        INNER JOIN pos.pos_order_item poi ON o.order_id = poi.order_id
        INNER JOIN pos.pos_item i ON poi.item_id = i.item_id
        INNER JOIN resort.staff s ON o.staff_id = s.staff_id
        LEFT JOIN resort.customer c ON o.customer_id = c.customer_id
        ORDER BY o.order_date DESC, o.order_id
    """
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(query)
        return [dict(r) for r in rows]


@app.get("/reports/financial-payments-audit", tags=["Relational Reports"])
async def report_financial_payments():
    query = """
        SELECT 
            p.payment_id,
            p.amount,
            p.method,
            p.payment_type,
            p.paid_at,
            CASE 
                WHEN p.booking_id IS NOT NULL THEN 'Accommodation/Court Booking'
                ELSE 'POS Counter Sale'
            END AS transaction_channel,
            p.booking_id,
            b.status AS booking_status,
            p.order_id,
            o.total_amount AS order_registered_total
        FROM resort.payment p
        LEFT JOIN resort.booking b ON p.booking_id = b.booking_id
        LEFT JOIN pos.pos_order o ON p.order_id = o.order_id
        ORDER BY p.paid_at DESC
    """
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(query)
        return [dict(r) for r in rows]


# =============================================================================
# ADMIN P&L / REVENUE ANALYTICS
# =============================================================================
@app.get(
    "/reports/revenue-pnl",
    tags=["Admin Financial Reports"],
    dependencies=[Depends(verify_staff_token)],
)
async def get_revenue_pnl_summary(
    start_date: Optional[date] = Query(default=None, description="Filter from date (YYYY-MM-DD)"),
    end_date: Optional[date] = Query(default=None, description="Filter to date (YYYY-MM-DD)"),
):
    query = """
        SELECT 
            COALESCE(SUM(CASE 
                WHEN p.booking_id IS NOT NULL AND p.payment_type = 'Payment' THEN p.amount 
                ELSE 0 
            END), 0) AS gross_booking_revenue,

            COALESCE(SUM(CASE 
                WHEN p.order_id IS NOT NULL AND p.payment_type = 'Payment' THEN p.amount 
                ELSE 0 
            END), 0) AS gross_pos_revenue,

            COALESCE(SUM(CASE 
                WHEN p.payment_type = 'Refund' THEN p.amount 
                ELSE 0 
            END), 0) AS total_refunds,

            COALESCE(SUM(CASE 
                WHEN p.payment_type = 'Payment' THEN p.amount 
                ELSE 0 
            END), 0) AS total_gross_revenue,

            COALESCE(SUM(CASE 
                WHEN p.payment_type = 'Payment' THEN p.amount 
                WHEN p.payment_type = 'Refund' THEN -p.amount 
                ELSE 0 
            END), 0) AS net_revenue,

            COUNT(p.payment_id) AS total_transactions_count
        FROM resort.payment p
        WHERE ($1::date IS NULL OR p.paid_at::date >= $1)
          AND ($2::date IS NULL OR p.paid_at::date <= $2)
    """
    async with acquire_db_connection() as conn:
        row = await conn.fetchrow(query, start_date, end_date)
        return {
            "period": {
                "start_date": start_date or "All-Time",
                "end_date": end_date or "All-Time",
            },
            "financial_breakdown": {
                "gross_booking_revenue": row["gross_booking_revenue"],
                "gross_pos_revenue": row["gross_pos_revenue"],
                "total_gross_revenue": row["total_gross_revenue"],
                "total_refunds_deductions": row["total_refunds"],
                "net_operating_revenue": row["net_revenue"],
            },
            "total_transactions": row["total_transactions_count"],
        }