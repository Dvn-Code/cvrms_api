from __future__ import annotations

import base64
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

# =============================================================================
# DATABASE CONNECTION CONFIGURATION
# =============================================================================
DB_USER = os.getenv("DB_USER", "cvrms_prd_service_account.knobgbjusbcqaatizjld")
DB_PASSWORD = os.getenv("DB_PASSWORD", "SWU_Root2026!!")
DB_HOST = os.getenv("DB_HOST", "aws-0-ap-southeast-1.pooler.supabase.com")
DB_PORT = os.getenv("DB_PORT", "6543")
DB_NAME = os.getenv("DB_NAME", "postgres")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"


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
    except Exception as e:
        print(f"Pool startup notice: {e}")
    yield
    if hasattr(app.state, "pool") and app.state.pool is not None:
        try:
            await app.state.pool.close()
        except Exception:
            pass


# =============================================================================
# SWAGGER GATEWAY AUTHENTICATION (BROWSER POPUP ONLY)
# =============================================================================
docs_security = HTTPBasic(auto_error=True)

ADMIN_USER = os.getenv("ADMIN_USERNAME", "cvrms_prd_service_account")
ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "Wilchin123")
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
    Does NOT register an OpenAPI security scheme, keeping the Swagger UI free
    of the green "Authorize" button.
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
# FASTAPI APP INSTANCE
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
# PROTECTED SWAGGER ROUTES (NO GREEN AUTHORIZE BUTTON)
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
        user = os.getenv("DB_USER", "cvrms_prd_service_account.knobgbjusbcqaatizjld")
        password = os.getenv("DB_PASSWORD", "SWU_Root2026!!")
        host = os.getenv("DB_HOST", "aws-0-ap-southeast-1.pooler.supabase.com")
        port = os.getenv("DB_PORT", "6543")
        dbname = os.getenv("DB_NAME", "postgres")
        db_url = f"postgresql://{user}:{password}@{host}:{port}/{dbname}"
        app.state.pool = await asyncpg.create_pool(
            db_url,
            min_size=1,
            max_size=5,
            statement_cache_size=0,
        )
    async with app.state.pool.acquire() as conn:
        yield conn


# =============================================================================
# PYDANTIC SCHEMAS
# =============================================================================

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
    phone: Optional[str] = Field(default="N/A", max_length=20)
    address: Optional[str] = Field(default=None, max_length=255)
    customer_type: Literal["Registered", "Walk-In"] = "Registered"


class CustomerUpdate(CustomerBase):
    pass


# Response model does not enforce registration validation rules
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

    customer_id: str = Field(min_length=3, max_length=20)
    staff_id: Optional[str] = Field(default=None, max_length=10)
    room_id: Optional[str] = Field(default=None, max_length=10)
    room_ids: Optional[List[str]] = Field(default=None)
    court_id: Optional[str] = Field(default=None, max_length=10)
    booking_date: date = Field(default_factory=date.today)
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
    print(f"\n>>> [DATABASE ERROR]: {type(err).__name__} -> {err}\n")
    if isinstance(err, asyncpg.UniqueViolationError):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Resource conflict: {err.detail or 'A duplicate entry violates a UNIQUE constraint.'}",
        )
    if isinstance(err, asyncpg.ForeignKeyViolationError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Foreign key constraint failed: {err.detail or 'Referenced parent key does not exist.'}",
        )
    if isinstance(err, asyncpg.CheckViolationError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Business rule violation: {err.detail or 'Operation failed a database CHECK constraint.'}",
        )
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=f"Database Error ({type(err).__name__}): {str(err)}",
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
# IN-MEMORY OTP VERIFICATION
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


# =============================================================================
# RESORT MODULE: CUSTOMERS CRUD
# =============================================================================
@app.get("/customers", response_model=List[CustomerResponse], tags=["Customers"])
async def get_customers():
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(
            """
            SELECT customer_id, first_name, middle_name, last_name, email, phone, address, customer_type
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
            SELECT customer_id, first_name, middle_name, last_name, email, phone, address, customer_type
            FROM resort.customer
            WHERE customer_id = $1 OR LOWER(email) = LOWER($1)
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
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO resort.customer (first_name, middle_name, last_name, email, phone, address, customer_type)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING customer_id, first_name, middle_name, last_name, email, phone, address, customer_type
                """,
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
        try:
            phone_val = customer.phone if customer.phone and customer.phone.strip() else "N/A"
            address_val = customer.address if customer.address and customer.address.strip() else "N/A"

            existing = await conn.fetchrow(
                """
                UPDATE resort.customer
                SET first_name = $1, middle_name = COALESCE($2, middle_name), last_name = $3, phone = $4, address = COALESCE($5, address)
                WHERE LOWER(email) = LOWER($6)
                RETURNING customer_id, first_name, middle_name, last_name, email, phone, address, customer_type
                """,
                customer.first_name,
                customer.middle_name,
                customer.last_name,
                phone_val,
                address_val,
                customer.email,
            )
            if existing:
                return dict(existing)

            row = await conn.fetchrow(
                """
                INSERT INTO resort.customer (first_name, middle_name, last_name, email, phone, address, customer_type)
                VALUES ($1, $2, $3, $4, $5, $6, 'Registered')
                RETURNING customer_id, first_name, middle_name, last_name, email, phone, address, customer_type
                """,
                customer.first_name,
                customer.middle_name,
                customer.last_name,
                customer.email,
                phone_val,
                address_val,
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
    booking_date: date = Query(default_factory=date.today, description="Booking date (YYYY-MM-DD)"),
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
# RESORT MODULE: RESERVATIONS & BOOKINGS CRUD (SCHEMA ALIGNED)
# =============================================================================
@app.get("/bookings", response_model=List[BookingResponse], tags=["Bookings"])
async def get_bookings(status_filter: Optional[str] = Query(default=None, alias="status")):
    base_query = """
        SELECT 
            b.booking_id, b.customer_id, b.staff_id, b.court_id, b.booking_date,
            b.start_time, b.end_time, b.check_in_date, b.check_out_date, b.exclusive,
            b.paddle_count, b.status, b.created_at, b.hold_expires_at, b.total_amount,
            COALESCE(
                (SELECT array_agg(br.room_id) FROM resort.booking_room br WHERE br.booking_id = b.booking_id),
                ARRAY[]::varchar[]
            ) AS room_ids
        FROM resort.booking b
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
            b.booking_id, b.customer_id, b.staff_id, b.court_id, b.booking_date,
            b.start_time, b.end_time, b.check_in_date, b.check_out_date, b.exclusive,
            b.paddle_count, b.status, b.created_at, b.hold_expires_at, b.total_amount,
            COALESCE(
                (SELECT array_agg(br.room_id) FROM resort.booking_room br WHERE br.booking_id = b.booking_id),
                ARRAY[]::varchar[]
            ) AS room_ids
        FROM resort.booking b
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
            b.booking_id, b.customer_id, b.staff_id, b.court_id, b.booking_date,
            b.start_time, b.end_time, b.check_in_date, b.check_out_date, b.exclusive,
            b.paddle_count, b.status, b.created_at, b.hold_expires_at, b.total_amount,
            COALESCE(
                (SELECT array_agg(br.room_id) FROM resort.booking_room br WHERE br.booking_id = b.booking_id),
                ARRAY[]::varchar[]
            ) AS room_ids
        FROM resort.booking b
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
                today_server = date.today()
                now_time_server = datetime.now().time()
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

                if booking.staff_id and booking.staff_id.strip():
                    await conn.execute(
                        """
                        INSERT INTO resort.staff (staff_id, first_name, last_name, role)
                        VALUES ($1, 'Front Desk', 'Staff', 'Front Desk')
                        ON CONFLICT (staff_id) DO NOTHING
                        """,
                        booking.staff_id,
                    )

                await conn.execute(
                    """
                    INSERT INTO resort.customer (customer_id, first_name, last_name, email, phone, address, customer_type)
                    VALUES ($1, 'Registered', 'Customer', $2, '09123456789', 'Cebu City', 'Registered')
                    ON CONFLICT (customer_id) DO NOTHING
                    """,
                    booking.customer_id,
                    f"{booking.customer_id.lower()}@casavista.com",
                )

                is_room_booking = booking.check_in_date is not None and booking.check_out_date is not None

                # Enforce chk_booking_shape constraint at database level
                court_id_val = None if is_room_booking else (booking.court_id if booking.court_id and booking.court_id.strip() else None)
                start_time_val = None if is_room_booking else booking.start_time
                end_time_val = None if is_room_booking else booking.end_time
                check_in_val = booking.check_in_date if is_room_booking else None
                check_out_val = booking.check_out_date if is_room_booking else None
                paddle_count_val = 0 if is_room_booking else booking.paddle_count

                target_rooms: List[str] = []
                if is_room_booking:
                    if booking.room_ids and len(booking.room_ids) > 0:
                        target_rooms = booking.room_ids
                    elif booking.room_id and booking.room_id.strip():
                        target_rooms = [booking.room_id]
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
                    await conn.execute(
                        """
                        INSERT INTO resort.court (court_id, court_name, court_type, rate_daytime, rate_nighttime, paddle_rate)
                        VALUES ($1, 'Court ' || $1, 'Pickleball', 400.00, 600.00, 100.00)
                        ON CONFLICT (court_id) DO NOTHING
                        """,
                        court_id_val,
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
                    booking.customer_id,
                    booking.staff_id if booking.staff_id and booking.staff_id.strip() else None,
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

            room_rows = await conn.fetch("SELECT room_id FROM resort.booking_room WHERE booking_id = $1", booking_id)
            r_ids = [r["room_id"] for r in room_rows]

            item = dict(row)
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

                    sched_date = booking["check_in_date"] or date.today()
                    sched_time = booking["start_time"] or time(14, 0)
                    sched_dt = datetime.combine(sched_date, sched_time)

                    if (sched_dt - datetime.now()).total_seconds() < 86400:
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
            SELECT order_id, customer_id, staff_id, order_date, total_amount
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