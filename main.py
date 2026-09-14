import os
from contextlib import asynccontextmanager
from datetime import date, datetime, time
from decimal import Decimal
from typing import Literal

import asyncpg
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

try:
    from pydantic import EmailStr
except Exception:
    EmailStr = str

load_dotenv()

#This is the main.py (FastAPI) for CVRMS (Casa Vista Resort Management System) API, which serves as the backend for managing resort accommodations, sports amenities, cashless payments, and POS retail modules. It includes database connection configuration, application lifespan management, Pydantic schemas for data validation, and CRUD operations for customers, staff, rooms, courts, bookings, payments, and POS items.
#Members: Abarquez, Divinangelo; Astrologo, Russell John; Cabilao, John Michael
#We intended to use FastAPI plus Supabase instead of local PHP since the client is serious in deploying this project and we have learned so much during our ITE 298 course.
#With that, this code already included github license (Apache 2.0) and we will be using this code for our final project in ITE 298.
#We also added a vercel.json and requirements.txt for free online hosting of the FastAPI.
#We have successfully deployed this project on Vercel and the link is https://cvrms-api.vercel.app/docs 
#We also successfully tried to register a customer in our Android Application, and thankfuly it worked after how many days of debugging.
#Plus, we also successfully connected a user to Supabase's auth.users with encrypted password.
#We also finished including Google Log-in Authentication for our Android App still incorporating Supabase with this FastAPI. 
#The limitations, however, for this P2 submission is that we haven't tried to actualy book a room yet. We still focused on registering an account (customer), not yet admin too.
#There's also no POS yet. Hehehe we don't know how to yet.
#Any feedbacks, suggestions, and comments are welcome. Thank you for your time and consideration sir.
#Note: We acknowledge that we used AI for this project but we also made sure to understand atleast the logic and flow of the code.
#- we also watched a lot of youtube videos and read some articles to understand the code and how to implement it in our Android Application.
#Thank you so much!

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


app = FastAPI(
    title="Casa Vista Resort Management System (CVRMS) API",
    description="Backend API supporting Resort Accommodations, Sports Amenities, Cashless Payments, and POS Retail Modules.",
    version="2.0.0",
    lifespan=lifespan,
)


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
# PYDANTIC SCHEMAS: VALIDATION, SANITIZATION & GUARDS
# =============================================================================

# --- CUSTOMER SCHEMAS ---
class CustomerBase(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    first_name: str = Field(min_length=1, max_length=50)
    last_name: str = Field(min_length=1, max_length=50)
    email: EmailStr | None = Field(default=None, max_length=120)
    phone: str = Field(min_length=7, max_length=20)
    address: str | None = Field(default=None, max_length=255)

    @field_validator("first_name", "last_name")
    @classmethod
    def names_must_not_contain_digits(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if any(char.isdigit() for char in v):
            raise ValueError("Names cannot contain numbers.")
        return v

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str | None) -> str | None:
        return v.lower() if v else None


class CustomerCreate(CustomerBase):
    pass


class CustomerUpdate(CustomerBase):
    pass


class CustomerResponse(CustomerBase):
    customer_id: str


# --- STAFF SCHEMAS ---
class StaffBase(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    first_name: str = Field(min_length=1, max_length=50)
    last_name: str = Field(min_length=1, max_length=50)
    role: str = Field(min_length=2, max_length=50)

    @field_validator("first_name", "last_name")
    @classmethod
    def names_must_not_contain_digits(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if any(char.isdigit() for char in v):
            raise ValueError("Staff names cannot contain numbers.")
        return v


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
    status: Literal["Available", "Occupied", "Cleaning", "Maintenance"] = "Available"


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

    customer_id: str = Field(min_length=3, max_length=10)
    staff_id: str = Field(min_length=3, max_length=10)
    room_id: str | None = Field(default=None, max_length=10)
    court_id: str | None = Field(default=None, max_length=10)
    booking_date: date
    start_time: time | None = None
    end_time: time | None = None
    check_in_date: date | None = None
    check_out_date: date | None = None
    exclusive: bool = False
    paddle_count: int = Field(default=0, ge=0)
    status: Literal["Pending", "Confirmed", "Checked-In", "Completed", "Cancelled"] = "Pending"

    @model_validator(mode="after")
    def validate_exclusive_booking_arc(self) -> "BookingBase":
        # Database constraint enforcement: XOR between room_id and court_id
        has_room = self.room_id is not None and self.room_id != ""
        has_court = self.court_id is not None and self.court_id != ""

        if not (has_room ^ has_court):
            raise ValueError(
                "A booking must be assigned to either a Room OR a Sports Court, never both and never neither."
            )

        if has_room and (self.check_in_date is None or self.check_out_date is None):
            raise ValueError("Room bookings require both check_in_date and check_out_date.")

        if has_court and (self.start_time is None or self.end_time is None):
            raise ValueError("Court reservations require both start_time and end_time.")

        return self


class BookingCreate(BookingBase):
    booking_id: str = Field(min_length=3, max_length=15, examples=["BK-001"])


class BookingUpdate(BookingBase):
    pass


class BookingResponse(BookingBase):
    booking_id: str
    created_at: datetime
    hold_expires_at: datetime | None


# --- PAYMENT SCHEMAS ---
class PaymentCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    payment_id: str = Field(min_length=3, max_length=15, examples=["PAY-001"])
    booking_id: str | None = Field(default=None, max_length=15)
    order_id: str | None = Field(default=None, max_length=15)
    amount: Decimal = Field(gt=Decimal("0.00"), decimal_places=2)
    method: Literal["Cash", "Card", "GCash", "Maya", "Online Gateway"]
    payment_type: Literal["Payment", "Refund"] = "Payment"

    @model_validator(mode="after")
    def validate_exclusive_payment_arc(self) -> "PaymentCreate":
        # Database constraint enforcement: XOR between booking_id and order_id
        has_booking = self.booking_id is not None and self.booking_id != ""
        has_order = self.order_id is not None and self.order_id != ""

        if not (has_booking ^ has_order):
            raise ValueError(
                "A payment must link to either a Booking OR a POS Order, never both and never neither."
            )
        return self


class PaymentResponse(BaseModel):
    payment_id: str
    booking_id: str | None
    order_id: str | None
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
    customer_id: str | None = Field(default=None, max_length=10)
    staff_id: str = Field(min_length=3, max_length=10)
    items: list[POSOrderItemCreate] = Field(min_length=1)


class POSOrderResponse(BaseModel):
    order_id: str
    customer_id: str | None
    staff_id: str
    order_date: datetime
    total_amount: Decimal
    items: list[POSOrderItemResponse] = []


# =============================================================================
# REUSABLE DATABASE EXCEPTION DISPATCHER & AUTH GUARDS
# =============================================================================
def handle_db_exception(err: Exception) -> None:
    """Translates asyncpg database errors into structured, rubric-compliant HTTP exceptions."""
    # PRINT THE ACTUAL DATABASE ERROR TO TERMINAL
    print(f"\n>>> [DATABASE ERROR TRIGGERED]: {type(err).__name__} -> {err}\n")

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
    # Include the error message in the 500 response while debugging
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=f"Database Error ({type(err).__name__}): {str(err)}",
    )


async def verify_staff_token(x_staff_token: str | None = Header(default=None)):
    """
    Guards administrative and analytical endpoints.
    Returns HTTP 401 Unauthorized if the client omits or supplies an invalid token.
    """
    STAFF_SECRET = os.getenv("STAFF_API_TOKEN", "CVRMS-SECURE-STAFF-TOKEN-2026")
    if not x_staff_token or x_staff_token != STAFF_SECRET:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Valid X-Staff-Token header is required to access this resource.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return x_staff_token


# =============================================================================
# API ROOT ENDPOINT
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
# RESORT MODULE: CUSTOMERS CRUD
# =============================================================================
@app.get("/customers", response_model=list[CustomerResponse], tags=["Customers"])
async def get_customers():
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(
            """
            SELECT customer_id, first_name, last_name, email, phone, address
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
            SELECT customer_id, first_name, last_name, email, phone, address
            FROM resort.customer
            WHERE customer_id = $1
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
                INSERT INTO resort.customer (first_name, last_name, email, phone, address)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING customer_id, first_name, last_name, email, phone, address
                """,
                customer.first_name,
                customer.last_name,
                customer.email,
                customer.phone,
                customer.address,
            )
            return dict(row)
        except Exception as err:
            handle_db_exception(err)


@app.put("/customers/{customer_id}", response_model=CustomerResponse, tags=["Customers"])
async def update_customer(customer_id: str, customer: CustomerUpdate):
    async with acquire_db_connection() as conn:
        try:
            row = await conn.fetchrow(
                """
                UPDATE resort.customer
                SET first_name = $1, last_name = $2, email = $3, phone = $4, address = $5
                WHERE customer_id = $6
                RETURNING customer_id, first_name, last_name, email, phone, address
                """,
                customer.first_name,
                customer.last_name,
                customer.email,
                customer.phone,
                customer.address,
                customer_id,
            )
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found."
                )
            return dict(row)
        except Exception as err:
            handle_db_exception(err)


@app.delete(
    "/customers/{customer_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Customers"]
)
async def delete_customer(customer_id: str):
    async with acquire_db_connection() as conn:
        try:
            status_text = await conn.execute(
                "DELETE FROM resort.customer WHERE customer_id = $1", customer_id
            )
            if status_text.split()[-1] == "0":
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found."
                )
            return None
        except Exception as err:
            handle_db_exception(err)


# =============================================================================
# RESORT MODULE: STAFF CRUD
# =============================================================================
@app.get("/staff", response_model=list[StaffResponse], tags=["Staff"])
async def get_staff_members():
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(
            """
            SELECT staff_id, first_name, last_name, role
            FROM resort.staff
            ORDER BY staff_id
            """
        )
        return [dict(r) for r in rows]


@app.post(
    "/staff", status_code=status.HTTP_201_CREATED, response_model=StaffResponse, tags=["Staff"]
)
async def create_staff(staff: StaffCreate):
    async with acquire_db_connection() as conn:
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO resort.staff (staff_id, first_name, last_name, role)
                VALUES ($1, $2, $3, $4)
                RETURNING staff_id, first_name, last_name, role
                """,
                staff.staff_id,
                staff.first_name,
                staff.last_name,
                staff.role,
            )
            return dict(row)
        except Exception as err:
            handle_db_exception(err)


# =============================================================================
# RESORT MODULE: ROOM INVENTORY & TARIFFS CRUD
# =============================================================================
@app.get("/rooms", response_model=list[RoomResponse], tags=["Rooms"])
async def get_rooms(status_filter: str | None = Query(default=None, alias="status")):
    async with acquire_db_connection() as conn:
        if status_filter:
            rows = await conn.fetch(
                """
                SELECT room_id, room_number, rate_per_day, max_pax, status
                FROM resort.room
                WHERE status = $1
                ORDER BY room_number
                """,
                status_filter,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT room_id, room_number, rate_per_day, max_pax, status
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
            SELECT room_id, room_number, rate_per_day, max_pax, status
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
                INSERT INTO resort.room (room_id, room_number, rate_per_day, max_pax, status)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING room_id, room_number, rate_per_day, max_pax, status
                """,
                room.room_id,
                room.room_number,
                room.rate_per_day,
                room.max_pax,
                room.status,
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
                SET room_number = $1, rate_per_day = $2, max_pax = $3, status = $4
                WHERE room_id = $5
                RETURNING room_id, room_number, rate_per_day, max_pax, status
                """,
                room.room_number,
                room.rate_per_day,
                room.max_pax,
                room.status,
                room_id,
            )
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Room not found."
                )
            return dict(row)
        except Exception as err:
            handle_db_exception(err)


# =============================================================================
# RESORT MODULE: SPORTS COURTS CRUD
# =============================================================================
@app.get("/courts", response_model=list[CourtResponse], tags=["Courts"])
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
@app.get("/bookings", response_model=list[BookingResponse], tags=["Bookings"])
async def get_bookings(status_filter: str | None = Query(default=None, alias="status")):
    async with acquire_db_connection() as conn:
        if status_filter:
            rows = await conn.fetch(
                """
                SELECT booking_id, customer_id, staff_id, room_id, court_id, booking_date,
                       start_time, end_time, check_in_date, check_out_date, exclusive,
                       paddle_count, status, created_at, hold_expires_at
                FROM resort.booking
                WHERE status = $1
                ORDER BY created_at DESC
                """,
                status_filter,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT booking_id, customer_id, staff_id, room_id, court_id, booking_date,
                       start_time, end_time, check_in_date, check_out_date, exclusive,
                       paddle_count, status, created_at, hold_expires_at
                FROM resort.booking
                ORDER BY created_at DESC
                """
            )
        return [dict(r) for r in rows]


@app.get("/bookings/{booking_id}", response_model=BookingResponse, tags=["Bookings"])
async def get_booking(booking_id: str):
    async with acquire_db_connection() as conn:
        row = await conn.fetchrow(
            """
            SELECT booking_id, customer_id, staff_id, room_id, court_id, booking_date,
                   start_time, end_time, check_in_date, check_out_date, exclusive,
                   paddle_count, status, created_at, hold_expires_at
            FROM resort.booking
            WHERE booking_id = $1
            """,
            booking_id,
        )
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found.")
        return dict(row)


@app.post(
    "/bookings",
    status_code=status.HTTP_201_CREATED,
    response_model=BookingResponse,
    tags=["Bookings"],
)
async def create_booking(booking: BookingCreate):
    async with acquire_db_connection() as conn:
        try:
            # 1. Ensure staff_id exists in resort.staff table
            await conn.execute(
                """
                INSERT INTO resort.staff (staff_id, first_name, last_name, role)
                VALUES ($1, 'System', 'Staff', 'Receptionist')
                ON CONFLICT (staff_id) DO NOTHING
                """,
                booking.staff_id,
            )

            # 2. Ensure customer_id exists in resort.customer table
            await conn.execute(
                """
                INSERT INTO resort.customer (customer_id, first_name, last_name, email, phone, address)
                VALUES ($1, 'Resort', 'Guest', $2, '09123456789', 'Cebu City')
                ON CONFLICT (customer_id) DO NOTHING
                """,
                booking.customer_id,
                f"{booking.customer_id.lower()}@casavista.com",
            )

            # 3. Ensure room_id exists in resort.room table if provided
            if booking.room_id and booking.room_id.strip():
                num = booking.room_id.replace("RM-", "")
                await conn.execute(
                    """
                    INSERT INTO resort.room (room_id, room_number, rate_per_day, max_pax, status)
                    VALUES ($1, $2, 2500.00, 4, 'Available')
                    ON CONFLICT (room_id) DO NOTHING
                    """,
                    booking.room_id,
                    num,
                )

            # 4. Ensure court_id exists in resort.court table if provided
            if booking.court_id and booking.court_id.strip():
                await conn.execute(
                    """
                    INSERT INTO resort.court (court_id, court_name, court_type, rate_daytime, rate_nighttime, paddle_rate)
                    VALUES ($1, 'Court ' || $1, 'Pickleball', 400.00, 600.00, 50.00)
                    ON CONFLICT (court_id) DO NOTHING
                    """,
                    booking.court_id,
                )

            # 15-minute hold auto-calculation: hold_expires_at = NOW() + 15 minutes
            row = await conn.fetchrow(
                """
                INSERT INTO resort.booking (
                    booking_id, customer_id, staff_id, room_id, court_id, booking_date,
                    start_time, end_time, check_in_date, check_out_date, exclusive,
                    paddle_count, status, created_at, hold_expires_at
                )
                VALUES (
                    $1, $2, $3, $4, $5, $6,
                    $7, $8, $9, $10, $11,
                    $12, $13, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '15 minutes'
                )
                RETURNING booking_id, customer_id, staff_id, room_id, court_id, booking_date,
                          start_time, end_time, check_in_date, check_out_date, exclusive,
                          paddle_count, status, created_at, hold_expires_at
                """,
                booking.booking_id,
                booking.customer_id,
                booking.staff_id,
                booking.room_id if booking.room_id and booking.room_id.strip() else None,
                booking.court_id if booking.court_id and booking.court_id.strip() else None,
                booking.booking_date,
                booking.start_time,
                booking.end_time,
                booking.check_in_date,
                booking.check_out_date,
                booking.exclusive,
                booking.paddle_count,
                booking.status,
            )
            return dict(row)
        except Exception as err:
            handle_db_exception(err)


@app.put("/bookings/{booking_id}/status", response_model=BookingResponse, tags=["Bookings"])
async def update_booking_status(
    booking_id: str,
    new_status: Literal["Pending", "Confirmed", "Checked-In", "Completed", "Cancelled"],
):
    async with acquire_db_connection() as conn:
        try:
            row = await conn.fetchrow(
                """
                UPDATE resort.booking
                SET status = $1
                WHERE booking_id = $2
                RETURNING booking_id, customer_id, staff_id, room_id, court_id, booking_date,
                          start_time, end_time, check_in_date, check_out_date, exclusive,
                          paddle_count, status, created_at, hold_expires_at
                """,
                new_status,
                booking_id,
            )
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found."
                )
            return dict(row)
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
                # Enforce 24-hour non-cancellation refund business rule
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

                    # Compute scheduled reservation start
                    sched_date = booking["check_in_date"]
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
                    payment.booking_id,
                    payment.order_id,
                    payment.amount,
                    payment.method,
                    payment.payment_type,
                )

                # Auto-confirm booking upon successful full payment capture
                if payment.booking_id and payment.payment_type == "Payment":
                    await conn.execute(
                        "UPDATE resort.booking SET status = 'Confirmed' WHERE booking_id = $1 AND status = 'Pending'",
                        payment.booking_id,
                    )

                return dict(row)
            except HTTPException:
                raise
            except Exception as err:
                handle_db_exception(err)


# =============================================================================
# POS MODULE: PRODUCT CATALOG CRUD
# =============================================================================
@app.get("/pos/items", response_model=list[POSItemResponse], tags=["POS Catalog"])
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


# =============================================================================
# POS MODULE: ORDERS & MULTI-ROW LINE ITEMS
# =============================================================================
@app.post(
    "/pos/orders",
    status_code=status.HTTP_201_CREATED,
    response_model=POSOrderResponse,
    tags=["POS Orders"],
)
async def create_pos_order(order: POSOrderCreate):
    async with acquire_db_connection() as conn:
        # Atomic database transaction: order header and line items succeed or fail together
        async with conn.transaction():
            try:
                # 1. Fetch catalog unit prices and verify existence
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

                # 2. Compute line subtotals and frozen total_amount
                total_amount = Decimal("0.00")
                line_items_data = []
                for item in order.items:
                    unit_price = price_map[item.item_id]
                    subtotal = unit_price * item.quantity
                    total_amount += subtotal
                    line_items_data.append((order.order_id, item.item_id, item.quantity, subtotal))

                # 3. Insert parent POS order
                order_row = await conn.fetchrow(
                    """
                    INSERT INTO pos.pos_order (order_id, customer_id, staff_id, order_date, total_amount)
                    VALUES ($1, $2, $3, CURRENT_TIMESTAMP, $4)
                    RETURNING order_id, customer_id, staff_id, order_date, total_amount
                    """,
                    order.order_id,
                    order.customer_id,
                    order.staff_id,
                    total_amount,
                )

                # 4. Bulk insert line items into bridge table
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
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="POS Order not found."
            )

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
# RELATIONAL JOINS & ANALYTICAL AUDIT ENDPOINTS
# =============================================================================
@app.get("/reports/active-bookings-detail", tags=["Relational Reports"])
async def report_active_bookings():
    """
    Demonstrates multi-table INNER and LEFT JOINs across resort schemas.
    Reconciles Customer identity, Assigned Staff, and Room/Court details.
    """
    query = """
        SELECT 
            b.booking_id,
            b.status AS booking_status,
            b.booking_date,
            c.customer_id,
            c.first_name || ' ' || c.last_name AS customer_full_name,
            c.phone AS customer_phone,
            s.first_name || ' ' || s.last_name AS handler_staff_name,
            r.room_number,
            r.rate_per_day,
            ct.court_name,
            ct.court_type,
            b.paddle_count,
            b.created_at,
            b.hold_expires_at
        FROM resort.booking b
        INNER JOIN resort.customer c ON b.customer_id = c.customer_id
        INNER JOIN resort.staff s ON b.staff_id = s.staff_id
        LEFT JOIN resort.room r ON b.room_id = r.room_id
        LEFT JOIN resort.court ct ON b.court_id = ct.court_id
        ORDER BY b.created_at DESC
    """
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(query)
        return [dict(r) for r in rows]


@app.get("/reports/room-occupancy-audit", tags=["Relational Reports"])
async def report_room_occupancy():
    """
    Demonstrates LEFT JOIN between physical Room inventory and active Bookings.
    Provides housekeeping status and current guest allocation.
    """
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
        LEFT JOIN resort.booking b ON r.room_id = b.room_id AND b.status IN ('Confirmed', 'Checked-In')
        LEFT JOIN resort.customer c ON b.customer_id = c.customer_id
        ORDER BY r.room_number
    """
    async with acquire_db_connection() as conn:
        rows = await conn.fetch(query)
        return [dict(r) for r in rows]


@app.get("/reports/pos-sales-ledger", tags=["Relational Reports"])
async def report_pos_sales():
    """
    Demonstrates cross-schema joins between pos and resort.
    Unwinds pos_order, pos_order_item, pos_item, staff, and customer.
    """
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
    """
    Demonstrates verification of the XOR exclusive arc for all captured payments.
    Joins payments with their parent Booking or parent POS Order.
    """
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
# ADMIN P&L / REVENUE ANALYTICS ENDPOINT
# =============================================================================
@app.get(
    "/reports/revenue-pnl",
    tags=["Admin Financial Reports"],
    dependencies=[Depends(verify_staff_token)],
)
async def get_revenue_pnl_summary(
    start_date: date | None = Query(default=None, description="Filter from date (YYYY-MM-DD)"),
    end_date: date | None = Query(default=None, description="Filter to date (YYYY-MM-DD)"),
):
    """
    Computes real-time Profit & Loss / Revenue analytics directly from the payment ledger.
    Calculates Gross Room/Court Revenue, Gross POS Sales, Refund Deductions, and Net Revenue.
    """
    query = """
        SELECT 
            -- Total Gross Bookings (Room & Sports Courts)
            COALESCE(SUM(CASE 
                WHEN p.booking_id IS NOT NULL AND p.payment_type = 'Payment' THEN p.amount 
                ELSE 0 
            END), 0) AS gross_booking_revenue,

            -- Total Gross POS Sales (Food, Drinks, Retail)
            COALESCE(SUM(CASE 
                WHEN p.order_id IS NOT NULL AND p.payment_type = 'Payment' THEN p.amount 
                ELSE 0 
            END), 0) AS gross_pos_revenue,

            -- Total Processed Refunds
            COALESCE(SUM(CASE 
                WHEN p.payment_type = 'Refund' THEN p.amount 
                ELSE 0 
            END), 0) AS total_refunds,

            -- Total Captured Payments (Gross Inflow)
            COALESCE(SUM(CASE 
                WHEN p.payment_type = 'Payment' THEN p.amount 
                ELSE 0 
            END), 0) AS total_gross_revenue,

            -- Net Revenue (Inflow minus Outflow)
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