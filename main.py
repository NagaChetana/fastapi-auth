from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from passlib.hash import pbkdf2_sha256
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from jose import jwt, JWTError
from datetime import datetime, timedelta
import secrets

app = FastAPI()

# ================= JWT CONFIG =================
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# ================= DATABASE SETUP =================
DATABASE_URL = "sqlite:///./bar_register.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String, unique=True, index=True)
    phone = Column(String)
    password = Column(String)
    salt = Column(String)   # ✅ SALT STORED HERE


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ================= REQUEST MODELS =================
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    phone: str
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str

# ================= PASSWORD WITH SALTING =================

def hash_password_with_salt(password: str, salt: str) -> str:
    combined = password + salt
    return pbkdf2_sha256.hash(combined)


def verify_password_with_salt(plain_password: str, salt: str, hashed_password: str) -> bool:
    combined = plain_password + salt
    return pbkdf2_sha256.verify(combined, hashed_password)

# ================= TOKEN FUNCTIONS =================

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

# ================= ROUTES =================

@app.get("/")
def home():
    return {"message": "FastAPI running ✅"}


# ---------- REGISTER ----------
@app.post("/register")
def register_user(user: RegisterRequest, db: Session = Depends(get_db)):

    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=401, detail="Email already registered")

    # ✅ Generate unique salt for this user
    salt = secrets.token_hex(16)

    # ✅ Hash password with salt
    hashed_password = hash_password_with_salt(user.password, salt)

    new_user = User(
        name=user.name,
        email=user.email,
        phone=user.phone,
        password=hashed_password,
        salt=salt
    )

    db.add(new_user)
    db.commit()

    return {"message": "Customer saved the password"}


# ---------- LOGIN ----------
@app.post("/login")
def login_user(user: LoginRequest, db: Session = Depends(get_db)):

    db_user = db.query(User).filter(User.email == user.email).first()

    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # ✅ Compare entered password with stored hash using stored salt
    if not verify_password_with_salt(user.password, db_user.salt, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token({"sub": db_user.email})
    refresh_token = create_refresh_token({"sub": db_user.email})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


# ---------- REFRESH -----------
@app.post("/refresh")
def refresh_token(data: RefreshRequest):

    payload = verify_token(data.refresh_token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    email = payload.get("sub")

    new_access_token = create_access_token({"sub": email})
    new_refresh_token = create_refresh_token({"sub": email})

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token
    }
