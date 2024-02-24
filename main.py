import re
import jwt
import secrets
import string
from typing import Annotated
from fastapi import Form, FastAPI, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from databases import Database
from sqlalchemy import or_
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from datetime import timedelta, datetime
from fastapi.responses import JSONResponse
from jose import JWTError
from jwt.exceptions import DecodeError
from sqlalchemy import UniqueConstraint, func
from sqlalchemy.exc import IntegrityError

DATABASE_URL = "postgresql://postgressqladmin:R%40y0T3%40m%21@rawarayopostgressql.postgres.database.azure.com/user_auth"
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
database = Database(DATABASE_URL)
Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
SECRET_KEY = "z_yhabov1RQAwA-CyDYBsYbUrATaXaXf-i2agxwgwJahwjmi11n1PkerWlikLLxjzKOhdjCPysW-Q_ngqP6IaA"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")
PASSWORD_REGEX = re.compile(r"^(?=.*[A-Z])(?=.*[!@#$%^&*(),.?\":{}|<>]).{7,}$")

CLIENT_ID = "881133682590-b7i4t27vjal4hu4fq668ob4dcnfiub94.apps.googleusercontent.com"
CLIENT_SECRET = "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"
REDIRECT_URI = "http://127.0.0.1:8000/auth/"
AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    email = Column(String)
    gender = Column(String)
    hashed_password = Column(String)
    auth_type = Column(String)
    medical_info = relationship("MedicalInfo", back_populates="user")


class MedicalInfo(Base):
    __tablename__ = "medical_info"
    medical_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    disease_id = Column(Integer, ForeignKey("disease.disease_id"), index=True)
    user = relationship("User", back_populates="medical_info")
    disease = relationship("DiseaseInfo", back_populates="medical_info")
    

class DiseaseInfo(Base):
    __tablename__ = "disease"
    disease_id = Column(Integer, primary_key=True, index=True)
    disease_name = Column(String, unique=True)  # Adding unique constraint
    medical_info = relationship("MedicalInfo", back_populates="disease")

    __table_args__ = (
        UniqueConstraint('disease_name', name='unique_disease_name'),
    )
    
Base.metadata.create_all(bind=engine)

app = FastAPI()
active_sessions = set()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_access_token(username: str, user_id: int, exp: timedelta):
    expires = datetime.utcnow() + exp
    encode = {"un": username, "id": user_id, "exp": expires}

    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


def is_user_logged_in(user_id: int):
    return user_id in active_sessions


def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("un")
        user_id: int = payload.get("id")
        if username is None or user_id is None:
            raise credentials_exception
        return {"sub": username, "id": user_id}
    except DecodeError as e:
        print(f"Error decoding token: {e}")
        raise credentials_exception
    except JWTError as e:
        print(f"JWTError: {e}")
        raise credentials_exception


def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(characters) for _ in range(length))

def register_google_microsoft_user(username: str, first_name: str, last_name: str, email: str, auth_type: str, db: Session):
    user = User(username=username, 
                first_name=first_name, 
                last_name=last_name, 
                email=email, 
                gender="",
                auth_type=auth_type,
                hashed_password=""
                )
    db.add(user)
    db.commit()
    db.refresh(user)
    raise HTTPException(status_code=200, detail=f"{first_name} {last_name} Successfully Created")

@app.get("/google_microsoft_info/")
async def decode_token(access_token: str = Query(..., description="JWT Access Token"),
                       auth_type: str = Query(..., description="Authentication Type"), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM],
                             options={"verify_signature": False})
        username = payload.get("name", "")
        first_name = payload.get("given_name", "")
        last_name = payload.get("family_name", "")
        email = payload.get("email", "")
        register_payload = {"username": username, 
                "first_name": first_name, 
                "last_name": last_name, 
                "email": email,
                "auth_type": auth_type}
        
        register_google_microsoft_user(db=db, **register_payload)
        return {"message": "User registered successfully"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/register_new_user")
def register_user(
    first_name: str = Form(...),
    last_name: str = Form(...),
    email: str = Form(...),
    gender: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    if not PASSWORD_REGEX.match(password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": status.HTTP_400_BAD_REQUEST,
                "error": "Invalid password",
                "message": "Password must be 7 characters long, contain at least one uppercase letter, and at least one symbol",
            },
        )

    hashed_password = pwd_context.hash(password)
    db_user = User(
        username=username,
        first_name=first_name,
        last_name=last_name,
        email=email,
        gender=gender,
        auth_type="UserName",
        hashed_password=hashed_password,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return {f"{first_name} {last_name} Successfully Created"}

@app.post("/add_disease/")
async def add_disease(disease_name: str, db: Session = Depends(get_db)):
    lower_disease_name = disease_name.lower()
    
    existing_disease = db.query(DiseaseInfo).filter(func.lower(DiseaseInfo.disease_name) == lower_disease_name).first()

    if existing_disease:
        return {"message": "Disease already present"}

    db_disease = DiseaseInfo(
        disease_name=lower_disease_name,
    )

    try:
        db.add(db_disease)
        db.commit()
        db.refresh(db_disease)
        return {"message": "Disease added successfully"}
    except IntegrityError:
        # Handle the case where a concurrent request added the same disease name
        return {"message": "Disease already present"}

@app.get("/list_diseases/")
async def list_diseases(db: Session = Depends(get_db)):
    diseases = db.query(DiseaseInfo).all()
    disease_names = [disease.disease_name for disease in diseases]
    return {"disease_name": disease_names}

@app.post("/add_medical_info")
def add_medical_info(
    current_user: dict = Depends(get_current_user),
    disease_name: str = Form(..., description="Disease Name"),
    db: Session = Depends(get_db),
):
    user_id = current_user["id"]

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_code": status.HTTP_404_NOT_FOUND,
                "error": "Not Found",
                "message": f"User with id {user_id} not found",
            },
        )

    lower_disease_name = disease_name.lower()

    existing_disease = db.query(DiseaseInfo).filter(func.lower(DiseaseInfo.disease_name) == lower_disease_name).first()

    if not existing_disease:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": status.HTTP_400_BAD_REQUEST,
                "error": "Bad Request",
                "message": f"Disease with name '{disease_name}' not found",
            },
        )

    medical_info = MedicalInfo(
        user_id=user_id,
        disease_id=existing_disease.disease_id,
    )
    db.add(medical_info)
    db.commit()
    db.refresh(medical_info)

    return {"Medical information added successfully"}

@app.post("/login")
def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = (
        db.query(User)
        .filter(
            or_(User.username == form_data.username, User.email == form_data.username)
        )
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error_code": status.HTTP_401_UNAUTHORIZED,
                "error": "Unauthorized",
                "message": "Invalid username or password",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.auth_type.lower() in ["google", "microsoft"]:
        if not is_user_logged_in(user.id):
            access_token = create_access_token(user.username, user.id, timedelta(minutes=60))
            active_sessions.add(user.id)
            return JSONResponse(
                {
                    "access_token": access_token,
                    "token_type": "bearer",
                    "user_already_logged_in": False,
                }
            )
        else:
            return {"user_already_logged_in": True}
    else:
        
        if not pwd_context.verify(form_data.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error_code": status.HTTP_401_UNAUTHORIZED,
                    "error": "Unauthorized",
                    "message": "Invalid username or password",
                },
                headers={"WWW-Authenticate": "Bearer"},
            )

    if is_user_logged_in(user.id):
        return {"user_already_logged_in": True}

    access_token = create_access_token(user.username, user.id, timedelta(minutes=60))

    active_sessions.add(user.id)
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "bearer",
            "user_already_logged_in": False,
        }
    )

@app.get("/check_login")
def check_login(current_user: dict = Depends(get_current_user)):
    user_id = current_user["id"]
    return {"user_already_logged_in": is_user_logged_in(user_id)}


@app.post("/logout")
def logout(current_user: dict = Depends(get_current_user)):
    user_id = current_user["id"]
    if is_user_logged_in(user_id):
        active_sessions.remove(user_id)
    return {"message": "Logout successful"}


@app.put("/update-password")
def update_password(
    current_password: str,
    new_password: str,
    confirm_password: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not PASSWORD_REGEX.match(new_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": status.HTTP_400_BAD_REQUEST,
                "error": "Bad Request",
                "message": "New password must be 7 characters long, contain at least one uppercase letter, and at least one symbol",
            },
        )

    user_id = current_user["id"]
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_code": status.HTTP_404_NOT_FOUND,
                "error": "Not Found",
                "message": f"User with id {user_id} not found",
            },
        )

    if not pwd_context.verify(current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error_code": status.HTTP_401_UNAUTHORIZED,
                "error": "Unauthorized",
                "message": "Incorrect current password",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    if new_password != confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": status.HTTP_400_BAD_REQUEST,
                "error": "Bad Request",
                "message": "New password and confirm password do not match",
            },
        )

    hashed_password = pwd_context.hash(new_password)
    user.hashed_password = hashed_password
    db.commit()

    return {"message": "Password updated successfully"}


@app.delete("/delete-account")
def delete_account(
    current_user: dict = Depends(get_current_user),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user_id = current_user["id"]
    user = db.query(User).filter(User.id == user_id).first()

    if not user or not pwd_context.verify(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error_code": status.HTTP_401_UNAUTHORIZED,
                "error": "Unauthorized",
                "message": "Invalid username or password",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    db.delete(user)
    db.commit()

    return {"message": "Account deleted successfully"}
