# database.py (Updated)
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import bcrypt
import pymysql
import logging
from datetime import datetime
from dotenv import load_dotenv
import os


pymysql.install_as_MySQLdb()

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
load_dotenv()
SQLALCHEMY_DATABASE_URL = os.getenv("SQLALCHEMY_DATABASE_URL")
try:
    engine = create_engine(SQLALCHEMY_DATABASE_URL)
    logger.info("Database connection established")
except Exception as e:
    logger.error(f"Database connection failed: {str(e)}")
    raise

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class User(Base):
    __tablename__ = "users_db"
    userID = Column(Integer, primary_key=True, index=True)
    username = Column(String(30), unique=True, index=True)
    password = Column(String(255))
    public_key_e = Column(Integer)  # RSA public key e
    public_key_n = Column(Integer)  # RSA public key n
    private_key_d = Column(Integer)  # RSA private key d
    private_key_n = Column(Integer)  # RSA private key n

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_username = Column(String(30), nullable=False)
    recipient_username = Column(String(30), nullable=False)
    encrypted_key = Column(Integer, nullable=False)  # RSA-encrypted Caesar key
    encrypted_message = Column(String(255), nullable=False)  # Caesar-encrypted message
    created_at = Column(DateTime, default=datetime.utcnow)  # Timestamp for deletion

Base.metadata.create_all(bind=engine)

# Helper Functions
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user(db: Session, username: str):
    try:
        user = db.query(User).filter(User.username == username).first()
        logger.debug(f"get_user: username={username}, result={user}")
        return user
    except Exception as e:
        logger.error(f"Error in get_user: {str(e)}")
        raise

def create_user(db: Session, user: User, public_key: tuple = None, private_key: tuple = None):
    try:
        hashed_password = hash_password(user.password)
        db_user = User(
            username=user.username,
            password=hashed_password,
            public_key_e=public_key[0] if public_key else None,
            public_key_n=public_key[1] if public_key else None,
            private_key_d=private_key[0] if private_key else None,
            private_key_n=private_key[1] if private_key else None
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        logger.info(f"User created: {user.username}")
        return "User created successfully"
    except Exception as e:
        logger.error(f"Error in create_user: {str(e)}")
        db.rollback()
        raise

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    logger.debug(f"Verifying password: plain={plain_password}, hashed={hashed_password}")
    try:
        result = bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
        logger.debug(f"Password verification result: {result}")
        return result
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False