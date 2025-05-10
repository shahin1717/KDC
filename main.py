import uvicorn
from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
import pymysql
import bcrypt
import logging
import secrets
from database import  SessionLocal, User, Message, get_db, get_user, create_user, verify_password
from crypto import generate_keypair, rsa_encrypt, rsa_decrypt, caesar_encrypt, caesar_decrypt

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

pymysql.install_as_MySQLdb()
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(
    SessionMiddleware,
    secret_key=secrets.token_hex(32),
    max_age=3600,
    same_site="lax",
    https_only=False
)

# Background task to delete old messages
def delete_old_messages():
    try:
        db = SessionLocal()
        expiration_time = datetime.utcnow() - timedelta(minutes=5)
        old_messages = db.query(Message).filter(Message.created_at < expiration_time).all()
        for msg in old_messages:
            db.delete(msg)
        db.commit()
        logger.info(f"Deleted {len(old_messages)} messages older than 5 minutes")
    except Exception as e:
        logger.error(f"Error in delete_old_messages: {str(e)}")
    finally:
        db.close()

# Start scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(delete_old_messages, 'interval', minutes=1)  # Check every minute
scheduler.start()

# Routes
@app.on_event("shutdown")
def shutdown_event():
    scheduler.shutdown()

@app.get("/", response_class=HTMLResponse)
def read_home(request: Request):
    user = request.session.get("user")
    logger.debug(f"Home endpoint session: {request.session}, user: {user}")
    return templates.TemplateResponse("index.html", {
        "request": request,
        "user": user
    })

@app.get("/send", response_class=HTMLResponse)
def read_send(request: Request):
    user = request.session.get("user")
    logger.debug(f"Send endpoint session: {request.session}")
    if not user:
        logger.info("No user in session, redirecting to login")
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("send.html", {
        "request": request,
        "user": user
    })

@app.get("/login", response_class=HTMLResponse)
def read_login(request: Request):
    user = request.session.get("user")
    if user:
        return RedirectResponse(url="/profile", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request})
@app.get("/register", response_class=HTMLResponse)
def read_register(request: Request, db: Session = Depends(get_db)):
    user = request.session.get("user")
    if user:
        db_user = get_user(db, user)
        if db_user:  # Only redirect if the user exists in the database
            logger.debug(f"User {user} already logged in, redirecting to profile")
            return RedirectResponse(url="/profile", status_code=303)
        else:
            logger.warning(f"Invalid user in session: {user}, clearing session")
            request.session.clear()  # Clear invalid session
    return templates.TemplateResponse("register.html", {"request": request})
# main.py (Updated snippet for /profile)
@app.get("/profile", response_class=HTMLResponse)
def read_profile(request: Request, db: Session = Depends(get_db)):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    db_user = get_user(db, user)
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "user": user,
        "user_data": db_user
    })
@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)

@app.get("/messages", response_class=HTMLResponse)
def read_messages(request: Request, db: Session = Depends(get_db)):
    try:
        user = request.session.get("user")
        logger.debug(f"Messages endpoint session: {request.session}, user: {user}")
        if not user:
            logger.info("No user in session, redirecting to login")
            return RedirectResponse(url="/login", status_code=303)

        db_user = get_user(db, user)
        if not db_user:
            logger.info(f"User {user} not found in database")
            return templates.TemplateResponse("messages.html", {
                "request": request,
                "user": user,
                "error": "User not found."
            })

        private_key = (db_user.private_key_d, db_user.private_key_n)
        messages = db.query(Message).filter(Message.recipient_username == user).all()
        decrypted_messages = []
        for msg in messages:
            try:
                caesar_key = rsa_decrypt(msg.encrypted_key, private_key)
                decrypted_message = caesar_decrypt(msg.encrypted_message, caesar_key)
                decrypted_messages.append({
                    "sender": msg.sender_username,
                    "caesar_key": caesar_key,
                    "message": decrypted_message
                })
            except Exception as e:
                logger.error(f"Decryption failed for message {msg.id}: {str(e)}")
                decrypted_messages.append({
                    "sender": msg.sender_username,
                    "caesar_key": f"Key decryption failed: {str(e)}",
                    "message": f"Message decryption failed: {str(e)}"
                })

        return templates.TemplateResponse("messages.html", {
            "request": request,
            "user": user,
            "messages": decrypted_messages
        })

    except Exception as e:
        logger.error(f"Internal Server Error in /messages: {str(e)}", exc_info=True)
        return templates.TemplateResponse("messages.html", {
            "request": request,
            "user": user,
            "error": "An unexpected error occurred. Please try again."
        })

@app.post("/send", response_class=HTMLResponse)
async def send_message(
    username: str = Form(...),
    message: str = Form(...),
    key: str = Form(...),
    request: Request = None,
    db: Session = Depends(get_db)
):
    try:
        user = request.session.get("user")
        logger.debug(f"User in session: {user}, Session: {request.session}")
        if not user:
            logger.info("No user in session, redirecting to login")
            return RedirectResponse(url="/login", status_code=303)

        logger.debug(f"Form data: username={username}, message={message}, key={key}")

        if not message:
            return templates.TemplateResponse("send.html", {
                "request": request,
                "user": user,
                "error": "Message is required."
            })

        recipient = get_user(db, username)
        logger.debug(f"Recipient query result: {recipient}")
        if not recipient:
            logger.info(f"Recipient {username} not found")
            return templates.TemplateResponse("send.html", {
                "request": request,
                "user": user,
                "error": "Recipient username does not exist."
            })

        try:
            key_int = int(key)
            if key_int <= 0:
                logger.info(f"Invalid key: {key} (non-positive)")
                return templates.TemplateResponse("send.html", {
                    "request": request,
                    "user": user,
                    "error": "Caesar key must be a positive integer."
                })
        except ValueError:
            logger.info(f"Invalid key: {key} (non-integer)")
            return templates.TemplateResponse("send.html", {
                "request": request,
                "user": user,
                "error": "Caesar key must be a valid integer."
            })

        public_key = (recipient.public_key_e, recipient.public_key_n)
        if not public_key[0] or not public_key[1]:
            logger.info(f"Recipient {username} has no public key")
            return templates.TemplateResponse("send.html", {
                "request": request,
                "user": user,
                "error": "Recipient has no public key."
            })

        try:
            encrypted_key = rsa_encrypt(key_int, public_key)
            logger.info(f"Encrypted Caesar key {key_int} for {username}: {encrypted_key}")
        except Exception as e:
            logger.error(f"RSA encryption failed: {str(e)}")
            return templates.TemplateResponse("send.html", {
                "request": request,
                "user": user,
                "error": f"RSA encryption failed: {str(e)}"
            })

        try:
            encrypted_message = caesar_encrypt(message, key_int)
            logger.info(f"Encrypted message for {username}: {encrypted_message}")
        except Exception as e:
            logger.error(f"Caesar encryption failed: {str(e)}")
            return templates.TemplateResponse("send.html", {
                "request": request,
                "user": user,
                "error": f"Caesar encryption failed: {str(e)}"
            })

        message_entry = Message(
            sender_username=user,
            recipient_username=username,
            encrypted_key=encrypted_key,
            encrypted_message=encrypted_message
        )
        db.add(message_entry)
        db.commit()
        logger.info(f"Stored encrypted message for {username} from {user}")

        return templates.TemplateResponse("send.html", {
            "request": request,
            "user": user,
            "success": f"Message and Caesar key sent to {username} successfully!"
        })

    except Exception as e:
        logger.error(f"Internal Server Error in /send: {str(e)}", exc_info=True)
        return templates.TemplateResponse("send.html", {
            "request": request,
            "user": user,
            "error": "An unexpected error occurred. Please try again."
        })

@app.post("/login")
async def login_user(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
    request: Request = None
):
    logger.debug(f"Login attempt for username: {username}")
    db_user = get_user(db, username)
    if not db_user or not verify_password(password, db_user.password):
        logger.info(f"Login failed for {username}")
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid username or password."
        })
    logger.debug(f"Setting session for user: {db_user.username}")
    request.session["user"] = db_user.username
    return RedirectResponse(url="/profile", status_code=303)

@app.post("/register")
async def register_user(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
    request: Request = None
):
    try:
        if get_user(db, username):
            logger.info(f"Registration failed: Username {username} exists")
            return templates.TemplateResponse("register.html", {
                "request": request,
                "error": "Username already exists."
            })
        public_key, private_key = generate_keypair()
        user = User(username=username, password=password)
        create_user(db, user, public_key, private_key)
        logger.debug(f"Setting session for user: {username}")
        request.session["user"] = username
        return RedirectResponse(url="/profile", status_code=303)
    except Exception as e:
        logger.error(f"Error in register_user: {str(e)}", exc_info=True)
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Registration failed. Please try again."
        })
    
if __name__ == "__main__":
    uvicorn.run("main:app", reload=True)
       