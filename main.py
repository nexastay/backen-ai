import os
import re
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, Optional, Sequence, List, Any
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status, Request, UploadFile, File, WebSocket, WebSocketDisconnect, Form, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from bson import ObjectId
from pymongo import ASCENDING, MongoClient
from gridfs import GridFSBucket
from pymongo.collection import Collection
import httpx
from bs4 import BeautifulSoup
from dateutil import tz
import base64
import uuid
import asyncio
import json
import io
import wave
from starlette.websockets import WebSocketState
from messaging import init_messaging

try:
    import _bcrypt  # type: ignore
except ImportError:  # pragma: no cover
    _bcrypt = None

if _bcrypt is not None:
    if not hasattr(_bcrypt, "__about__"):
        class _BcryptAbout:  # pragma: no cover - compatibility shim
            __version__ = getattr(_bcrypt, "__version__", "0")

        _bcrypt.__about__ = _BcryptAbout()

    _orig_hashpw = getattr(_bcrypt, "hashpw", None)

    def _hashpw_trunc(secret: bytes, config: bytes):  # pragma: no cover - runtime shim
        if _orig_hashpw is None:
            raise ValueError("bcrypt backend unavailable")
        try:
            return _orig_hashpw(secret, config)
        except ValueError as exc:
            if "longer than 72 bytes" in str(exc):
                return _orig_hashpw(secret[:72], config)
            raise

    if _orig_hashpw:
        _bcrypt.hashpw = _hashpw_trunc  # type: ignore[attr-defined]
try:
    from vosk import Model, KaldiRecognizer
except Exception:  # noqa: BLE001
    Model = None
    KaldiRecognizer = None
try:
    from deepface import DeepFace
    import cv2
    import numpy as np
except Exception:  # noqa: BLE001
    DeepFace = None
    cv2 = None
    np = None

VOSK_MODEL_CACHE = None
FACE_MODEL_CACHE = None


load_dotenv()


def get_env(name: str, default: Optional[str] = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


MONGODB_URI = get_env("MONGODB_URI")
DB_NAME = os.getenv("DB_NAME", "neo_auth")
JWT_SECRET = get_env("JWT_SECRET", "change-me")
JWT_ALG = "HS256"
JWT_EXP_MIN = int(os.getenv("JWT_EXP_MIN", "30"))
JWT_REFRESH_EXP_DAYS = int(os.getenv("JWT_REFRESH_EXP_DAYS", "7"))
EMAIL_SENDER = get_env("MAIL_CONFIRMATION")
EMAIL_PASSWORD = get_env("MOT_DE_PASSE_CONFIRMATION")
EMAIL_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("SMTP_PORT", "587"))
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:3000")
PROJECT_NAME = os.getenv("APP_NAME", "Neo Auth")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
GROQ_MODEL_VISION = os.getenv("GROQ_MODEL_VISION", "llama-3.2-11b-vision-preview")
WEB_SEARCH_ENABLED = os.getenv("WEB_SEARCH_ENABLED", "false").lower() == "true"
SEARCH_MAX_RESULTS = int(os.getenv("SEARCH_MAX_RESULTS", "5"))
SERPAPI_KEY = os.getenv("SERPAPI_KEY")
FACE_RECO_THRESHOLD = float(os.getenv("FACE_RECO_THRESHOLD", "0.75"))
VOSK_MODEL_PATH = os.getenv("VOSK_MODEL_PATH")  # chemin vers un modèle Vosk (optionnel)
ALLOWED_ORIGINS: Sequence[str] = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "").split(",")
    if origin.strip()
]
RATE_LIMIT_WINDOW_SEC = int(os.getenv("RATE_LIMIT_WINDOW_SEC", "60"))
RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv("RATE_LIMIT_MAX_ATTEMPTS", "10"))
FAILED_ATTEMPTS: Dict[str, Dict[str, int]] = {}

CRAWL_WHITELIST = [
    "wikipedia.org",
    "arxiv.org",
    "huggingface.co",
    "pypi.org",
    "docs.python.org",
    "developer.mozilla.org",
    "openai.com",
]


client = MongoClient(MONGODB_URI)
db = client.get_database(DB_NAME)
users: Collection = db["users"]
users.create_index([("email", ASCENDING)], unique=True)
users.create_index([("pseudo", ASCENDING)], unique=True)
conversations: Collection = db["conversations"]
messages_col: Collection = db["messages"]
images_col: Collection = db["images"]
faces_col: Collection = db["faces"]
conversations.create_index([("user_id", ASCENDING)], unique=False)
messages_col.create_index([("conversation_id", ASCENDING), ("created_at", ASCENDING)])
images_col.create_index([("user_id", ASCENDING), ("created_at", ASCENDING)])
faces_col.create_index([("user_id", ASCENDING)], unique=False)
file_storage = GridFSBucket(db, bucket_name="neo_files")

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
serializer = URLSafeTimedSerializer(JWT_SECRET)
app = FastAPI(title=f"{PROJECT_NAME} Auth API")

if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(ALLOWED_ORIGINS),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

PASSWORD_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$"
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


POLLINATIONS_BASE_URL = os.getenv("POLLINATIONS_BASE_URL", "https://image.pollinations.ai/prompt")
POLLINATIONS_SEED = os.getenv("POLLINATIONS_SEED", "neo-labs")


class SignupRequest(BaseModel):
    pseudo: str = Field(..., min_length=3, max_length=32)
    email: EmailStr
    display_name: str = Field(..., min_length=1, max_length=64)
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class VerifyEmailRequest(BaseModel):
    token: str


class RefreshRequest(BaseModel):
    refresh_token: str


class ProfileResponse(BaseModel):
    id: str
    pseudo: str
    email: EmailStr
    display_name: str
    created_at: datetime
    updated_at: datetime


class ChatMessage(BaseModel):
    role: str
    content: str
    images: Optional[List[str]] = None


class ChatRequest(BaseModel):
    conversation_id: Optional[str] = None
    message: str
    mode: str = "chat"  # chat|code|reasoning
    bot_name: Optional[str] = "Neo"
    user_name: Optional[str] = "Utilisateur"
    images: Optional[List[str]] = None
    search: bool = False
    max_tokens: Optional[int] = None
    temperature: float = 0.5


class ChatResponse(BaseModel):
    conversation_id: str
    reply: str
    sources: Optional[List[str]] = None


class ImageUploadResponse(BaseModel):
    image_id: str
    analysis: Optional[str] = None


class ImageGenerationRequest(BaseModel):
    prompt: str
    seed: Optional[str] = None
    width: int = 768
    height: int = 768


class ImageGenerationResponse(BaseModel):
    prompt: str
    seed: str
    image_base64: str


class TranscribeResponse(BaseModel):
    text: str
    note: Optional[str] = None


class SearchRequest(BaseModel):
    query: str
    max_results: int = 3


class SearchResponse(BaseModel):
    results: List[Dict[str, str]]


class FaceMatchResponse(BaseModel):
    match: bool
    note: Optional[str] = None


class FaceEnrollResponse(BaseModel):
    face_id: str
    label: str


class MemoryMessage(BaseModel):
    role: str
    content: str
    images: Optional[List[str]] = None
    created_at: datetime


class MemoryResponse(BaseModel):
    conversation_id: str
    summary: Optional[str]
    messages: List[MemoryMessage]


class ConversationItem(BaseModel):
    id: str
    bot_name: str
    summary: Optional[str]
    updated_at: datetime
    last_message: Optional[str] = None


CHAT_HISTORY_LIMIT = int(os.getenv("CHAT_HISTORY_LIMIT", "30"))
CHAT_SUMMARY_EVERY = int(os.getenv("CHAT_SUMMARY_EVERY", "30"))
FACE_MODEL_NAME = os.getenv("FACE_MODEL_NAME", "Facenet")
FACE_DISTANCE_THRESHOLD = float(os.getenv("FACE_DISTANCE_THRESHOLD", "0.45"))


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_jwt(sub: str, expires_delta: timedelta, token_type: str = "access") -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": sub, "iat": now, "exp": now + expires_delta, "type": token_type}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def decode_jwt(token: str, expected_type: Optional[str] = None) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        if expected_type and payload.get("type") != expected_type:
            raise HTTPException(status_code=401, detail="Type de token invalide")
        return payload.get("sub")
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Token invalide") from exc


def create_email_token(email: str) -> str:
    return serializer.dumps(email, salt="email-confirm")


def verify_email_token(token: str, max_age: int = 60 * 60 * 24) -> str:
    try:
        return serializer.loads(token, salt="email-confirm", max_age=max_age)
    except SignatureExpired as exc:
        raise HTTPException(status_code=400, detail="Token expiré") from exc
    except BadSignature as exc:
        raise HTTPException(status_code=400, detail="Token invalide") from exc


def send_confirmation_email(to_email: str, token: str) -> None:
    confirm_link = f"{APP_BASE_URL}/confirm-email?token={token}"
    msg = EmailMessage()
    msg["Subject"] = f"{PROJECT_NAME} - Confirmation d'email"
    msg["From"] = EMAIL_SENDER
    msg["To"] = to_email
    msg.set_content(
        f"Bonjour,\n\nMerci de créer un compte sur {PROJECT_NAME}.\n"
        f"Cliquez pour confirmer votre email : {confirm_link}\n\n"
        "Si vous n'êtes pas à l'origine de cette demande, ignorez ce message."
    )

    with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.send_message(msg)


def is_rate_limited(key: str) -> bool:
    now_ts = int(datetime.utcnow().timestamp())
    window_start = now_ts - RATE_LIMIT_WINDOW_SEC
    bucket = FAILED_ATTEMPTS.get(key, {"ts": now_ts, "count": 0})
    # reset window if older
    if bucket["ts"] < window_start:
        bucket = {"ts": now_ts, "count": 0}
    if bucket["count"] >= RATE_LIMIT_MAX_ATTEMPTS:
        FAILED_ATTEMPTS[key] = bucket
        return True
    FAILED_ATTEMPTS[key] = bucket
    return False


def increment_failure(key: str) -> None:
    now_ts = int(datetime.utcnow().timestamp())
    bucket = FAILED_ATTEMPTS.get(key, {"ts": now_ts, "count": 0})
    if now_ts - bucket["ts"] > RATE_LIMIT_WINDOW_SEC:
        bucket = {"ts": now_ts, "count": 0}
    bucket["count"] += 1
    bucket["ts"] = now_ts
    FAILED_ATTEMPTS[key] = bucket


BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"
FRONTEND_ASSETS = FRONTEND_DIR / "assets"
FAVICON_PATH = FRONTEND_DIR / "favicon.ico"
DEFAULT_FAVICON = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMB/axctyEAAAAASUVORK5CYII="
)

if FRONTEND_DIR.exists():
    app.mount("/frontend", StaticFiles(directory=FRONTEND_DIR), name="frontend")
if FRONTEND_ASSETS.exists():
    app.mount("/frontend/assets", StaticFiles(directory=FRONTEND_ASSETS), name="frontend-assets")


@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return HTMLResponse(index_path.read_text(encoding="utf-8"))
    return HTMLResponse(
        "<h1>Néo Auth API</h1><p>L'interface Néo AI n'est pas encore construite.</p>",
        status_code=200,
    )


@app.get("/frontend-config")
def frontend_config():
    return {
        "appName": PROJECT_NAME,
        "webSearchEnabled": WEB_SEARCH_ENABLED,
        "historyLimit": CHAT_HISTORY_LIMIT,
        "summaryInterval": CHAT_SUMMARY_EVERY,
    }


@app.get("/favicon.ico")
def favicon():
    if FAVICON_PATH.exists():
        return FileResponse(FAVICON_PATH)
    return Response(content=DEFAULT_FAVICON, media_type="image/png")


@app.get("/health")
def health():
    return {"status": "ok", "service": PROJECT_NAME}


@app.post("/auth/register")
def register(payload: SignupRequest):
    if len(payload.password.encode("utf-8")) > 72:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mot de passe trop long (72 octets max).",
        )
    if not PASSWORD_REGEX.match(payload.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mot de passe invalide : 8 caractères min, avec minuscule, majuscule, chiffre, caractère spécial",
        )

    key = f"signup:{payload.email.lower()}"
    if is_rate_limited(key):
        raise HTTPException(status_code=429, detail="Trop de tentatives, réessayez plus tard")

    existing = users.find_one(
        {"$or": [{"email": payload.email.lower()}, {"pseudo": payload.pseudo}]}
    )
    if existing:
        increment_failure(key)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pseudo ou email déjà utilisé",
        )

    now = datetime.utcnow()
    user_doc = {
        "pseudo": payload.pseudo,
        "email": payload.email.lower(),
        "display_name": payload.display_name,
        "password_hash": hash_password(payload.password),
        "email_verified": True,  # confirmation différée pour l'instant
        "created_at": now,
        "updated_at": now,
    }
    users.insert_one(user_doc)

    return {"message": "Compte créé"}


@app.post("/auth/refresh", response_model=TokenResponse)
def refresh_tokens(payload: RefreshRequest):
    user_id = decode_jwt(payload.refresh_token, expected_type="refresh")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token invalide")

    try:
        obj_id = ObjectId(user_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=401, detail="Token invalide") from exc

    user = users.find_one({"_id": obj_id})
    if not user:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")
    if not user.get("email_verified"):
        raise HTTPException(status_code=403, detail="Email non confirmé")

    access_token = create_jwt(sub=user_id, expires_delta=timedelta(minutes=JWT_EXP_MIN))
    refresh_token = create_jwt(
        sub=user_id, expires_delta=timedelta(days=JWT_REFRESH_EXP_DAYS), token_type="refresh"
    )
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


def authenticate_user(email: str, password: str):
    user = users.find_one({"email": email.lower()})
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


def get_current_user(token: str = Depends(oauth2_scheme)):
    user_id = decode_jwt(token, expected_type="access")
    try:
        obj_id = ObjectId(user_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=401, detail="Token invalide") from exc
    user = users.find_one({"_id": obj_id})
    if not user:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")
    return user


async def _ws_get_user(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4401)
        return None
    try:
        user_id = decode_jwt(token, expected_type="access")
        obj_id = ObjectId(user_id)
        user = users.find_one({"_id": obj_id})
        if not user:
            await websocket.close(code=4401)
            return None
        return user
    except Exception:
        await websocket.close(code=4401)
        return None


@app.post("/auth/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends(), request: Request = None):
    key = f"login:{request.client.host if request and request.client else 'unknown'}"
    if is_rate_limited(key):
        raise HTTPException(status_code=429, detail="Trop de tentatives, réessayez plus tard")

    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        increment_failure(key)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Identifiants invalides"
        )
    user_id = str(user["_id"])
    access_token = create_jwt(
        sub=user_id, expires_delta=timedelta(minutes=JWT_EXP_MIN), token_type="access"
    )
    refresh_token = create_jwt(
        sub=user_id, expires_delta=timedelta(days=JWT_REFRESH_EXP_DAYS), token_type="refresh"
    )
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@app.get("/auth/me", response_model=ProfileResponse)
def me(current_user=Depends(get_current_user)):
    return ProfileResponse(
        id=str(current_user["_id"]),
        pseudo=current_user["pseudo"],
        email=current_user["email"],
        display_name=current_user["display_name"],
        created_at=current_user["created_at"],
        updated_at=current_user["updated_at"],
    )


class UserDirectoryEntry(BaseModel):
    id: str
    pseudo: str
    display_name: str


@app.get("/users/directory", response_model=List[UserDirectoryEntry])
def users_directory(current_user=Depends(get_current_user)):
    cursor = users.find(
        {"_id": {"$ne": current_user["_id"]}},
        {"pseudo": 1, "display_name": 1},
    ).sort("display_name", ASCENDING)
    return [
        UserDirectoryEntry(
            id=str(doc["_id"]),
            pseudo=doc.get("pseudo") or "",
            display_name=doc.get("display_name") or doc.get("pseudo") or "Utilisateur",
        )
        for doc in cursor
    ]


# -------- IA helpers --------

def _save_message(conversation_id: ObjectId, role: str, content: str, images: Optional[List[str]] = None):
    doc = {
        "conversation_id": conversation_id,
        "role": role,
        "content": content,
        "images": images or [],
        "created_at": datetime.utcnow(),
    }
    messages_col.insert_one(doc)
    conversations.update_one(
        {"_id": conversation_id},
        {"$set": {"updated_at": datetime.utcnow()}},
    )


def _get_or_create_conversation(user_id: ObjectId, bot_name: str) -> ObjectId:
    conv = conversations.find_one({"user_id": user_id})
    if conv:
        return conv["_id"]
    conv_id = conversations.insert_one(
        {"user_id": user_id, "bot_name": bot_name, "created_at": datetime.utcnow(), "updated_at": datetime.utcnow()}
    ).inserted_id
    return conv_id


def _count_messages(conv_id: ObjectId) -> int:
    return messages_col.count_documents({"conversation_id": conv_id})


def _last_message_preview(conv_id: ObjectId) -> Optional[str]:
    doc = messages_col.find_one({"conversation_id": conv_id}, sort=[("created_at", -1)])
    if not doc:
        return None
    content = doc.get("content", "")
    if len(content) > 160:
        return content[:160].rstrip() + "…"
    return content


def _optional_user_from_request(request: Request):
    auth = request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    try:
        user_id = decode_jwt(token, expected_type="access")
        obj_id = ObjectId(user_id)
    except Exception:
        return None
    return users.find_one({"_id": obj_id})


async def _maybe_summarize(conv_id: ObjectId):
    total = _count_messages(conv_id)
    if total == 0 or total % CHAT_SUMMARY_EVERY != 0:
        return
    history_cursor = messages_col.find({"conversation_id": conv_id}).sort("created_at", 1).limit(CHAT_HISTORY_LIMIT)
    prompt = "\n".join(
        f"{doc.get('role','user')}: {doc.get('content','')}" for doc in history_cursor
    )
    summary_prompt = (
        "Résume brièvement la conversation (français), en listes concises (bullets) et points clés. "
        "Ne dépasse pas 120 mots."
    )
    try:
        summary = await _groq_chat(f"{summary_prompt}\n\n{prompt}")
    except Exception:
        summary = None
    if summary:
        conversations.update_one(
            {"_id": conv_id},
            {"$set": {"summary": summary, "summary_updated_at": datetime.utcnow(), "updated_at": datetime.utcnow()}},
        )


async def _crawl(url: str, max_bytes: int = 200_000) -> str:
    parsed = urlparse(url)
    if not parsed.netloc or not any(parsed.netloc.endswith(d) for d in CRAWL_WHITELIST):
        raise HTTPException(status_code=400, detail="Domaine non autorisé")
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        content = resp.content[:max_bytes]
        soup = BeautifulSoup(content, "html.parser")
        text = soup.get_text(separator="\n")
        return "\n".join(line.strip() for line in text.splitlines() if line.strip())[:5000]


async def _search(query: str, max_results: int) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    if WEB_SEARCH_ENABLED and SERPAPI_KEY:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                "https://serpapi.com/search",
                params={"q": query, "engine": "google", "api_key": SERPAPI_KEY, "num": max_results},
            )
            r.raise_for_status()
            data = r.json()
            for item in data.get("organic_results", [])[:max_results]:
                results.append({"title": item.get("title", ""), "link": item.get("link", "")})
        if results:
            return results
    if WEB_SEARCH_ENABLED and not results:
        # Fallback DuckDuckGo HTML (gratuit, sans clé)
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                "https://duckduckgo.com/html/",
                params={"q": query},
                headers={"User-Agent": "Mozilla/5.0 (compatible; NeoBot/1.0)"},
            )
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.select("a.result__a")[:max_results]:
                title = a.get_text(" ", strip=True)
                href = a.get("href")
                if href and title:
                    results.append({"title": title, "link": href})
    return results


async def _groq_chat(
    prompt: str,
    vision_images: Optional[List[str]] = None,
    temperature: float = 0.5,
    max_tokens: Optional[int] = None,
    _vision_retry: bool = False,
    allow_vision_retry: bool = True,
) -> str:
    # Placeholder simple echo if GROQ_API_KEY missing
    if not GROQ_API_KEY:
        return f"(stub) {prompt}"
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    if vision_images:
        content: List[Any] = [{"type": "text", "text": prompt}]
        for img_b64 in vision_images:
            content.append({"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{img_b64}"}})
        messages = [{"role": "user", "content": content}]
        model = GROQ_MODEL_VISION
    else:
        messages = [{"role": "user", "content": prompt}]
        model = GROQ_MODEL
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }
    if max_tokens:
        payload["max_tokens"] = max_tokens
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=payload)
            r.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if vision_images and allow_vision_retry and not _vision_retry:
                # Retry without vision payload if the model rejects multimodal content
                return await _groq_chat(
                    prompt,
                    None,
                    temperature,
                    max_tokens,
                    _vision_retry=True,
                    allow_vision_retry=allow_vision_retry,
                )
            body_preview = exc.response.text[:400]
            raise HTTPException(
                status_code=502,
                detail=f"Groq API error ({exc.response.status_code}): {body_preview or 'voir logs'}",
            ) from exc
        data = r.json()
        return data["choices"][0]["message"]["content"]


def _store_image(user_id: ObjectId, file: UploadFile, content: bytes) -> str:
    image_id = str(uuid.uuid4())
    images_col.insert_one(
        {
            "_id": image_id,
            "user_id": user_id,
            "filename": file.filename,
            "content_type": file.content_type,
            "data": base64.b64encode(content).decode("utf-8"),
            "created_at": datetime.utcnow(),
        }
    )
    return image_id


async def _groq_vision_analyze(content_b64: str, prompt: str = "Décris l'image") -> str:
    """Réutilise le même flux que le chat vision (payload validé)."""
    return await _groq_chat(prompt, [content_b64], temperature=0.2, allow_vision_retry=False)


VISION_MAX_BYTES = 4 * 1024 * 1024


@app.post("/ai/upload-image", response_model=ImageUploadResponse)
async def upload_image(file: UploadFile = File(...), current_user=Depends(get_current_user)):
    content = await file.read()
    if len(content) > VISION_MAX_BYTES:
        raise HTTPException(status_code=400, detail="Image trop volumineuse (max 4MB)")
    image_id = _store_image(current_user["_id"], file, content)
    b64 = base64.b64encode(content).decode("utf-8")
    try:
        analysis = await _groq_vision_analyze(b64, prompt="Décris l'image brièvement.")
    except HTTPException:
        raise
    except Exception:
        analysis = "Analyse vision indisponible"
    return ImageUploadResponse(image_id=image_id, analysis=analysis)


@app.post("/ai/generate-image", response_model=ImageGenerationResponse)
async def generate_image(payload: ImageGenerationRequest, current_user=Depends(get_current_user)):
    prompt = payload.prompt.strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="Prompt obligatoire")
    seed = payload.seed or POLLINATIONS_SEED
    params = {
        "seed": seed,
        "width": max(256, min(payload.width, 1024)),
        "height": max(256, min(payload.height, 1024)),
    }
    url = f"{POLLINATIONS_BASE_URL}/{httpx.QueryParams({'prompt': prompt})}".split("?", 1)[0]
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.get(url, params=params)
        if response.status_code != 200:
            raise HTTPException(status_code=502, detail="Pollinations indisponible")
        data = base64.b64encode(response.content).decode("utf-8")
    return ImageGenerationResponse(prompt=prompt, seed=seed, image_base64=data)


@app.get("/ai/conversations", response_model=List[ConversationItem])
def list_conversations(current_user=Depends(get_current_user)):
    convs = conversations.find({"user_id": current_user["_id"]}).sort("updated_at", -1)
    items: List[ConversationItem] = []
    for conv in convs:
        conv_id = conv["_id"]
        items.append(
            ConversationItem(
                id=str(conv_id),
                bot_name=conv.get("bot_name", "Neo"),
                summary=conv.get("summary"),
                updated_at=conv.get("updated_at", conv.get("created_at", datetime.utcnow())),
                last_message=_last_message_preview(conv_id),
            )
        )
    return items


@app.delete("/ai/conversations/{conversation_id}")
def delete_conversation(conversation_id: str, current_user=Depends(get_current_user)):
    try:
        conv_id = ObjectId(conversation_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="conversation_id invalide") from exc

    conv = conversations.find_one({"_id": conv_id, "user_id": current_user["_id"]})
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation introuvable")

    conversations.delete_one({"_id": conv_id})
    messages_col.delete_many({"conversation_id": conv_id})
    return {"status": "deleted"}


@app.post("/ai/search", response_model=SearchResponse)
async def ai_search(payload: SearchRequest, current_user=Depends(get_current_user)):
    max_r = min(payload.max_results, SEARCH_MAX_RESULTS)
    results = await _search(payload.query, max_r)
    return SearchResponse(results=results)


@app.get("/ai/memory/{conversation_id}", response_model=MemoryResponse)
async def ai_memory(conversation_id: str, current_user=Depends(get_current_user)):
    try:
        conv_id = ObjectId(conversation_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="conversation_id invalide") from exc

    conv = conversations.find_one({"_id": conv_id, "user_id": current_user["_id"]})
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation introuvable")

    msgs = list(messages_col.find({"conversation_id": conv_id}).sort("created_at", 1))
    messages_resp = [
        MemoryMessage(
            role=m.get("role", "user"),
            content=m.get("content", ""),
            images=m.get("images", []),
            created_at=m.get("created_at", datetime.utcnow()),
        )
        for m in msgs
    ]
    return MemoryResponse(conversation_id=conversation_id, summary=conv.get("summary"), messages=messages_resp)


@app.post("/ai/chat", response_model=ChatResponse)
async def ai_chat(payload: ChatRequest, request: Request):
    current_user = _optional_user_from_request(request)
    user_id = current_user["_id"] if current_user else None

    conv_doc = None
    if payload.conversation_id:
        try:
            conv_id = ObjectId(payload.conversation_id)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail="conversation_id invalide") from exc
        conv_doc = conversations.find_one({"_id": conv_id})
        if not conv_doc:
            raise HTTPException(status_code=404, detail="Conversation introuvable")
        if conv_doc.get("user_id") and user_id and conv_doc["user_id"] != user_id:
            raise HTTPException(status_code=403, detail="Conversation inaccessible")
    else:
        conv_id = _get_or_create_conversation(user_id, payload.bot_name or "Neo")
        conv_doc = conversations.find_one({"_id": conv_id})

    history_cursor = messages_col.find({"conversation_id": conv_id}).sort("created_at", 1).limit(CHAT_HISTORY_LIMIT)
    history = list(history_cursor)

    prompt_parts = []
    if conv_doc and conv_doc.get("summary"):
        prompt_parts.append(f"Résumé précédent:\n{conv_doc['summary']}\n---")
    for msg in history:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        prompt_parts.append(f"{role}: {content}")
    prompt_parts.append(f"{payload.user_name or 'Utilisateur'}: {payload.message}")
    if payload.search:
        prompt_parts.append("(Le bot peut utiliser des recherches web disponibles.)")
    prompt = "\n".join(prompt_parts)

    reply = await _groq_chat(
        prompt,
        vision_images=payload.images,
        temperature=payload.temperature,
        max_tokens=payload.max_tokens,
    )
    _save_message(conv_id, "user", payload.message, payload.images)
    _save_message(conv_id, "assistant", reply)
    await _maybe_summarize(conv_id)

    return ChatResponse(conversation_id=str(conv_id), reply=reply, sources=None)


@app.post("/ai/transcribe", response_model=TranscribeResponse)
async def transcribe_audio(file: UploadFile = File(...), current_user=Depends(get_current_user)):
    if not Model or not KaldiRecognizer:
        return TranscribeResponse(text="", note="Transcription non disponible (vosk non installé)")
    if not VOSK_MODEL_PATH:
        return TranscribeResponse(text="", note="Transcription non configurée (VOSK_MODEL_PATH manquant)")
    global VOSK_MODEL_CACHE
    if VOSK_MODEL_CACHE is None:
        try:
            VOSK_MODEL_CACHE = Model(VOSK_MODEL_PATH)
        except Exception as exc:  # noqa: BLE001
            return TranscribeResponse(text="", note=f"Erreur chargement modèle Vosk: {exc}")

    data = await file.read()
    # Expect WAV; if not, try to read as WAV in memory
    try:
        wf = wave.open(io.BytesIO(data), "rb")
    except Exception:
        return TranscribeResponse(text="", note="Format audio non supporté (envoyez du WAV PCM)")
    if wf.getnchannels() != 1 or wf.getsampwidth() != 2:
        return TranscribeResponse(text="", note="Audio attendu mono 16-bit")
    rec = KaldiRecognizer(VOSK_MODEL_CACHE, wf.getframerate())
    text = ""
    while True:
        buf = wf.readframes(4000)
        if len(buf) == 0:
            break
        if rec.AcceptWaveform(buf):
            res = json.loads(rec.Result())
            text += " " + res.get("text", "")
    res_final = json.loads(rec.FinalResult())
    text += " " + res_final.get("text", "")
    return TranscribeResponse(text=text.strip(), note=None)


def _ensure_face_model():
    if not DeepFace or not cv2 or not np:
        raise HTTPException(status_code=500, detail="Librairie face non disponible")


def _encode_face(content: bytes) -> "np.ndarray":
    _ensure_face_model()
    file_bytes = np.frombuffer(content, np.uint8)
    img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
    if img is None:
        raise HTTPException(status_code=400, detail="Image invalide")
    return img


def _compute_face_embedding(img: "np.ndarray") -> List[float]:
    _ensure_face_model()
    try:
        rep = DeepFace.represent(img_path=img, model_name=FACE_MODEL_NAME, enforce_detection=True)
        if isinstance(rep, list) and rep:
            return rep[0]["embedding"]
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Impossible d'extraire le visage: {exc}") from exc
    raise HTTPException(status_code=400, detail="Aucun visage détecté")


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    va = np.array(a, dtype=np.float32)
    vb = np.array(b, dtype=np.float32)
    denom = np.linalg.norm(va) * np.linalg.norm(vb)
    if denom == 0:
        return 0.0
    return float(np.dot(va, vb) / denom)


@app.post("/ai/face-enroll", response_model=FaceEnrollResponse)
async def face_enroll(label: str = Form(...), file: UploadFile = File(...), current_user=Depends(get_current_user)):
    content = await file.read()
    img = _encode_face(content)
    embedding = _compute_face_embedding(img)
    face_id = str(uuid.uuid4())
    faces_col.insert_one(
        {
            "_id": face_id,
            "user_id": current_user["_id"],
            "label": label,
            "embedding": embedding,
            "created_at": datetime.utcnow(),
        }
    )
    return FaceEnrollResponse(face_id=face_id, label=label)


@app.post("/ai/face-match", response_model=FaceMatchResponse)
async def face_match(file: UploadFile = File(...), current_user=Depends(get_current_user)):
    content = await file.read()
    img = _encode_face(content)
    embedding = _compute_face_embedding(img)

    candidates = list(faces_col.find({"user_id": current_user["_id"]}))
    if not candidates:
        return FaceMatchResponse(match=False, note="Aucun visage enrôlé")

    best_sim = -1.0
    best_label = None
    for cand in candidates:
        sim = _cosine_similarity(embedding, cand.get("embedding", []))
        if sim > best_sim:
            best_sim = sim
            best_label = cand.get("label")
    match = best_sim >= (1 - FACE_DISTANCE_THRESHOLD)
    note = f"label={best_label}, similarity={best_sim:.3f}" if best_label else None
    return FaceMatchResponse(match=match, note=note)


# WebSocket streaming chat
@app.websocket("/ws/ai/chat")
async def ws_ai_chat(websocket: WebSocket):
    user = None  # open access
    await websocket.accept()
    try:
        while True:
            msg = await websocket.receive_text()
            try:
                payload = json.loads(msg)
                message = payload.get("message", "")
                conv_id_str = payload.get("conversation_id")
                bot_name = payload.get("bot_name", "Neo")
                user_name = payload.get("user_name", "Utilisateur")
                use_search = bool(payload.get("search", False))
                images_b64 = payload.get("images") or []
                temperature = float(payload.get("temperature", 0.5))
                max_tokens = payload.get("max_tokens")
            except Exception:
                await websocket.send_text(json.dumps({"error": "Payload invalide"}))
                continue

            conv_id = ObjectId(conv_id_str) if conv_id_str else _get_or_create_conversation(None, bot_name)
            history_cursor = messages_col.find({"conversation_id": conv_id}).sort("created_at", 1).limit(CHAT_HISTORY_LIMIT)
            history = list(history_cursor)
            conv_doc = conversations.find_one({"_id": conv_id})

            prompt_parts = []
            if conv_doc and conv_doc.get("summary"):
                prompt_parts.append(f"Résumé précédent:\n{conv_doc['summary']}\n---")
            for msg_doc in history:
                role = msg_doc.get("role", "user")
                content = msg_doc.get("content", "")
                prompt_parts.append(f"{role}: {content}")
            prompt_parts.append(f"{user_name}: {message}")
            if use_search:
                prompt_parts.append("(Le bot peut utiliser des recherches web disponibles.)")
            prompt = "\n".join(prompt_parts)

            try:
                reply = await _groq_chat(
                    prompt,
                    vision_images=images_b64,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            except Exception as exc:
                await websocket.send_text(json.dumps({"error": f"Erreur LLM: {exc}"}))
                continue

            _save_message(conv_id, "user", message, images_b64)
            _save_message(conv_id, "assistant", reply)
            await _maybe_summarize(conv_id)

            await websocket.send_text(json.dumps({"conversation_id": str(conv_id), "reply": reply}))
    except WebSocketDisconnect:
        if websocket.application_state != WebSocketState.DISCONNECTED:
            await websocket.close()


init_messaging(
    app,
    db=db,
    users_collection=users,
    file_storage=file_storage,
    get_current_user=get_current_user,
    ws_user_fetcher=_ws_get_user,
    jwt_secret=JWT_SECRET,
)
