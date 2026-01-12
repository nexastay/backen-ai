import os
import re
import secrets
import smtplib
from datetime import datetime, timedelta, timezone, date
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, Optional, Sequence, List, Any, Literal, Tuple
from urllib.parse import urlparse
from enum import Enum

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
from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.collection import Collection
from pymongo.errors import DuplicateKeyError
from gridfs import GridFSBucket
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
# messaging package lives alongside this module
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
ENABLE_SPEECH = os.getenv("ENABLE_SPEECH", "false").lower() == "true"
ENABLE_FACE = os.getenv("ENABLE_FACE", "false").lower() == "true"

if ENABLE_SPEECH:
    try:
        from vosk import Model, KaldiRecognizer
    except Exception:  # noqa: BLE001
        ENABLE_SPEECH = False
        Model = None
        KaldiRecognizer = None
else:
    Model = None
    KaldiRecognizer = None

if ENABLE_FACE:
    try:
        from deepface import DeepFace
        import cv2
        import numpy as np
    except Exception:  # noqa: BLE001
        ENABLE_FACE = False
        DeepFace = None
        cv2 = None
        np = None
else:
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
AUTH_DISABLED = os.getenv("AUTH_DISABLED", "false").lower() == "true"
AUTH_BYPASS_EMAIL = os.getenv("AUTH_BYPASS_EMAIL", "demo@neo.local")
AUTH_BYPASS_PSEUDO = os.getenv("AUTH_BYPASS_PSEUDO", "demo")
AUTH_BYPASS_NAME = os.getenv("AUTH_BYPASS_NAME", "Demo User")
EMAIL_SENDER = os.getenv("MAIL_CONFIRMATION")
EMAIL_PASSWORD = os.getenv("MOT_DE_PASSE_CONFIRMATION")
EMAIL_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("SMTP_PORT", "587"))
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:3000")
PROJECT_NAME = os.getenv("APP_NAME", "Neo Auth")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
GROQ_MODEL_VISION = os.getenv("GROQ_MODEL_VISION", "llama-3.2-11b-vision-preview")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
ANTHROPIC_VERSION = os.getenv("ANTHROPIC_VERSION", "2023-06-01")
ANTHROPIC_MAX_TOKENS = int(os.getenv("ANTHROPIC_MAX_TOKENS", "1024"))
ANTHROPIC_BASE_URL = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1/messages")
WEB_SEARCH_ENABLED = os.getenv("WEB_SEARCH_ENABLED", "true").lower() == "true"
SEARCH_MAX_RESULTS = int(os.getenv("SEARCH_MAX_RESULTS", "5"))
SERPAPI_KEY = os.getenv("SERPAPI_KEY")
FACE_RECO_THRESHOLD = float(os.getenv("FACE_RECO_THRESHOLD", "0.75"))
VOSK_MODEL_PATH = os.getenv("VOSK_MODEL_PATH")  # chemin vers un modèle Vosk (optionnel)
_cors_env = os.getenv("CORS_ORIGINS", "").strip()
ALLOWED_ORIGINS: Sequence[str] = (
    [origin.strip() for origin in _cors_env.split(",") if origin.strip()]
    if _cors_env else ["*"]  # Allow all origins if not specified (for APK/mobile)
)
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
enterprises_col: Collection = db["enterprises"]
enterprise_users_col: Collection = db["enterprise_users"]
projects_col: Collection = db["projects"]
conversations.create_index([("user_id", ASCENDING)], unique=False)
messages_col.create_index([("conversation_id", ASCENDING), ("created_at", ASCENDING)])
images_col.create_index([("user_id", ASCENDING), ("created_at", ASCENDING)])
faces_col.create_index([("user_id", ASCENDING)], unique=False)
enterprises_col.create_index([("code", ASCENDING)], unique=True)
enterprises_col.create_index([("siret", ASCENDING)], unique=True, sparse=True)
enterprise_users_col.create_index([("enterprise_id", ASCENDING), ("role", ASCENDING)])
enterprise_users_col.create_index([("code", ASCENDING)], unique=True, sparse=True)
projects_col.create_index([("enterprise_id", ASCENDING), ("code", ASCENDING)])
projects_col.create_index([("analysis_status", ASCENDING)])
file_storage = GridFSBucket(db, bucket_name="neo_files")

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
serializer = URLSafeTimedSerializer(JWT_SECRET)
app = FastAPI(title=f"{PROJECT_NAME} Auth API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  # Must be False when using wildcard origins
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["*"],
)

PASSWORD_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$"
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=not AUTH_DISABLED)


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
    search: bool = False
    images: Optional[List[str]] = None
    temperature: float = 0.4
    max_tokens: Optional[int] = None
    user_id: Optional[str] = None


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


class EnterpriseRole(str, Enum):
    ENTREPRISE = "ENTREPRISE"
    OUVRIER = "OUVRIER"
    SOUS_TRAITANT = "SOUS_TRAITANT"
    CLIENT = "CLIENT"
    FOURNISSEUR = "FOURNISSEUR"
    VENDEUR = "VENDEUR"


class ProjectScheduleStatus(str, Enum):
    PREVU = "Prévu"
    EN_COURS = "En cours"
    TERMINE = "Terminé"


class ProjectOrderStatus(str, Enum):
    CREEE = "Créée"
    CONFIRMEE = "Confirmée"
    PRETE = "Prête"
    LIVREE = "Livrée"


class PickupMode(str, Enum):
    LIVRAISON = "Livraison"
    RETRAIT = "Retrait"


class AnalysisStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    READY = "ready"


class CompanyProfileModel(BaseModel):
    id: str
    name: str
    siret: str
    contact_email: EmailStr
    phone: str
    code: str
    dtu_references: List[str] = Field(default_factory=list)
    special_norms: List[str] = Field(default_factory=list)
    authorizations: List[str] = Field(default_factory=list)


class EnterpriseUserModel(BaseModel):
    id: str
    enterprise_id: str
    role: EnterpriseRole
    name: str
    email: EmailStr
    code: str
    assigned_projects: List[str] = Field(default_factory=list)


class ProjectDocumentModel(BaseModel):
    id: str
    name: str
    mime_type: str
    uploaded_at: datetime
    uri: Optional[str] = None


class ProjectScheduleItemModel(BaseModel):
    id: str
    label: str
    start_date: date
    end_date: date
    status: ProjectScheduleStatus


class ProjectOrderModel(BaseModel):
    id: str
    material: str
    quantity: str
    supplier: str
    pickup_mode: PickupMode
    assigned_worker_id: Optional[str] = None
    status: ProjectOrderStatus
    delivery_date: Optional[date] = None


class ProjectProgressModel(BaseModel):
    percent: int
    updated_at: datetime
    next_milestone: str


class ProjectModel(BaseModel):
    id: str
    enterprise_id: str
    name: str
    client_name: str
    client_email: EmailStr
    address: str
    code: str
    start_date: date
    end_date: date
    documents: List[ProjectDocumentModel] = Field(default_factory=list)
    schedule: List[ProjectScheduleItemModel] = Field(default_factory=list)
    orders: List[ProjectOrderModel] = Field(default_factory=list)
    progress: ProjectProgressModel
    bill_of_materials: List[Dict[str, str]] = Field(default_factory=list)
    analysis_status: AnalysisStatus


class EnterpriseStateModel(BaseModel):
    company: CompanyProfileModel
    users: List[EnterpriseUserModel]
    projects: List[ProjectModel]


class CompanyUpsertRequest(BaseModel):
    id: Optional[str] = None
    name: str
    siret: Optional[str] = None
    contact_email: EmailStr
    phone: str
    code: Optional[str] = None
    dtu_references: List[str] = Field(default_factory=list)
    special_norms: List[str] = Field(default_factory=list)
    authorizations: List[str] = Field(default_factory=list)


class EnterpriseUserPayload(BaseModel):
    id: Optional[str] = None
    enterprise_id: Optional[str] = None
    role: EnterpriseRole
    name: str
    email: EmailStr
    code: Optional[str] = None
    assigned_projects: List[str] = Field(default_factory=list)


class ProjectDocumentPayload(BaseModel):
    id: Optional[str] = None
    name: str
    mime_type: str
    uploaded_at: datetime
    uri: Optional[str] = None


class ProjectScheduleItemPayload(BaseModel):
    id: Optional[str] = None
    label: str
    start_date: date
    end_date: date
    status: ProjectScheduleStatus = ProjectScheduleStatus.PREVU


class ProjectOrderPayload(BaseModel):
    id: Optional[str] = None
    material: str
    quantity: str
    supplier: str
    pickup_mode: PickupMode = PickupMode.LIVRAISON
    assigned_worker_id: Optional[str] = None
    status: ProjectOrderStatus = ProjectOrderStatus.CREEE
    delivery_date: Optional[date] = None


class ProjectProgressPayload(BaseModel):
    percent: int = Field(ge=0, le=100)
    updated_at: datetime
    next_milestone: str


class BillOfMaterialItemPayload(BaseModel):
    id: Optional[str] = None
    label: str
    value: str
    source: str


class ProjectUpsertRequest(BaseModel):
    id: Optional[str] = None
    enterprise_id: Optional[str] = None
    name: str
    client_name: str
    client_email: EmailStr
    address: str
    code: Optional[str] = None
    start_date: date
    end_date: date
    documents: List[ProjectDocumentPayload] = Field(default_factory=list)
    schedule: List[ProjectScheduleItemPayload] = Field(default_factory=list)
    orders: List[ProjectOrderPayload] = Field(default_factory=list)
    progress: ProjectProgressPayload
    bill_of_materials: List[BillOfMaterialItemPayload] = Field(default_factory=list)
    analysis_status: AnalysisStatus = AnalysisStatus.PENDING


def _generate_code(prefix: str, random_bytes: int = 3) -> str:
    suffix = secrets.token_hex(random_bytes).upper()
    return f"{prefix}-{suffix}"


def _ensure_object_id(value: Optional[str], *, field: str) -> ObjectId:
    if not value:
        raise HTTPException(status_code=400, detail=f"{field} requis")
    try:
        return ObjectId(value)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"{field} invalide") from exc


def _coerce_date(value: Any) -> date:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.split("T")[0])
        except ValueError:
            pass
    raise HTTPException(status_code=500, detail="Date invalide en base")


def _coerce_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass
    return datetime.utcnow()


def _serialize_company(doc: Dict[str, Any]) -> CompanyProfileModel:
    return CompanyProfileModel(
        id=str(doc["_id"]),
        name=doc.get("name", ""),
        siret=doc.get("siret", "") or "",
        contact_email=doc.get("contact_email"),
        phone=doc.get("phone", ""),
        code=doc.get("code", ""),
        dtu_references=doc.get("dtu_references", []),
        special_norms=doc.get("special_norms", []),
        authorizations=doc.get("authorizations", []),
    )


def _serialize_enterprise_user(doc: Dict[str, Any]) -> EnterpriseUserModel:
    return EnterpriseUserModel(
        id=str(doc["_id"]),
        enterprise_id=str(doc["enterprise_id"]),
        role=EnterpriseRole(doc.get("role", EnterpriseRole.OUVRIER)),
        name=doc.get("name", ""),
        email=doc.get("email", ""),
        code=doc.get("code", ""),
        assigned_projects=doc.get("assigned_projects", []),
    )


def _serialize_project(doc: Dict[str, Any]) -> ProjectModel:
    documents = [
        ProjectDocumentModel(
            id=d.get("id", str(ObjectId())),
            name=d.get("name", ""),
            mime_type=d.get("mime_type", "application/octet-stream"),
            uploaded_at=_coerce_datetime(d.get("uploaded_at")),
            uri=d.get("uri"),
        )
        for d in doc.get("documents", [])
    ]
    schedule = [
        ProjectScheduleItemModel(
            id=item.get("id", str(ObjectId())),
            label=item.get("label", ""),
            start_date=_coerce_date(item.get("start_date")),
            end_date=_coerce_date(item.get("end_date")),
            status=ProjectScheduleStatus(item.get("status", ProjectScheduleStatus.PREVU.value)),
        )
        for item in doc.get("schedule", [])
    ]
    orders = [
        ProjectOrderModel(
            id=order.get("id", str(ObjectId())),
            material=order.get("material", ""),
            quantity=order.get("quantity", ""),
            supplier=order.get("supplier", ""),
            pickup_mode=PickupMode(order.get("pickup_mode", PickupMode.LIVRAISON.value)),
            assigned_worker_id=order.get("assigned_worker_id"),
            status=ProjectOrderStatus(order.get("status", ProjectOrderStatus.CREEE.value)),
            delivery_date=_coerce_date(order.get("delivery_date")) if order.get("delivery_date") else None,
        )
        for order in doc.get("orders", [])
    ]
    progress_payload = doc.get("progress") or {}
    progress = ProjectProgressModel(
        percent=int(progress_payload.get("percent", 0)),
        updated_at=_coerce_datetime(progress_payload.get("updated_at")),
        next_milestone=progress_payload.get("next_milestone", ""),
    )
    analysis_status = doc.get("analysis_status", AnalysisStatus.PENDING.value)
    return ProjectModel(
        id=str(doc["_id"]),
        enterprise_id=str(doc["enterprise_id"]),
        name=doc.get("name", ""),
        client_name=doc.get("client_name", ""),
        client_email=doc.get("client_email", ""),
        address=doc.get("address", ""),
        code=doc.get("code", ""),
        start_date=_coerce_date(doc.get("start_date")),
        end_date=_coerce_date(doc.get("end_date")),
        documents=documents,
        schedule=schedule,
        orders=orders,
        progress=progress,
        bill_of_materials=doc.get("bill_of_materials", []),
        analysis_status=AnalysisStatus(analysis_status),
    )


def _ensure_enterprise_for_user(user: Dict[str, Any]) -> Dict[str, Any]:
    doc = enterprises_col.find_one({"owner_id": user["_id"]})
    if doc:
        return doc
    now = datetime.utcnow()
    template = {
        "owner_id": user["_id"],
        "name": user.get("display_name", "Entreprise Néo"),
        "siret": "",
        "contact_email": user.get("email"),
        "phone": "",
        "code": _generate_code("ENT"),
        "dtu_references": [],
        "special_norms": [],
        "authorizations": [],
        "created_at": now,
        "updated_at": now,
    }
    inserted_id = enterprises_col.insert_one(template).inserted_id
    doc = enterprises_col.find_one({"_id": inserted_id})
    assert doc is not None
    return doc


def _get_enterprise_scope(current_user: Dict[str, Any]) -> Tuple[Dict[str, Any], ObjectId]:
    enterprise = _ensure_enterprise_for_user(current_user)
    enterprise_id = enterprise["_id"]
    return enterprise, enterprise_id


def _project_payload_to_doc(payload: ProjectUpsertRequest, enterprise_id: ObjectId) -> Dict[str, Any]:
    documents = [
        {
            "id": item.id or str(ObjectId()),
            "name": item.name,
            "mime_type": item.mime_type,
            "uploaded_at": item.uploaded_at,
            "uri": item.uri,
        }
        for item in payload.documents
    ]
    schedule = [
        {
            "id": item.id or str(ObjectId()),
            "label": item.label,
            "start_date": item.start_date.isoformat(),
            "end_date": item.end_date.isoformat(),
            "status": item.status.value,
        }
        for item in payload.schedule
    ]
    orders = [
        {
            "id": item.id or str(ObjectId()),
            "material": item.material,
            "quantity": item.quantity,
            "supplier": item.supplier,
            "pickup_mode": item.pickup_mode.value,
            "assigned_worker_id": item.assigned_worker_id,
            "status": item.status.value,
            "delivery_date": item.delivery_date.isoformat() if item.delivery_date else None,
        }
        for item in payload.orders
    ]
    bill_of_materials = [bom.dict() for bom in payload.bill_of_materials]
    return {
        "enterprise_id": enterprise_id,
        "name": payload.name,
        "client_name": payload.client_name,
        "client_email": payload.client_email,
        "address": payload.address,
        "code": payload.code,
        "start_date": payload.start_date.isoformat(),
        "end_date": payload.end_date.isoformat(),
        "documents": documents,
        "schedule": schedule,
        "orders": orders,
        "progress": payload.progress.dict(),
        "bill_of_materials": bill_of_materials,
        "analysis_status": payload.analysis_status.value if isinstance(payload.analysis_status, AnalysisStatus) else payload.analysis_status,
        "updated_at": datetime.utcnow(),
    }


def _ensure_demo_user():
    user = users.find_one({"email": AUTH_BYPASS_EMAIL})
    if user:
        return user
    now = datetime.utcnow()
    doc = {
        "pseudo": AUTH_BYPASS_PSEUDO,
        "email": AUTH_BYPASS_EMAIL,
        "display_name": AUTH_BYPASS_NAME,
        "password_hash": hash_password(secrets.token_urlsafe(16)),
        "email_verified": True,
        "created_at": now,
        "updated_at": now,
    }
    users.insert_one(doc)
    return doc


def get_current_user(token: Optional[str] = Depends(oauth2_scheme)):
    if AUTH_DISABLED:
        return _ensure_demo_user()
    if not token:
        raise HTTPException(status_code=401, detail="Authentification requise")
    user_id = decode_jwt(token, expected_type="access")
    try:
        obj_id = ObjectId(user_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=401, detail="Token invalide") from exc
    user = users.find_one({"_id": obj_id})
    if not user:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")
    return user


@app.get("/enterprise/state", response_model=EnterpriseStateModel)
def enterprise_state(current_user=Depends(get_current_user)):
    enterprise, enterprise_id = _get_enterprise_scope(current_user)
    users_cursor = enterprise_users_col.find({"enterprise_id": enterprise_id}).sort("name", ASCENDING)
    projects_cursor = projects_col.find({"enterprise_id": enterprise_id}).sort("created_at", DESCENDING)
    return EnterpriseStateModel(
        company=_serialize_company(enterprise),
        users=[_serialize_enterprise_user(doc) for doc in users_cursor],
        projects=[_serialize_project(doc) for doc in projects_cursor],
    )


@app.put("/enterprise/company", response_model=CompanyProfileModel)
def update_company(payload: CompanyUpsertRequest, current_user=Depends(get_current_user)):
    enterprise, _ = _get_enterprise_scope(current_user)
    updated_fields = {
        "name": payload.name,
        "siret": payload.siret or "",
        "contact_email": payload.contact_email,
        "phone": payload.phone,
        "code": payload.code or enterprise.get("code") or _generate_code("ENT"),
        "dtu_references": payload.dtu_references,
        "special_norms": payload.special_norms,
        "authorizations": payload.authorizations,
        "updated_at": datetime.utcnow(),
    }
    enterprises_col.update_one({"_id": enterprise["_id"]}, {"$set": updated_fields})
    enterprise.update(updated_fields)
    return _serialize_company(enterprise)


@app.post("/enterprise/users", response_model=EnterpriseUserModel)
def create_enterprise_user(payload: EnterpriseUserPayload, current_user=Depends(get_current_user)):
    _, enterprise_id = _get_enterprise_scope(current_user)
    now = datetime.utcnow()
    doc = {
        "enterprise_id": enterprise_id,
        "role": payload.role.value,
        "name": payload.name,
        "email": payload.email,
        "code": payload.code or _generate_code("USR"),
        "assigned_projects": payload.assigned_projects,
        "created_at": now,
        "updated_at": now,
    }
    inserted = enterprise_users_col.insert_one(doc).inserted_id
    saved = enterprise_users_col.find_one({"_id": inserted})
    assert saved is not None
    return _serialize_enterprise_user(saved)


@app.put("/enterprise/users/{user_id}", response_model=EnterpriseUserModel)
def update_enterprise_user(user_id: str, payload: EnterpriseUserPayload, current_user=Depends(get_current_user)):
    _, enterprise_id = _get_enterprise_scope(current_user)
    obj_id = _ensure_object_id(user_id, field="user_id")
    doc = enterprise_users_col.find_one({"_id": obj_id, "enterprise_id": enterprise_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    updates = {
        "role": payload.role.value,
        "name": payload.name,
        "email": payload.email,
        "code": payload.code or doc.get("code") or _generate_code("USR"),
        "assigned_projects": payload.assigned_projects,
        "updated_at": datetime.utcnow(),
    }
    enterprise_users_col.update_one({"_id": obj_id}, {"$set": updates})
    doc.update(updates)
    return _serialize_enterprise_user(doc)


@app.delete("/enterprise/users/{user_id}")
def delete_enterprise_user(user_id: str, current_user=Depends(get_current_user)):
    _, enterprise_id = _get_enterprise_scope(current_user)
    obj_id = _ensure_object_id(user_id, field="user_id")
    result = enterprise_users_col.delete_one({"_id": obj_id, "enterprise_id": enterprise_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    projects_col.update_many(
        {"enterprise_id": enterprise_id},
        {"$pull": {"orders.$[].assigned_worker_id": user_id}},
    )
    return {"status": "deleted"}


@app.post("/enterprise/projects", response_model=ProjectModel)
def create_project(payload: ProjectUpsertRequest, current_user=Depends(get_current_user)):
    _, enterprise_id = _get_enterprise_scope(current_user)
    base_doc = _project_payload_to_doc(payload, enterprise_id)
    base_doc["code"] = payload.code or base_doc.get("code") or _generate_code("CH")
    now = datetime.utcnow()
    base_doc["created_at"] = now
    inserted = projects_col.insert_one(base_doc).inserted_id
    saved = projects_col.find_one({"_id": inserted})
    assert saved is not None
    return _serialize_project(saved)


@app.put("/enterprise/projects/{project_id}", response_model=ProjectModel)
def update_project(project_id: str, payload: ProjectUpsertRequest, current_user=Depends(get_current_user)):
    _, enterprise_id = _get_enterprise_scope(current_user)
    obj_id = _ensure_object_id(project_id, field="project_id")
    doc = projects_col.find_one({"_id": obj_id, "enterprise_id": enterprise_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Chantier introuvable")
    updated = _project_payload_to_doc(payload, enterprise_id)
    updated["code"] = payload.code or doc.get("code") or _generate_code("CH")
    projects_col.update_one({"_id": obj_id}, {"$set": updated})
    doc.update(updated)
    return _serialize_project(doc)


@app.get("/enterprise/projects/{project_id}", response_model=ProjectModel)
def get_project(project_id: str, current_user=Depends(get_current_user)):
    _, enterprise_id = _get_enterprise_scope(current_user)
    obj_id = _ensure_object_id(project_id, field="project_id")
    doc = projects_col.find_one({"_id": obj_id, "enterprise_id": enterprise_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Chantier introuvable")
    return _serialize_project(doc)


@app.delete("/enterprise/projects/{project_id}")
def delete_project(project_id: str, current_user=Depends(get_current_user)):
    _, enterprise_id = _get_enterprise_scope(current_user)
    obj_id = _ensure_object_id(project_id, field="project_id")
    result = projects_col.delete_one({"_id": obj_id, "enterprise_id": enterprise_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Chantier introuvable")
    return {"status": "deleted"}


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


@app.get("/")
def root():
    return {"status": "Neo backend up"}

@app.head("/")
async def head_root():
    return Response(status_code=200)


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


def _ensure_demo_user():
    user = users.find_one({"email": AUTH_BYPASS_EMAIL})
    if user:
        return user
    now = datetime.utcnow()
    doc = {
        "pseudo": AUTH_BYPASS_PSEUDO,
        "email": AUTH_BYPASS_EMAIL,
        "display_name": AUTH_BYPASS_NAME,
        "password_hash": hash_password(secrets.token_urlsafe(16)),
        "email_verified": True,
        "created_at": now,
        "updated_at": now,
    }
    users.insert_one(doc)
    return doc


def get_current_user(token: Optional[str] = Depends(oauth2_scheme)):
    if AUTH_DISABLED:
        return _ensure_demo_user()
    if not token:
        raise HTTPException(status_code=401, detail="Authentification requise")
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
    if not WEB_SEARCH_ENABLED:
        return results

    try:
        if SERPAPI_KEY:
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

        # Fallback DuckDuckGo HTML (gratuit, sans clé)
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                "https://html.duckduckgo.com/html/",
                params={"q": query},
                headers={"User-Agent": "Mozilla/5.0 (compatible; NeoBot/1.0)"},
                follow_redirects=True,
            )
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.select("a.result__a")[:max_results]:
                title = a.get_text(" ", strip=True)
                href = a.get("href")
                if href and title:
                    results.append({"title": title, "link": href})
    except Exception as exc:  # noqa: BLE001
        print(f"[Search] ⚠️ Impossible d'effectuer la recherche web ({exc})")
        return []

    return results


WEATHER_KEYWORDS = ("meteo", "météo", "weather", "temps", "temperature")
WEATHER_STOP_WORDS = {
    "aujourd'hui",
    "aujourdhui",
    "auj",
    "ajd",
    "demain",
    "maintenant",
    "svp",
    "stp",
    "please",
    "merci",
    "meteo",
    "météo",
    "weather",
    "temps",
    "temperature",
    "forecast",
}
WEATHER_CITY_AFTER_KEYWORD = re.compile(
    r"(?:meteo|météo|weather|temps|temperature)\s*(?:a|à|au|en|pour|sur|de|du|des)?\s*([A-Za-zÀ-ÖØ-öø-ÿ' -]{2,})",
    re.IGNORECASE,
)
WEATHER_CITY_AFTER_PREP = re.compile(
    r"(?:à|a|au|en|sur|pour)\s+([A-Za-zÀ-ÖØ-öø-ÿ' -]{2,})",
    re.IGNORECASE,
)
WEATHER_CODE_MAP: Dict[int, str] = {
    0: "ciel dégagé",
    1: "temps clair",
    2: "quelques nuages",
    3: "couvert",
    45: "brouillard",
    48: "brouillard givrant",
    51: "bruine faible",
    53: "bruine modérée",
    55: "bruine dense",
    56: "bruine verglaçante faible",
    57: "bruine verglaçante dense",
    61: "pluie faible",
    63: "pluie modérée",
    65: "forte pluie",
    66: "pluie verglaçante faible",
    67: "pluie verglaçante forte",
    71: "chute de neige légère",
    73: "chute de neige modérée",
    75: "chute de neige forte",
    77: "grésil",
    80: "averses faibles",
    81: "averses modérées",
    82: "fortes averses",
    85: "averses de neige faibles",
    86: "averses de neige fortes",
    95: "orages",
    96: "orages avec grêle",
    99: "orages violents avec grêle",
}


def _clean_city_phrase(raw: str) -> Optional[str]:
    if not raw:
        return None
    raw = raw.strip(" ,.;:!?")
    if not raw:
        return None
    tokens = [tok for tok in re.split(r"\s+", raw) if tok]
    cleaned: List[str] = []
    for token in tokens:
        normalized = token.lower().strip(" ,.;:!?")
        if normalized in WEATHER_STOP_WORDS:
            break
        cleaned.append(token.strip(" ,.;:!?"))
        if len(cleaned) >= 3:
            continue
    if not cleaned:
        return None
    return " ".join(cleaned)


def _extract_weather_city(message: str) -> Optional[str]:
    lowered = message.lower()
    if not any(keyword in lowered for keyword in WEATHER_KEYWORDS):
        return None
    match = WEATHER_CITY_AFTER_KEYWORD.search(message)
    if match:
        candidate = _clean_city_phrase(match.group(1))
        if candidate:
            return candidate
    match = WEATHER_CITY_AFTER_PREP.search(message)
    if match:
        candidate = _clean_city_phrase(match.group(1))
        if candidate:
            return candidate
    sanitized = lowered
    for keyword in WEATHER_KEYWORDS:
        sanitized = sanitized.replace(keyword, " ")
    sanitized = re.sub(r"\b(?:a|à|au|en|dans|pour|sur|de|du|des|la|le|les)\b", " ", sanitized)
    candidate = _clean_city_phrase(sanitized)
    if candidate:
        return candidate.title()
    return None


def _describe_weather_code(code: Optional[int]) -> str:
    if code is None:
        return "conditions inconnues"
    return WEATHER_CODE_MAP.get(code, f"conditions code {code}")


def _format_hour_label(iso_ts: Optional[str]) -> str:
    if not iso_ts:
        return ""
    iso_ts = iso_ts.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso_ts)
        if dt.tzinfo:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%d/%m %Hh")
    except ValueError:
        return iso_ts.replace("T", " ")


async def _fetch_weather_context(city_query: str) -> Optional[str]:
    async with httpx.AsyncClient(timeout=10) as client:
        geo_resp = await client.get(
            "https://geocoding-api.open-meteo.com/v1/search",
            params={"name": city_query, "count": 1, "language": "fr"},
        )
        geo_resp.raise_for_status()
        geo_data = geo_resp.json()
        matches = geo_data.get("results") or []
        if not matches:
            return None
        place = matches[0]
        city_name = place.get("name") or city_query.title()
        admin = place.get("admin1")
        country = place.get("country")
        lat = place.get("latitude")
        lon = place.get("longitude")
        tz_name = place.get("timezone") or "auto"
        forecast_resp = await client.get(
            "https://api.open-meteo.com/v1/forecast",
            params={
                "latitude": lat,
                "longitude": lon,
                "current_weather": True,
                "hourly": "temperature_2m,apparent_temperature,precipitation_probability",
                "timezone": tz_name,
            },
        )
        forecast_resp.raise_for_status()
        forecast_data = forecast_resp.json()

    current = forecast_data.get("current_weather")
    if not current:
        return None
    hourly = forecast_data.get("hourly") or {}
    times = hourly.get("time") or []
    temps = hourly.get("temperature_2m") or []
    feels = hourly.get("apparent_temperature") or []
    precip = hourly.get("precipitation_probability") or []
    cw_time = current.get("time")
    start_idx = times.index(cw_time) if cw_time in times else 0
    apparent_now = feels[start_idx] if start_idx < len(feels) else None
    location_label = ", ".join(filter(None, [city_name, admin, country]))

    forecast_lines: List[str] = []
    for i in range(start_idx, min(len(times), start_idx + 3)):
        label = _format_hour_label(times[i]) or times[i]
        temp_val = temps[i] if i < len(temps) else None
        feel_val = feels[i] if i < len(feels) else None
        precip_val = precip[i] if i < len(precip) else None
        if temp_val is None:
            continue
        line = f"{label}: {float(temp_val):.1f}°C"
        if feel_val is not None:
            line += f" (ressenti {float(feel_val):.1f}°C)"
        if precip_val is not None:
            line += f", pluie {int(precip_val)}%"
        forecast_lines.append(line)

    temp_now = current.get("temperature")
    wind = current.get("windspeed")
    wind_dir = current.get("winddirection")
    desc = _describe_weather_code(current.get("weathercode"))

    parts = [
        f"Données Open-Meteo pour {location_label or city_query.title()} (lat {lat:.2f}, lon {lon:.2f}, fuseau {tz_name})."
    ]
    current_line = f"Conditions actuelles ({cw_time}): {desc}"
    if temp_now is not None:
        current_line += f", {float(temp_now):.1f}°C"
    if apparent_now is not None:
        current_line += f" (ressenti {float(apparent_now):.1f}°C)"
    if wind is not None:
        wind_text = f"{float(wind):.0f} km/h"
        if wind_dir is not None:
            wind_text += f" direction {int(wind_dir)}°"
        current_line += f", vent {wind_text}"
    parts.append(current_line)
    if forecast_lines:
        parts.append("Prochaines heures: " + " | ".join(forecast_lines))
    parts.append("Source: https://open-meteo.com/")
    return "\n".join(parts)


async def _maybe_weather_context(message: str) -> Optional[str]:
    city = _extract_weather_city(message)
    if not city:
        return None
    try:
        return await _fetch_weather_context(city)
    except Exception as exc:  # noqa: BLE001
        print(f"[Weather] ⚠️ Impossible de récupérer la météo pour '{city}': {exc}")
        return None


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


async def _anthropic_chat(
    prompt: str,
    *,
    temperature: float = 0.5,
    max_tokens: Optional[int] = None,
) -> str:
    if not ANTHROPIC_API_KEY:
        raise RuntimeError("Claude non configuré")
    headers = {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": ANTHROPIC_VERSION,
        "content-type": "application/json",
    }
    payload = {
        "model": ANTHROPIC_MODEL,
        "max_tokens": max_tokens or ANTHROPIC_MAX_TOKENS,
        "temperature": temperature,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": prompt,
                    }
                ],
            }
        ],
    }
    async with httpx.AsyncClient(timeout=45) as client:
        try:
            resp = await client.post(ANTHROPIC_BASE_URL, headers=headers, json=payload)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            body_preview = exc.response.text[:400]
            raise HTTPException(
                status_code=502,
                detail=f"Anthropic API error ({exc.response.status_code}): {body_preview or 'voir logs'}",
            ) from exc
        data = resp.json()
        try:
            return data["content"][0]["text"]
        except (KeyError, IndexError):
            raise HTTPException(status_code=502, detail="Réponse Anthropic invalide")


async def _choose_llm_reply(
    prompt: str,
    *,
    images: Optional[List[str]],
    temperature: float,
    max_tokens: Optional[int],
) -> str:
    if images:
        return await _groq_chat(prompt, vision_images=images, temperature=temperature, max_tokens=max_tokens)
    anthropic_error: Optional[Exception] = None
    if ANTHROPIC_API_KEY:
        try:
            return await _anthropic_chat(prompt, temperature=temperature, max_tokens=max_tokens)
        except Exception as exc:  # noqa: BLE001
            anthropic_error = exc
    try:
        return await _groq_chat(prompt, temperature=temperature, max_tokens=max_tokens)
    except Exception as groq_exc:  # noqa: BLE001
        if anthropic_error and isinstance(anthropic_error, HTTPException):
            raise anthropic_error
        if anthropic_error:
            raise HTTPException(
                status_code=502,
                detail=f"Anthropic échec: {anthropic_error}; fallback Groq échec: {groq_exc}",
            ) from groq_exc
        raise


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
async def generate_image(payload: ImageGenerationRequest, request: Request):
    current_user = _optional_user_from_request(request)
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
    
    # Si search=True, faire une VRAIE recherche web et injecter les résultats
    if payload.search:
        search_results = await _search(payload.message, 3)
        if search_results:
            search_context = "\n".join([f"- {r['title']}: {r['link']}" for r in search_results])
            prompt_parts.append(f"\n[Résultats de recherche web pour '{payload.message}']:\n{search_context}\n")
        prompt_parts.append("Utilise les informations de recherche ci-dessus pour répondre précisément.")
    weather_context = await _maybe_weather_context(payload.message)
    if weather_context:
        prompt_parts.append(f"\n[Données météo fiables]:\n{weather_context}\n")
        prompt_parts.append("Réponds en utilisant exclusivement les données météo ci-dessus (pas d'invention).")
    prompt = "\n".join(prompt_parts)

    reply = await _choose_llm_reply(
        prompt,
        images=payload.images,
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
    if not ENABLE_FACE:
        raise HTTPException(status_code=503, detail="Reconnaissance faciale désactivée")
    if not DeepFace or not cv2 or not np:
        raise HTTPException(status_code=503, detail="Bibliothèque faciale non disponible sur cet environnement")


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
    if not ENABLE_FACE:
        raise HTTPException(status_code=503, detail="Fonction d'enrôlement facial désactivée")
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
    if not ENABLE_FACE:
        raise HTTPException(status_code=503, detail="Fonction de comparaison faciale désactivée")
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
            
            # Si search=True, faire une VRAIE recherche web
            if use_search:
                search_results = await _search(message, 3)
                if search_results:
                    search_context = "\n".join([f"- {r['title']}: {r['link']}" for r in search_results])
                    prompt_parts.append(f"\n[Résultats de recherche web]:\n{search_context}\n")
                prompt_parts.append("Utilise ces informations pour répondre précisément.")
            weather_context = await _maybe_weather_context(message)
            if weather_context:
                prompt_parts.append(f"\n[Données météo fiables]:\n{weather_context}\n")
                prompt_parts.append("Réponds en utilisant exclusivement les données météo ci-dessus.")
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


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
