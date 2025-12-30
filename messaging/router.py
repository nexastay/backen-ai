"""Messaging backend (rooms, messages, attachments, realtime)."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Literal
from uuid import uuid4

from bson import ObjectId
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, Field

from .crypto import get_cipher, MessageCipher
from .moderation import ModerationError, ModerationService

ATTACHMENT_LIMIT = 20 * 1024 * 1024  # 20 MB
MESSAGE_LIMIT = 10_000
EMOTE_CATEGORIES: Sequence[Dict[str, Any]] = [
    {
        "category": "Humeurs & réactions",
        "emotes": [
            "😀",
            "😁",
            "😂",
            "🤣",
            "😃",
            "😄",
            "😅",
            "😆",
            "😉",
            "😊",
            "🙂",
            "🙃",
            "🥰",
            "😍",
            "😘",
            "😗",
            "😙",
            "😚",
            "😋",
            "😛",
            "😜",
            "🤪",
            "😝",
            "🤗",
            "🤭",
            "🤔",
            "🫢",
            "🤨",
            "😐",
            "😑",
            "😶",
            "🥲",
            "😢",
            "😭",
            "🥺",
            "😤",
            "😠",
            "😡",
            "🤬",
            "🤯",
            "😳",
            "😱",
            "😰",
            "😥",
            "😓",
            "😪",
            "😴",
            "🤒",
            "🤕",
            "😷",
            "🤧",
            "🥱",
            "😎",
            "🤓",
            "🧐",
            "🤠",
        ],
    },
    {
        "category": "Gestes & interactions",
        "emotes": [
            "👍",
            "👎",
            "👏",
            "🙌",
            "🤝",
            "🙏",
            "🤲",
            "👐",
            "👊",
            "🤜",
            "🤛",
            "✊",
            "✋",
            "🤚",
            "🖐️",
            "🖖",
            "👌",
            "🤌",
            "🤏",
            "👉",
            "👈",
            "👆",
            "👇",
            "☝️",
            "🤞",
            "🤟",
            "🤘",
            "👋",
            "🤙",
            "💪",
            "🦾",
            "🦿",
            "🦵",
            "🦶",
            "🫱",
            "🫲",
            "🫳",
            "🫴",
            "🙋",
            "🙆",
            "🙅",
            "💁",
            "🤷",
            "🙇",
            "🧎",
            "🚶",
            "🏃",
            "🧘",
            "🕺",
            "💃",
        ],
    },
    {
        "category": "Travail & productivité",
        "emotes": [
            "💡",
            "📱",
            "💻",
            "🖥️",
            "⌨️",
            "🖱️",
            "🖊️",
            "📝",
            "📋",
            "📌",
            "📍",
            "📎",
            "🧷",
            "📅",
            "📆",
            "📊",
            "📈",
            "📉",
            "📚",
            "📖",
            "🧾",
            "🧮",
            "📦",
            "🗃️",
            "🗂️",
            "📮",
            "📫",
            "📬",
            "📯",
            "🧰",
            "🧲",
            "🪛",
            "🪚",
            "⚙️",
            "⚒️",
            "⚖️",
            "📡",
            "🔋",
            "🔌",
            "🧪",
            "🧫",
            "🩺",
            "🚀",
            "🛰️",
            "💼",
            "🧳",
        ],
    },
    {
        "category": "Lifestyle & bien-être",
        "emotes": [
            "☕",
            "🫖",
            "🍵",
            "🥤",
            "🍹",
            "🍷",
            "🍺",
            "🍽️",
            "🍱",
            "🍣",
            "🍜",
            "🍝",
            "🥗",
            "🥪",
            "🍔",
            "🍕",
            "🌮",
            "🌯",
            "🍩",
            "🍪",
            "🧁",
            "🍰",
            "🍫",
            "🍦",
            "🍓",
            "🍉",
            "🍍",
            "🍋",
            "🥑",
            "🥕",
            "🥐",
            "🥨",
            "🧀",
            "🥚",
            "🍳",
            "🥞",
            "🥓",
            "🥩",
            "🍗",
            "🍖",
            "🥂",
            "🍾",
            "🎂",
            "🎉",
            "🎁",
            "🎈",
            "🛍️",
            "💅",
        ],
    },
    {
        "category": "Nature & cosmos",
        "emotes": [
            "🌸",
            "🌼",
            "🌻",
            "🌹",
            "🌷",
            "🌺",
            "🌲",
            "🌳",
            "🌴",
            "🌵",
            "🌱",
            "🍀",
            "🍃",
            "🍂",
            "🍁",
            "🌾",
            "🌊",
            "🔥",
            "💧",
            "❄️",
            "⚡",
            "🌪️",
            "🌈",
            "☀️",
            "🌤️",
            "⛅",
            "🌥️",
            "🌦️",
            "🌧️",
            "🌨️",
            "🌩️",
            "🌫️",
            "🌙",
            "⭐",
            "🌟",
            "✨",
            "🌠",
            "🌌",
            "🌍",
            "🌎",
            "🌏",
            "🪐",
            "🌋",
            "🗻",
            "🏔️",
            "🏝️",
            "🏞️",
            "🦋",
            "🐝",
        ],
    },
    {
        "category": "Culture & fête",
        "emotes": [
            "🎉",
            "🥳",
            "🎊",
            "🎈",
            "🎆",
            "🎇",
            "🎃",
            "🪅",
            "🎟️",
            "🎫",
            "🎬",
            "🎧",
            "🎤",
            "🎹",
            "🥁",
            "🎷",
            "🎺",
            "🎸",
            "🪗",
            "🎮",
            "🕹️",
            "🧩",
            "♟️",
            "🃏",
            "🎴",
            "🀄",
            "🎯",
            "🎳",
            "⚽",
            "🏀",
            "🏈",
            "⚾",
            "🎾",
            "🏐",
            "🏓",
            "🥊",
            "🥋",
            "🎽",
            "🏆",
            "🥇",
            "🥈",
            "🥉",
            "🎖️",
            "🛹",
            "🪂",
            "🚴",
            "⛷️",
            "🏄",
            "🏊",
        ],
    },
    {
        "category": "Symboles essentiels",
        "emotes": [
            "❤️",
            "🧡",
            "💛",
            "💚",
            "💙",
            "💜",
            "🖤",
            "🤍",
            "🤎",
            "❤️‍🔥",
            "❤️‍🩹",
            "💔",
            "❣️",
            "💕",
            "💞",
            "💓",
            "💗",
            "💖",
            "💘",
            "💝",
            "💟",
            "☮️",
            "☯️",
            "⚛️",
            "♾️",
            "✝️",
            "☪️",
            "🕉️",
            "☸️",
            "✡️",
            "🔯",
            "☦️",
            "🛐",
            "♻️",
            "⚠️",
            "✅",
            "❌",
            "⚡",
            "✨",
            "💬",
            "🗨️",
            "💭",
            "🔔",
            "🔕",
            "⭐",
            "🌟",
            "🔒",
            "🔓",
            "🔑",
        ],
    },
    {
        "category": "Drapeaux & territoires",
        "emotes": [
            "🏳️",
            "🏴",
            "🏁",
            "🚩",
            "🏳️‍🌈",
            "🏳️‍⚧️",
            "🇦🇫",
            "🇦🇱",
            "🇩🇿",
            "🇦🇩",
            "🇦🇴",
            "🇦🇷",
            "🇦🇲",
            "🇦🇺",
            "🇦🇹",
            "🇦🇿",
            "🇧🇭",
            "🇧🇩",
            "🇧🇪",
            "🇧🇷",
            "🇨🇦",
            "🇨🇳",
            "🇨🇴",
            "🇨🇷",
            "🇨🇺",
            "🇨🇿",
            "🇩🇰",
            "🇩🇴",
            "🇪🇨",
            "🇪🇬",
            "🇪🇪",
            "🇪🇹",
            "🇪🇺",
            "🇫🇮",
            "🇫🇷",
            "🇬🇦",
            "🇩🇪",
            "🇬🇭",
            "🇬🇷",
            "🇬🇹",
            "🇭🇳",
            "🇭🇺",
            "🇮🇸",
            "🇮🇳",
            "🇮🇩",
            "🇮🇪",
            "🇮🇱",
            "🇮🇹",
            "🇯🇵",
            "🇰🇪",
            "🇰🇷",
            "🇱🇧",
            "🇲🇬",
            "🇲🇾",
            "🇲🇽",
            "🇲🇦",
            "🇳🇱",
            "🇳🇿",
            "🇳🇬",
            "🇳🇴",
            "🇵🇰",
            "🇵🇪",
            "🇵🇭",
            "🇵🇱",
            "🇵🇹",
            "🇶🇦",
            "🇷🇴",
            "🇷🇺",
            "🇸🇦",
            "🇸🇳",
            "🇷🇸",
            "🇸🇬",
            "🇸🇰",
            "🇿🇦",
            "🇪🇸",
            "🇱🇰",
            "🇸🇪",
            "🇨🇭",
            "🇹🇳",
            "🇹🇷",
            "🇺🇬",
            "🇺🇦",
            "🇦🇪",
            "🇬🇧",
            "🇺🇸",
            "🇺🇾",
            "🇻🇪",
            "🇻🇳",
        ],
    },
]

EMOTE_LOOKUP: Set[str] = {emote for category in EMOTE_CATEGORIES for emote in category["emotes"]}


def _utcnow() -> datetime:
    return datetime.utcnow()


def _ensure_object_id(value: str) -> ObjectId:
    try:
        return ObjectId(value)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="Identifiant invalide") from exc


class AttachmentKind(str):
    TEXT = "text"
    AUDIO = "audio"
    IMAGE = "image"
    VIDEO = "video"
    DOCUMENT = "document"
    EMOTE = "emote"


class MessageKind(str):
    TEXT = "text"
    AUDIO = "audio"
    IMAGE = "image"
    VIDEO = "video"
    DOCUMENT = "document"
    EMOTE = "emote"


class CreateRoomRequest(BaseModel):
    name: Optional[str] = Field(None, max_length=80)
    member_ids: List[str] = Field(..., min_length=1)
    is_group: bool = False
    avatar: Optional[str] = None


class UpdateRoomMembersRequest(BaseModel):
    name: Optional[str] = Field(None, max_length=80)
    add_member_ids: List[str] = Field(default_factory=list)
    remove_member_ids: List[str] = Field(default_factory=list)


class RoomResponse(BaseModel):
    id: str
    name: str
    is_group: bool
    members: List[Dict[str, Any]]
    last_message: Optional[Dict[str, Any]] = None
    unread: int = 0


class AttachmentResponse(BaseModel):
    id: str
    kind: str
    filename: str
    size: int
    content_type: str


class MessageResponse(BaseModel):
    id: str
    room_id: str
    sender: Dict[str, Any]
    kind: str
    content: Optional[str] = None
    attachments: List[AttachmentResponse] = Field(default_factory=list)
    created_at: datetime
    delivered_to: List[str]
    read_by: List[str]


class SendMessageRequest(BaseModel):
    kind: str = Field(MessageKind.TEXT)
    content: Optional[str] = None
    attachment_ids: List[str] = Field(default_factory=list)
    emotes: List[str] = Field(default_factory=list)


class TypingPayload(BaseModel):
    typing: bool = True
    mode: Literal["text", "voice", "audio"] = "text"


class DeliveryPayload(BaseModel):
    message_id: Optional[str] = None


class ReadReceiptPayload(BaseModel):
    message_id: Optional[str] = None


class PresencePayload(BaseModel):
    status: Literal["online", "away", "busy", "offline"] = "online"


class EmoteCategoryModel(BaseModel):
    category: str
    emotes: List[str]


class EmoteCatalogResponse(BaseModel):
    categories: List[EmoteCategoryModel]


class MessagingService:
    def __init__(self, db, users_collection, file_storage, secret: str) -> None:
        self.rooms = db["chat_rooms"]
        self.messages = db["chat_messages"]
        self.attachments = db["chat_attachments"]
        self.files = file_storage
        self.users = users_collection
        self.cipher: MessageCipher = get_cipher(secret)
        self.moderation = ModerationService()
        self.connections: Dict[str, Set[WebSocket]] = {}
        self.presence: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        self.rooms.create_index([("member_ids", 1)])
        self.rooms.create_index([("updated_at", -1)])
        self.messages.create_index([("room_id", 1), ("created_at", -1)])
        self.attachments.create_index([("owner_id", 1), ("created_at", -1)])

    def get_presence_snapshot(self) -> List[Dict[str, Any]]:
        snapshot: List[Dict[str, Any]] = []
        for user_id, payload in self.presence.items():
            snapshot.append({"user_id": user_id, **payload})
        return snapshot

    async def update_presence(self, user: Dict[str, Any], status: str) -> None:
        normalized = status if status in {"online", "away", "busy", "offline"} else "online"
        user_id = str(user["_id"])
        payload = {
            "status": normalized,
            "updated_at": _utcnow().isoformat(),
            "pseudo": user.get("pseudo"),
            "display_name": user.get("display_name"),
        }
        self.presence[user_id] = payload
        await self.broadcast(
            list(self.connections.keys()),
            {"type": "presence", "user_id": user_id, **payload},
        )

    def _moderate_content(self, payload: SendMessageRequest) -> None:
        if payload.kind == MessageKind.TEXT:
            if payload.content and len(payload.content) > MESSAGE_LIMIT:
                raise HTTPException(status_code=400, detail="Message trop long")
            try:
                self.moderation.ensure_text_allowed(payload.content, context="message")
            except ModerationError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        if payload.kind == MessageKind.EMOTE:
            if not payload.emotes:
                raise HTTPException(status_code=400, detail="Aucune émote sélectionnée")
            invalid = [emote for emote in payload.emotes if emote not in EMOTE_LOOKUP]
            if invalid:
                raise HTTPException(status_code=400, detail=f"Émotes inconnues: {' '.join(invalid[:5])}")

    def _sanitize_members(self, member_ids: List[str], creator_id: ObjectId) -> Tuple[List[ObjectId], List[Dict[str, Any]]]:
        unique_ids = {creator_id}
        bson_ids: List[ObjectId] = []
        members_payload: List[Dict[str, Any]] = []
        for mid in member_ids:
            obj_id = _ensure_object_id(mid)
            unique_ids.add(obj_id)
        for oid in unique_ids:
            user = self.users.find_one({"_id": oid})
            if not user:
                raise HTTPException(status_code=404, detail="Utilisateur introuvable")
            bson_ids.append(oid)
            members_payload.append(
                {
                    "user_id": oid,
                    "pseudo": user.get("pseudo"),
                    "display_name": user.get("display_name"),
                    "typing": False,
                    "last_read_at": None,
                    "joined_at": _utcnow(),
                }
            )
        return bson_ids, members_payload

    def create_room(self, creator: Dict[str, Any], payload: CreateRoomRequest) -> RoomResponse:
        member_ids, members_payload = self._sanitize_members(payload.member_ids, creator["_id"])
        is_group = payload.is_group or len(member_ids) > 2
        name = payload.name or (payload.avatar or (payload.is_group and "Groupe")) or ", ".join(
            sorted(m["display_name"] for m in members_payload if m["user_id"] != creator["_id"])
        )
        doc = {
            "name": name,
            "avatar": payload.avatar,
            "is_group": is_group,
            "member_ids": member_ids,
            "members": members_payload,
            "created_at": _utcnow(),
            "updated_at": _utcnow(),
            "creator_id": creator["_id"],
        }
        result = self.rooms.insert_one(doc)
        doc["_id"] = result.inserted_id
        return self._room_to_response(doc, creator["_id"])

    def update_room_members(
        self, room_id: str, current_user: Dict[str, Any], payload: UpdateRoomMembersRequest
    ) -> RoomResponse:
        room = self._validate_room_access(room_id, current_user)
        member_ids: List[ObjectId] = list(room.get("member_ids", []))
        members_payload: List[Dict[str, Any]] = list(room.get("members", []))
        member_lookup: Dict[ObjectId, Dict[str, Any]] = {
            member["user_id"]: member for member in members_payload
        }

        # Handle additions
        if payload.add_member_ids:
            for mid in payload.add_member_ids:
                oid = _ensure_object_id(mid)
                if oid in member_lookup:
                    continue
                user = self.users.find_one({"_id": oid})
                if not user:
                    raise HTTPException(status_code=404, detail="Utilisateur introuvable")
                entry = {
                    "user_id": oid,
                    "pseudo": user.get("pseudo"),
                    "display_name": user.get("display_name"),
                    "typing": False,
                    "last_read_at": None,
                    "joined_at": _utcnow(),
                }
                member_ids.append(oid)
                members_payload.append(entry)
                member_lookup[oid] = entry

        # Handle removals (cannot remove self)
        remove_ids: Set[ObjectId] = set()
        for mid in payload.remove_member_ids or []:
            oid = _ensure_object_id(mid)
            if oid == current_user["_id"]:
                raise HTTPException(status_code=400, detail="Impossible de vous retirer du groupe.")
            remove_ids.add(oid)

        if remove_ids:
            member_ids = [oid for oid in member_ids if oid not in remove_ids]
            members_payload = [member for member in members_payload if member["user_id"] not in remove_ids]
            if len(member_ids) < 2:
                raise HTTPException(status_code=400, detail="Un groupe doit contenir au moins deux membres.")

        update_fields: Dict[str, Any] = {
            "member_ids": member_ids,
            "members": members_payload,
            "updated_at": _utcnow(),
        }
        new_name = (payload.name or "").strip()
        if new_name:
            update_fields["name"] = new_name

        self.rooms.update_one({"_id": room["_id"]}, {"$set": update_fields})
        room.update(update_fields)
        updated = self.rooms.find_one({"_id": room["_id"]})
        response = self._room_to_response(updated, current_user["_id"])
        asyncio.create_task(
            self._broadcast_room(
                updated,
                {
                    "type": "room_updated",
                    "room_id": response.id,
                    "payload": response.dict(),
                },
            )
        )
        return response

    def list_rooms(self, current_user: Dict[str, Any]) -> List[RoomResponse]:
        cursor = self.rooms.find({"member_ids": current_user["_id"]}).sort("updated_at", -1)
        return [self._room_to_response(doc, current_user["_id"]) for doc in cursor]

    def _room_to_response(self, doc: Dict[str, Any], user_id: ObjectId) -> RoomResponse:
        last_message = self.messages.find_one({"room_id": doc["_id"]}, sort=[("created_at", -1)])
        unread = self.messages.count_documents({
            "room_id": doc["_id"],
            "delivered_to": {"$ne": str(user_id)},
            "sender_id": {"$ne": user_id},
        })
        return RoomResponse(
            id=str(doc["_id"]),
            name=doc.get("name", "Conversation"),
            is_group=doc.get("is_group", False),
            members=[
                {
                    "id": str(member["user_id"]),
                    "pseudo": member.get("pseudo"),
                    "display_name": member.get("display_name"),
                    "typing": member.get("typing", False),
                }
                for member in doc.get("members", [])
            ],
            last_message=self._message_to_dict(last_message) if last_message else None,
            unread=unread,
        )

    def _message_to_dict(self, doc: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not doc:
            return None
        content = doc.get("content")
        if content:
            try:
                decrypted = self.cipher.decrypt(content)
            except Exception:  # pragma: no cover - corrupted payload
                decrypted = None
        else:
            decrypted = None
        return {
            "id": str(doc["_id"]),
            "kind": doc.get("kind", MessageKind.TEXT),
            "content": decrypted,
            "sender": {
                "id": str(doc.get("sender_id")),
                "pseudo": doc.get("sender_pseudo"),
            },
            "created_at": doc.get("created_at"),
        }

    def _validate_room_access(self, room_id: str, current_user: Dict[str, Any]) -> Dict[str, Any]:
        room = self.rooms.find_one({"_id": _ensure_object_id(room_id), "member_ids": current_user["_id"]})
        if not room:
            raise HTTPException(status_code=404, detail="Conversation introuvable")
        return room

    def get_messages(
        self,
        room_id: str,
        current_user: Dict[str, Any],
        *,
        limit: int = 50,
        before: Optional[str] = None,
    ) -> List[MessageResponse]:
        room = self._validate_room_access(room_id, current_user)
        query: Dict[str, Any] = {"room_id": room["_id"]}
        if before:
            query["_id"] = {"$lt": _ensure_object_id(before)}
        cursor = self.messages.find(query).sort("created_at", -1).limit(max(1, min(limit, 200)))
        messages = list(cursor)
        messages.reverse()
        return [self._doc_to_message_response(doc) for doc in messages]

    def _doc_to_message_response(self, doc: Dict[str, Any]) -> MessageResponse:
        attachments = self.attachments.find({"_id": {"$in": [att["attachment_id"] for att in doc.get("attachments", [])]}})
        attachments_map = {str(att["_id"]): att for att in attachments}
        return MessageResponse(
            id=str(doc["_id"]),
            room_id=str(doc["room_id"]),
            sender={
                "id": str(doc["sender_id"]),
                "pseudo": doc.get("sender_pseudo"),
            },
            kind=doc.get("kind", MessageKind.TEXT),
            content=self.cipher.decrypt(doc["content"]) if doc.get("content") else None,
            attachments=[
                AttachmentResponse(
                    id=str(att_id),
                    kind=attachments_map[att_id].get("kind", AttachmentKind.DOCUMENT),
                    filename=attachments_map[att_id].get("filename", ""),
                    size=attachments_map[att_id].get("size", 0),
                    content_type=attachments_map[att_id].get("content_type", "application/octet-stream"),
                )
                for att_id in [att["attachment_id"] for att in doc.get("attachments", []) if att["attachment_id"] in attachments_map]
            ],
            created_at=doc.get("created_at"),
            delivered_to=doc.get("delivered_to", []),
            read_by=doc.get("read_by", []),
        )

    async def store_attachment(self, current_user: Dict[str, Any], kind: str, file: UploadFile) -> AttachmentResponse:
        data = await file.read()
        if len(data) > ATTACHMENT_LIMIT:
            raise HTTPException(status_code=400, detail="Fichier trop volumineux (20MB max)")
        file_id = self.files.upload_from_stream(
            file.filename or "attachment",
            data,
            metadata={
                "owner_id": str(current_user["_id"]),
                "kind": kind,
                "content_type": file.content_type or "application/octet-stream",
            },
        )
        doc_id = str(uuid4())
        doc = {
            "_id": doc_id,
            "owner_id": current_user["_id"],
            "kind": kind,
            "filename": file.filename,
            "size": len(data),
            "content_type": file.content_type or "application/octet-stream",
            "file_id": file_id,
            "created_at": _utcnow(),
        }
        self.attachments.insert_one(doc)
        return AttachmentResponse(
            id=doc_id,
            kind=kind,
            filename=file.filename,
            size=len(data),
            content_type=doc["content_type"],
        )

    def _attachment_docs(self, ids: List[str]) -> List[Dict[str, Any]]:
        if not ids:
            return []
        docs = list(self.attachments.find({"_id": {"$in": ids}}))
        if len(docs) != len(ids):
            raise HTTPException(status_code=404, detail="Pièce jointe introuvable")
        return docs

    def send_message(self, room_id: str, current_user: Dict[str, Any], payload: SendMessageRequest) -> MessageResponse:
        room = self._validate_room_access(room_id, current_user)
        attachments = self._attachment_docs(payload.attachment_ids)
        self._moderate_content(payload)
        if payload.kind == MessageKind.EMOTE and payload.emotes:
            payload.content = json.dumps(payload.emotes)
        encrypted = self.cipher.encrypt(payload.content or "") if payload.content else None
        doc = {
            "room_id": room["_id"],
            "sender_id": current_user["_id"],
            "sender_pseudo": current_user.get("pseudo"),
            "kind": payload.kind,
            "content": encrypted,
            "attachments": [
                {
                    "attachment_id": att["_id"],
                    "kind": att.get("kind", AttachmentKind.DOCUMENT),
                }
                for att in attachments
            ],
            "created_at": _utcnow(),
            "delivered_to": [str(current_user["_id"])],
            "read_by": [str(current_user["_id"])],
        }
        inserted = self.messages.insert_one(doc)
        doc["_id"] = inserted.inserted_id
        self.rooms.update_one({"_id": room["_id"]}, {"$set": {"updated_at": _utcnow()}})
        message_resp = self._doc_to_message_response(doc)
        asyncio.create_task(self._broadcast_room(room, {
            "type": "message",
            "room_id": str(room["_id"]),
            "payload": message_resp.dict(),
        }))
        return message_resp

    def update_typing(self, room_id: str, current_user: Dict[str, Any], typing: bool, mode: str) -> None:
        if mode not in {"text", "voice", "audio"}:
            raise HTTPException(status_code=400, detail="Mode de saisie invalide")
        room = self._validate_room_access(room_id, current_user)
        self.rooms.update_one(
            {"_id": room["_id"], "members.user_id": current_user["_id"]},
            {"$set": {"members.$.typing": typing}},
        )
        asyncio.create_task(
            self._broadcast_room(
                room,
                {
                    "type": "typing",
                    "room_id": str(room["_id"]),
                    "user_id": str(current_user["_id"]),
                    "typing": typing,
                    "mode": mode,
                },
            )
        )

    def mark_delivery(self, room_id: str, current_user: Dict[str, Any], message_id: Optional[str]) -> None:
        room = self._validate_room_access(room_id, current_user)
        filter_query = {"room_id": room["_id"], "sender_id": {"$ne": current_user["_id"]}}
        if message_id:
            filter_query["_id"] = {"$lte": _ensure_object_id(message_id)}
        self.messages.update_many(
            filter_query,
            {
                "$addToSet": {
                    "delivered_to": str(current_user["_id"]),
                }
            },
        )
        asyncio.create_task(
            self._broadcast_room(
                room,
                {
                    "type": "delivery",
                    "room_id": str(room["_id"]),
                    "user_id": str(current_user["_id"]),
                    "message_id": message_id,
                },
            )
        )

    def mark_read(self, room_id: str, current_user: Dict[str, Any], message_id: Optional[str]) -> None:
        room = self._validate_room_access(room_id, current_user)
        filter_query = {"room_id": room["_id"], "sender_id": {"$ne": current_user["_id"]}}
        if message_id:
            filter_query["_id"] = {"$lte": _ensure_object_id(message_id)}
        self.messages.update_many(
            filter_query,
            {
                "$addToSet": {
                    "delivered_to": str(current_user["_id"]),
                    "read_by": str(current_user["_id"]),
                }
            },
        )
        asyncio.create_task(
            self._broadcast_room(
                room,
                {
                    "type": "read",
                    "room_id": str(room["_id"]),
                    "user_id": str(current_user["_id"]),
                    "message_id": message_id,
                },
            )
        )

    async def _broadcast_room(self, room: Dict[str, Any], payload: Dict[str, Any]) -> None:
        user_ids = [str(mid) for mid in room.get("member_ids", [])]
        await self.broadcast(user_ids, payload)

    async def broadcast(self, user_ids: Sequence[str], payload: Dict[str, Any]) -> None:
        data = json.dumps(payload)
        for user_id in user_ids:
            connections = list(self.connections.get(user_id, set()))
            for ws in connections:
                try:
                    await ws.send_text(data)
                except RuntimeError:
                    await self.unregister_connection(user_id, ws)

    async def register_connection(self, user_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            self.connections.setdefault(user_id, set()).add(websocket)

    async def unregister_connection(self, user_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            conns = self.connections.get(user_id)
            if not conns:
                return
            conns.discard(websocket)
            if not conns:
                self.connections.pop(user_id, None)
                # mark offline when no more active sockets
                self.presence[user_id] = {"status": "offline", "updated_at": _utcnow().isoformat()}
                asyncio.create_task(
                    self.broadcast(
                        list(self.connections.keys()),
                        {"type": "presence", "user_id": user_id, **self.presence[user_id]},
                    )
                )


def init_messaging(
    app,
    *,
    db,
    users_collection,
    file_storage,
    get_current_user,
    ws_user_fetcher,
    jwt_secret: str,
):
    service = MessagingService(db, users_collection, file_storage, jwt_secret)
    router = APIRouter(prefix="/messaging", tags=["Messaging"])

    @router.get("/emotes", response_model=EmoteCatalogResponse)
    def emote_catalog():
        return EmoteCatalogResponse(categories=[EmoteCategoryModel(**category) for category in EMOTE_CATEGORIES])

    @router.post("/presence", status_code=204)
    async def update_presence(payload: PresencePayload, current_user=Depends(get_current_user)):
        await service.update_presence(current_user, payload.status)
        return {"status": payload.status}

    @router.get("/presence")
    def get_presence(current_user=Depends(get_current_user)):
        return service.get_presence_snapshot()

    @router.post("/rooms", response_model=RoomResponse)
    def create_room(payload: CreateRoomRequest, current_user=Depends(get_current_user)):
        return service.create_room(current_user, payload)

    @router.get("/rooms", response_model=List[RoomResponse])
    def list_rooms(current_user=Depends(get_current_user)):
        return service.list_rooms(current_user)

    @router.get("/rooms/{room_id}/messages", response_model=List[MessageResponse])
    def fetch_messages(
        room_id: str,
        limit: int = 50,
        before: Optional[str] = None,
        current_user=Depends(get_current_user),
    ):
        return service.get_messages(room_id, current_user, limit=limit, before=before)

    @router.post("/rooms/{room_id}/messages", response_model=MessageResponse)
    def post_message(room_id: str, payload: SendMessageRequest, current_user=Depends(get_current_user)):
        return service.send_message(room_id, current_user, payload)

    @router.post("/rooms/{room_id}/typing", status_code=204)
    def typing(room_id: str, payload: TypingPayload, current_user=Depends(get_current_user)):
        service.update_typing(room_id, current_user, payload.typing, payload.mode)

    @router.post("/rooms/{room_id}/delivery", status_code=204)
    def mark_delivery(room_id: str, payload: DeliveryPayload, current_user=Depends(get_current_user)):
        service.mark_delivery(room_id, current_user, payload.message_id)

    @router.post("/rooms/{room_id}/read", status_code=204)
    def mark_read(room_id: str, payload: ReadReceiptPayload, current_user=Depends(get_current_user)):
        service.mark_read(room_id, current_user, payload.message_id)

    @router.post("/attachments", response_model=AttachmentResponse)
    async def upload_attachment(
        kind: str = Form(...),
        file: UploadFile = File(...),
        current_user=Depends(get_current_user),
    ):
        if kind not in {
            AttachmentKind.TEXT,
            AttachmentKind.AUDIO,
            AttachmentKind.IMAGE,
            AttachmentKind.VIDEO,
            AttachmentKind.DOCUMENT,
            AttachmentKind.EMOTE,
        }:
            raise HTTPException(status_code=400, detail="Type de pièce jointe invalide")
        return await service.store_attachment(current_user, kind, file)

    @router.get("/attachments/{attachment_id}")
    def download_attachment(attachment_id: str, current_user=Depends(get_current_user)):
        doc = service.attachments.find_one({"_id": attachment_id})
        if not doc:
            raise HTTPException(status_code=404, detail="Pièce jointe introuvable")
        if doc.get("owner_id") != current_user["_id"]:
            room = service.rooms.find_one({
                "member_ids": current_user["_id"],
                "_id": {
                    "$in": [m.get("room_id") for m in service.messages.find({"attachments.attachment_id": attachment_id})],
                },
            })
            if not room:
                raise HTTPException(status_code=403, detail="Accès refusé")
        try:
            grid_file = service.files.get(doc["file_id"])
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=404, detail="Fichier introuvable") from exc
        return StreamingResponse(
            grid_file,
            media_type=doc.get("content_type", "application/octet-stream"),
            headers={"Content-Disposition": f"attachment; filename={doc.get('filename','file')}"},
        )

    app.include_router(router)

    @app.websocket("/ws/messaging")
    async def messaging_socket(websocket: WebSocket):
        await websocket.accept()
        user = await ws_user_fetcher(websocket)
        if not user:
            return
        user_id = str(user["_id"])
        await service.register_connection(user_id, websocket)
        await service.update_presence(user, "online")
        try:
            while True:
                data = await websocket.receive_text()
                try:
                    payload = json.loads(data)
                except json.JSONDecodeError:
                    await websocket.send_text(json.dumps({"type": "error", "detail": "Payload invalide"}))
                    continue
                if payload.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
                elif payload.get("type") == "presence":
                    status = payload.get("status", "online")
                    await service.update_presence(user, status)
                elif payload.get("type") == "typing":
                    service.update_typing(payload["room_id"], user, payload.get("typing", False), payload.get("mode", "text"))
        except WebSocketDisconnect:
            pass
        finally:
            await service.unregister_connection(user_id, websocket)
