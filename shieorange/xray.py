"""Full Bot API disguise X-Ray extractor, Unicode de-obfuscator, and safe image normalizer."""

from __future__ import annotations

import asyncio
import base64
import io
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Optional

from PIL import Image
from telegram import Message, MessageEntity

logger = logging.getLogger("shieorange.xray")

# Guard against decompression bombs & event-loop blocking during image transcoding
MAX_IMAGE_PIXELS = 25_000_000
MAX_IMAGE_BYTES = 5 * 1024 * 1024
_IMAGE_WORK_SEM: Optional[asyncio.Semaphore] = None


def _get_image_sem() -> asyncio.Semaphore:
    global _IMAGE_WORK_SEM
    if _IMAGE_WORK_SEM is None:
        _IMAGE_WORK_SEM = asyncio.Semaphore(2)
    return _IMAGE_WORK_SEM


def _transcode_jpeg_sync(raw_bytes: bytes) -> Optional[str]:
    """Check pixel dimensions before full decode, resize <=768px, and encode RGB JPEG."""
    if not raw_bytes or len(raw_bytes) > MAX_IMAGE_BYTES:
        return None
    with Image.open(io.BytesIO(raw_bytes)) as img:
        if (img.width * img.height) > MAX_IMAGE_PIXELS:
            logger.warning(
                "跳过超大像素图片 (%dx%d > %d pixels)",
                img.width,
                img.height,
                MAX_IMAGE_PIXELS,
            )
            return None
        # Downscale JPEG/PNG lazily via draft/thumbnail before full RGB conversion where possible
        img.thumbnail((768, 768))
        if img.mode in ("RGBA", "LA", "P"):
            bg = Image.new("RGB", img.size, (255, 255, 255))
            rgba = img.convert("RGBA")
            bg.paste(rgba, mask=rgba.split()[-1])
            out_img = bg
        else:
            out_img = img.convert("RGB")

        out = io.BytesIO()
        out_img.save(out, format="JPEG", quality=80, optimize=True)
        b64 = base64.b64encode(out.getvalue()).decode("ascii")
        return f"data:image/jpeg;base64,{b64}"

# Zero-width & invisible formatting characters commonly abused to bypass filters
_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u00ad\u034f\u061c\u180e]")
# Typical bulk-registered account display name: two arbitrary-length Latin alphabetic segments
# e.g. "aawsda sdawsda", "John Smith", "qwerty asdfgh"
_TWO_PART_LATIN_RE = re.compile(r"^[A-Za-z]{2,}\s+[A-Za-z]{2,}$")
_CONSONANT_CLUSTER_RE = re.compile(r"[bcdfghjklmnpqrstvwxz]{4,}", re.IGNORECASE)
_VOWEL_RE = re.compile(r"[aeiouy]", re.IGNORECASE)


def _looks_like_random_latin(full_name: str) -> bool:
    """Detect keyboard-mash / random-letter two-part names like 'aawsda sdawsda'."""
    parts = full_name.strip().split()
    if len(parts) != 2:
        return False
    # All-lowercase two-part Latin (e.g. "aawsda sdawsda") is a strong bulk-bot tell
    if all(p.islower() and len(p) >= 3 for p in parts):
        return True
    for p in parts:
        if len(p) >= 4 and not _VOWEL_RE.search(p):
            return True
        if _CONSONANT_CLUSTER_RE.search(p):
            return True
        # Same letter repeated 3+ times or very low character variety in long string
        if re.search(r"(.)\1\1", p, re.IGNORECASE):
            return True
    return False


def analyze_profile_risk(profile: dict[str, Any], clean_count: int = 0) -> tuple[list[str], int, bool]:
    """Additive profile risk scoring for blank/bulk-registered spam accounts.

    Each signal contributes independently, with two-part pure Latin names weighted highest:
      - Two-part random/gibberish Latin name (e.g. "aawsda sdawsda"): +12
      - Two-part regular Latin name (e.g. "John Smith"):              +10
      - No real profile photo (default letter avatar):                 +4
      - Empty profile (no bio and no personal channel):                +3
      - No @username set:                                              +2
    Full-hit (all 4 signals) sets is_max_risk=True (every message forced to AI, even after >=5 clean msgs).
    Note: The score boost is ONLY added when AI already flags suspicious intent (score >= 45),
    so normal conversations are never false-banned.
    """
    if not profile:
        return [], 0, False

    has_photo = profile.get("has_photo", True)
    full_name = str(profile.get("full_name", "") or "").strip()
    username = str(profile.get("username", "") or "").strip()
    bio = str(profile.get("bio", "") or "").strip()
    personal_channel = str(profile.get("personal_channel", "") or "").strip()

    no_avatar = has_photo is False
    two_part_latin = bool(_TWO_PART_LATIN_RE.match(full_name))
    random_latin = two_part_latin and _looks_like_random_latin(full_name)
    empty_profile = (not bio) and (not personal_channel)
    no_username = username in {"", "(无)"}

    full_hit = no_avatar and two_part_latin and empty_profile and no_username

    # Non-full-hit profiles are exempted once the member has >= 5 clean messages
    if not full_hit and clean_count >= 5:
        return [], 0, False

    flags: list[str] = []
    boost = 0

    if random_latin:
        flags.append("两段随机/无意义字母昵称(+12)")
        boost += 12
    elif two_part_latin:
        flags.append("两段纯字母昵称(+10)")
        boost += 10

    if no_avatar:
        flags.append("无真实头像(+4)")
        boost += 4

    if empty_profile:
        flags.append("主页Bio空白(+3)")
        boost += 3

    if no_username:
        flags.append("无@用户名(+2)")
        boost += 2

    return flags, boost, full_hit

# Executable/malware extensions frequently used in TG account-stealing scams
DANGEROUS_EXTENSIONS = (
    ".apk",
    ".exe",
    ".msi",
    ".scr",
    ".bat",
    ".cmd",
    ".vbs",
    ".ps1",
    ".dmg",
    ".jar",
    ".lnk",
)


def normalize_and_detect_obfuscation(text: str) -> tuple[str, list[str]]:
    """Strip zero-width characters, apply NFKC normalization, and flag obfuscation tricks."""
    if not text:
        return "", []

    flags: list[str] = []
    zw_matches = _ZERO_WIDTH_RE.findall(text)
    if zw_matches:
        flags.append(f"含{len(zw_matches)}个零宽隐形混淆字符")
    cleaned = _ZERO_WIDTH_RE.sub("", text)

    nfkc = unicodedata.normalize("NFKC", cleaned)
    # Detect full-width / stylized Unicode math/alphanumeric spoofing (excluding standard CJK punctuation)
    if nfkc != cleaned:
        diff_alnum = any(
            (a != b) and b.isascii() and b.isalnum()
            for a, b in zip(cleaned, nfkc)
        )
        if diff_alnum:
            flags.append("含全角/变形字母数字混淆")

    return nfkc, flags


@dataclass
class MessageXRay:
    is_edited: bool = False
    text: str = ""
    normalized_text: str = ""
    obfuscation_flags: list[str] = field(default_factory=list)
    hidden_links: list[str] = field(default_factory=list)
    plain_urls: list[str] = field(default_factory=list)
    mentions: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    custom_emojis: int = 0
    inline_buttons: list[str] = field(default_factory=list)
    via_bot: str = ""
    external_reply: str = ""
    is_reply: bool = False
    reply_preview: str = ""
    forward_from: str = ""
    sender_chat: str = ""
    sticker_info: str = ""
    poll_info: str = ""
    special_payload: str = ""
    dangerous_filename: str = ""
    media_type: str = ""

    def allow_shared_cache(self) -> bool:
        """Replies to another group message (including stickers/captionless media) never populate or hit shared spam cache."""
        return not self.is_reply

    def has_risk_signal(self) -> bool:
        return bool(
            self.is_edited
            or self.obfuscation_flags
            or self.hidden_links
            or self.plain_urls
            or self.inline_buttons
            or self.via_bot
            or self.external_reply
            or self.forward_from
            or self.sender_chat
            or self.poll_info
            or self.special_payload
            or self.dangerous_filename
            or self.media_type
            or self.mentions
            or self.commands
            or self.custom_emojis > 0
        )

    def build_preview(self) -> str:
        parts: list[str] = []
        if self.normalized_text or self.text:
            parts.append((self.normalized_text or self.text)[:220])
        if self.hidden_links:
            parts.append("隐藏链:" + " ".join(self.hidden_links)[:180])
        if self.inline_buttons:
            parts.append("按钮:" + " ".join(self.inline_buttons)[:150])
        if self.via_bot:
            parts.append(f"via:{self.via_bot}")
        if self.external_reply:
            parts.append(f"外引:{self.external_reply[:100]}")
        if self.poll_info:
            parts.append(f"投票:{self.poll_info[:100]}")
        if self.special_payload:
            parts.append(self.special_payload)
        if self.dangerous_filename:
            parts.append(f"高危文件:{self.dangerous_filename}")
        if self.media_type:
            parts.append(f"媒体:{self.media_type}")
        return " | ".join(parts) or "(空消息)"

    def format_for_ai(
        self,
        profile: dict[str, str],
        recent_context: list[str],
        user_fragments: list[str],
        clean_count: int,
        vision_attached: bool,
    ) -> str:
        rep = "新面孔" if clean_count < 3 else ("普通成员" if clean_count < 15 else "高活跃老群友")
        lines = [
            f"【用户信誉】: {rep}（本群历史正常发言 {clean_count} 次）",
            f"【是否编辑后的消息】: {'是（高危：事后修改）' if self.is_edited else '否'}",
            f"【发件人资料】: 昵称={profile.get('full_name', '')} | 用户名={profile.get('username', '(无)')}",
        ]
        if profile.get("bio"):
            lines.append(f"【发件人个人简介(Bio)】: {profile['bio']}")
        if profile.get("personal_channel"):
            lines.append(f"【发件人主页绑定频道】: {profile['personal_channel']}")
        if profile.get("personal_channel_bio"):
            lines.append(f"【发件人主页频道简介】: {profile['personal_channel_bio']}")
        profile_flags, profile_boost, is_max_risk = analyze_profile_risk(
            profile, clean_count=clean_count
        )
        if is_max_risk:
            lines.append(
                f"【最高风控画像·全命中 (+{profile_boost}分)】: {' + '.join(profile_flags)}（高度疑似批量广告协议号，请从严审核，仅正常聊天放行）"
            )
        elif profile_flags:
            lines.append(
                f"【账号画像风险信号 (+{profile_boost}分)】: {'、'.join(profile_flags)}（请结合发言内容综合判断）"
            )
        if self.obfuscation_flags:
            lines.append(f"【检测到字符混淆】: {', '.join(self.obfuscation_flags)}")
        if self.sender_chat:
            lines.append(f"【使用外部频道马甲发言】: {self.sender_chat}")
        if self.via_bot:
            lines.append(f"【通过外部内联机器人发送】: {self.via_bot}")
        if self.forward_from:
            lines.append(f"【转发来源】: {self.forward_from}")
        if self.external_reply:
            lines.append(f"【外部引用来源】: {self.external_reply}")
        if self.reply_preview:
            lines.append(f"【回复的群内消息】: {self.reply_preview}")
        if self.hidden_links:
            lines.append(f"【剥出的隐藏超链接】: {', '.join(self.hidden_links)}")
        if self.plain_urls:
            lines.append(f"【明文链接】: {', '.join(self.plain_urls)}")
        if self.inline_buttons:
            lines.append(f"【内联跳转按钮】: {', '.join(self.inline_buttons)}")
        if self.poll_info:
            lines.append(f"【投票内容】: {self.poll_info}")
        if self.special_payload:
            lines.append(f"【特殊消息载体】: {self.special_payload}")
        if self.dangerous_filename:
            lines.append(f"【高危可执行文件】: {self.dangerous_filename}")
        if self.mentions:
            lines.append(f"【@提及】: {', '.join(self.mentions)}")
        if self.commands:
            lines.append(f"【指令】: {', '.join(self.commands)}")
        if self.sticker_info:
            lines.append(f"【贴纸信息】: {self.sticker_info}")
        if self.media_type:
            note = "（已附带图片供视觉审查）" if vision_attached else "（当前未启用图片视觉审查）"
            lines.append(f"【附带媒体】: {self.media_type} {note}")

        effective_text = self.normalized_text or self.text
        body = (effective_text[:800] + "…") if len(effective_text) > 800 else (
            effective_text or "(无文字，请结合附带图片/贴纸/链接/外部引用/投票/资料判断)"
        )
        lines.append(f"【当前消息正文】:\n{body}")

        if user_fragments:
            lines.append(
                "【该用户近10分钟连续发言（排查拆分广告）】:\n"
                + "\n".join(f"- {f}" for f in user_fragments)
            )
        if recent_context:
            lines.append("【群内最近聊天上下文】:\n" + "\n".join(recent_context))

        return "\n".join(lines)

    def format_content_only_for_ai(self, *, vision_attached: bool) -> str:
        """Pure standalone message content prompt (ZERO sender profile, history, or chat context).

        Used exclusively before promoting a fingerprint into a shared same-group spam cache so
        one member's bio/fragments/context can NEVER cause another member to be auto-banned.
        """
        lines = [
            "【纯消息内容独立复核（不含发言人资料、历史发言与群聊上下文）】",
            "请仅依据以下单条消息内容本身（及附带图片）判断是否属于垃圾广告/引流/欺诈；"
            "若脱离发言人资料或上下文无法独立断定为垃圾广告，请判为正常(state=0，给低分)。",
        ]
        if self.obfuscation_flags:
            lines.append(f"【检测到字符混淆】: {', '.join(self.obfuscation_flags)}")
        if self.sender_chat:
            lines.append(f"【外部频道马甲】: {self.sender_chat}")
        if self.via_bot:
            lines.append(f"【外部内联机器人】: {self.via_bot}")
        if self.forward_from:
            lines.append(f"【转发来源】: {self.forward_from}")
        if self.external_reply:
            lines.append(f"【外部引用来源】: {self.external_reply}")
        if self.hidden_links:
            lines.append(f"【剥出的隐藏超链接】: {', '.join(self.hidden_links)}")
        if self.plain_urls:
            lines.append(f"【明文链接】: {', '.join(self.plain_urls)}")
        if self.inline_buttons:
            lines.append(f"【内联跳转按钮】: {', '.join(self.inline_buttons)}")
        if self.poll_info:
            lines.append(f"【投票内容】: {self.poll_info}")
        if self.special_payload:
            lines.append(f"【特殊消息载体】: {self.special_payload}")
        if self.dangerous_filename:
            lines.append(f"【高危可执行文件】: {self.dangerous_filename}")
        if self.mentions:
            lines.append(f"【@提及】: {', '.join(self.mentions)}")
        if self.commands:
            lines.append(f"【指令】: {', '.join(self.commands)}")
        if self.sticker_info:
            lines.append(f"【贴纸信息】: {self.sticker_info}")
        if self.media_type:
            note = "（已附带图片供视觉审查）" if vision_attached else "（当前未启用图片视觉审查）"
            lines.append(f"【附带媒体】: {self.media_type} {note}")

        effective_text = self.normalized_text or self.text
        body = (effective_text[:800] + "…") if len(effective_text) > 800 else (
            effective_text or "(无文字，请仅结合附带图片/贴纸/链接/外部引用/投票判断)"
        )
        lines.append(f"【当前消息正文】:\n{body}")
        return "\n".join(lines)


def _describe_origin(origin: Any) -> str:
    if not origin:
        return ""
    chat = getattr(origin, "chat", None) or getattr(origin, "sender_chat", None)
    if chat:
        title = getattr(chat, "title", "") or ""
        uname = f"@{chat.username}" if getattr(chat, "username", None) else ""
        return f"{title} {uname}".strip()
    user = getattr(origin, "sender_user", None)
    if user:
        uname = f"@{user.username}" if getattr(user, "username", None) else ""
        return f"{getattr(user, 'full_name', '')} {uname}".strip()
    hidden = getattr(origin, "sender_user_name", None)
    if hidden:
        return str(hidden)
    return str(getattr(origin, "type", "unknown"))


def _safe_slice_utf16(text: str, offset: int, length: int) -> str:
    if not text:
        return ""
    raw = text.encode("utf-16-le")
    return raw[offset * 2 : (offset + length) * 2].decode("utf-16-le", errors="ignore")


def extract_xray(msg: Any, is_edited: bool = False) -> MessageXRay:
    text = getattr(msg, "text", None) or getattr(msg, "caption", None) or ""
    normalized_text, obfuscation_flags = normalize_and_detect_obfuscation(text)

    entity_pairs: list[tuple[Any, str]] = []
    for ent in getattr(msg, "entities", None) or ():
        if hasattr(msg, "parse_entity"):
            try:
                seg = msg.parse_entity(ent)
            except Exception:
                seg = _safe_slice_utf16(getattr(msg, "text", "") or "", ent.offset, ent.length)
        else:
            seg = _safe_slice_utf16(getattr(msg, "text", "") or "", ent.offset, ent.length)
        entity_pairs.append((ent, seg))

    for ent in getattr(msg, "caption_entities", None) or ():
        if hasattr(msg, "parse_caption_entity"):
            try:
                seg = msg.parse_caption_entity(ent)
            except Exception:
                seg = _safe_slice_utf16(getattr(msg, "caption", "") or "", ent.offset, ent.length)
        else:
            seg = _safe_slice_utf16(getattr(msg, "caption", "") or "", ent.offset, ent.length)
        entity_pairs.append((ent, seg))

    hidden_links: list[str] = []
    plain_urls: list[str] = []
    mentions: list[str] = []
    commands: list[str] = []
    custom_emojis = 0

    for ent, seg in entity_pairs:
        etype = getattr(ent, "type", "")
        if etype == MessageEntity.TEXT_LINK and getattr(ent, "url", None):
            hidden_links.append(f"[{seg or '隐形字符'} -> {ent.url}]")
        elif etype == MessageEntity.URL:
            plain_urls.append(seg)
        elif etype == MessageEntity.MENTION:
            mentions.append(seg)
        elif etype == MessageEntity.TEXT_MENTION and getattr(ent, "user", None):
            mentions.append(f"{seg}(uid:{ent.user.id})")
        elif etype == MessageEntity.BOT_COMMAND:
            commands.append(seg)
        elif etype == MessageEntity.CUSTOM_EMOJI:
            custom_emojis += 1

    lpo = getattr(msg, "link_preview_options", None)
    if lpo and getattr(lpo, "url", None):
        hidden_links.append(f"[网页预览隐藏链接 -> {lpo.url}]")

    inline_buttons: list[str] = []
    markup = getattr(msg, "reply_markup", None)
    if markup and getattr(markup, "inline_keyboard", None):
        for row in markup.inline_keyboard:
            for btn in row:
                web_app = getattr(btn, "web_app", None)
                target = (
                    getattr(btn, "url", None)
                    or (getattr(web_app, "url", None) if web_app else None)
                    or getattr(btn, "callback_data", None)
                    or ""
                )
                inline_buttons.append(f"[{getattr(btn, 'text', '')} -> {target}]")

    via_bot = ""
    vb = getattr(msg, "via_bot", None)
    if vb:
        via_bot = f"@{vb.username}" if getattr(vb, "username", None) else getattr(vb, "full_name", "bot")

    external_reply = ""
    ext = getattr(msg, "external_reply", None)
    quote = getattr(msg, "quote", None)
    quote_text = getattr(quote, "text", "") or ""
    if ext:
        origin_desc = _describe_origin(getattr(ext, "origin", None))
        ext_chat = getattr(ext, "chat", None)
        if ext_chat:
            ctitle = getattr(ext_chat, "title", "") or ""
            cuser = f"@{ext_chat.username}" if getattr(ext_chat, "username", None) else ""
            origin_desc = f"{origin_desc} ({ctitle} {cuser})".strip()
        external_reply = f"来源:{origin_desc}; 引用:{quote_text[:200]}".strip()
    elif quote_text:
        external_reply = f"引用片段:{quote_text[:200]}"

    reply_preview = ""
    reply_msg = getattr(msg, "reply_to_message", None)
    is_reply = bool(
        reply_msg is not None and not getattr(reply_msg, "forum_topic_created", None)
    )
    if reply_msg:
        rtext = getattr(reply_msg, "text", None) or getattr(reply_msg, "caption", None) or ""
        if rtext:
            reply_preview = rtext[:160]

    forward_from = _describe_origin(getattr(msg, "forward_origin", None))

    sender_chat = ""
    sc = getattr(msg, "sender_chat", None)
    chat = getattr(msg, "chat", None)
    if sc and chat and getattr(sc, "id", None) != getattr(chat, "id", None):
        sc_title = getattr(sc, "title", "") or ""
        sc_user = f"@{sc.username}" if getattr(sc, "username", None) else ""
        sender_chat = f"{sc_title} {sc_user}".strip()

    # Poll / Story / Paid Media coverage
    poll_info = ""
    poll = getattr(msg, "poll", None)
    if poll:
        opts = [getattr(o, "text", "") for o in (getattr(poll, "options", None) or [])]
        poll_info = f"问题:{getattr(poll, 'question', '')} | 选项:{' / '.join(opts[:10])}"

    special_parts: list[str] = []
    if getattr(msg, "story", None):
        st_chat = getattr(msg.story, "chat", None)
        st_name = getattr(st_chat, "title", "") or getattr(st_chat, "username", "") if st_chat else ""
        special_parts.append(f"转发动态(Story:{st_name})")
    if getattr(msg, "paid_media", None):
        stars = getattr(msg.paid_media, "star_count", 0)
        special_parts.append(f"付费星币媒体({stars} Stars)")
    special_payload = ", ".join(special_parts)

    # Sticker, media & dangerous executable file detection
    sticker_info = ""
    media_type = ""
    dangerous_filename = ""
    if getattr(msg, "photo", None):
        media_type = "photo"
    elif getattr(msg, "sticker", None):
        media_type = "sticker"
        st = msg.sticker
        sticker_info = f"emoji={getattr(st, 'emoji', '') or ''}, set={getattr(st, 'set_name', '') or ''}"
    elif getattr(msg, "video", None):
        media_type = "video"
    elif getattr(msg, "animation", None):
        media_type = "gif"
    elif getattr(msg, "document", None):
        fname = getattr(msg.document, "file_name", "") or ""
        media_type = f"document({fname})"
        if fname.lower().endswith(DANGEROUS_EXTENSIONS):
            dangerous_filename = fname

    return MessageXRay(
        is_edited=is_edited,
        text=text[:1500],
        normalized_text=normalized_text[:1500],
        obfuscation_flags=obfuscation_flags,
        hidden_links=hidden_links[:10],
        plain_urls=plain_urls[:10],
        mentions=mentions[:10],
        commands=commands[:5],
        custom_emojis=custom_emojis,
        inline_buttons=inline_buttons[:10],
        via_bot=via_bot,
        external_reply=external_reply,
        is_reply=is_reply,
        reply_preview=reply_preview,
        forward_from=forward_from,
        sender_chat=sender_chat,
        sticker_info=sticker_info,
        poll_info=poll_info[:300],
        special_payload=special_payload,
        dangerous_filename=dangerous_filename,
        media_type=media_type,
    )


async def extract_image_data_url(bot: Any, msg: Message) -> Optional[str]:
    """Download photo/sticker/video thumbnail and normalize to <=768px RGB JPEG base64."""
    file_id: Optional[str] = None
    if msg.photo:
        chosen = msg.photo[-1]
        for p in msg.photo:
            if p.width >= 640 or p.height >= 640:
                chosen = p
                break
        file_id = chosen.file_id
    elif msg.sticker:
        if msg.sticker.thumbnail:
            file_id = msg.sticker.thumbnail.file_id
        elif not msg.sticker.is_animated and not msg.sticker.is_video:
            file_id = msg.sticker.file_id
    elif msg.video and msg.video.thumbnail:
        file_id = msg.video.thumbnail.file_id
    elif msg.animation and msg.animation.thumbnail:
        file_id = msg.animation.thumbnail.file_id
    elif msg.document and msg.document.thumbnail:
        file_id = msg.document.thumbnail.file_id
    elif msg.document and (msg.document.mime_type or "").startswith("image/"):
        if (msg.document.file_size or 0) <= 5 * 1024 * 1024:
            file_id = msg.document.file_id

    if not file_id:
        return None

    try:
        async with _get_image_sem():
            tg_file = await bot.get_file(file_id)
            if (getattr(tg_file, "file_size", None) or 0) > MAX_IMAGE_BYTES:
                return None
            buf = io.BytesIO()
            await tg_file.download_to_memory(out=buf)
            raw_bytes = buf.getvalue()
            if not raw_bytes:
                return None
            return await asyncio.to_thread(_transcode_jpeg_sync, raw_bytes)
    except Exception as exc:
        logger.debug("提取图片缩略图失败（忽略识图）: %s", exc)
        return None
