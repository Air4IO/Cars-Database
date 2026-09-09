from pathlib import Path
import os
import re
import time
import json
import threading
import hashlib
import hmac
import base64
import secrets
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from io import BytesIO
from urllib.parse import quote

import pandas as pd
import gspread

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload

from fastapi import FastAPI, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel


# ============================================================
# CONFIG
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

# ============================================================
# USER AUTHENTICATION - GOOGLE SHEETS
# ============================================================

GOOGLE_SHEET_ID = os.getenv(
    "GOOGLE_SHEET_ID",
    "1wW_eL9ZrmfV2uc7Nnd32J4e46L8t_R6JsKGiVmecLFY",
).strip()
GOOGLE_USERS_TAB = os.getenv("GOOGLE_USERS_TAB", "Users").strip()
SERVICE_ACCOUNT_FILE = os.getenv(
    "GOOGLE_SERVICE_ACCOUNT_FILE",
    str(BASE_DIR / "service_account.json"),
)
AUTH_SECRET_FILE = Path(
    os.getenv("AUTH_SECRET_FILE", str(BASE_DIR / ".auth_secret"))
)
TOKEN_EXPIRE_HOURS = int(os.getenv("TOKEN_EXPIRE_HOURS", "12"))
USERS_SHEET_CACHE_SECONDS = int(os.getenv("USERS_SHEET_CACHE_SECONDS", "30"))


def _load_or_create_auth_secret():
    env_secret = os.getenv("AUTH_SECRET", "").strip()
    if env_secret:
        return env_secret.encode("utf-8")
    if AUTH_SECRET_FILE.exists():
        return AUTH_SECRET_FILE.read_bytes()
    secret = secrets.token_bytes(32)
    AUTH_SECRET_FILE.write_bytes(secret)
    return secret


AUTH_SECRET = _load_or_create_auth_secret()
_users_sheet_lock = threading.RLock()
_users_sheet = None
_users_cache = []
_users_cache_at = 0.0


def _get_users_worksheet():
    global _users_sheet
    with _users_sheet_lock:
        if _users_sheet is not None:
            return _users_sheet
        if not Path(SERVICE_ACCOUNT_FILE).exists():
            raise RuntimeError(f"Google service account file not found: {SERVICE_ACCOUNT_FILE}")
        credentials = service_account.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_FILE,
            scopes=[
                "https://www.googleapis.com/auth/spreadsheets",
                "https://www.googleapis.com/auth/drive.readonly",
            ],
        )
        gc = gspread.authorize(credentials)
        _users_sheet = gc.open_by_key(GOOGLE_SHEET_ID).worksheet(GOOGLE_USERS_TAB)
        return _users_sheet


def _load_users(force=False):
    global _users_cache, _users_cache_at
    now = time.time()
    with _users_sheet_lock:
        if not force and _users_cache and now - _users_cache_at < USERS_SHEET_CACHE_SECONDS:
            return list(_users_cache)
        ws = _get_users_worksheet()
        rows = ws.get_all_records()
        records = []
        for row in rows:
            records.append({str(k).strip(): row.get(k, "") for k in row.keys()})
        _users_cache = records
        _users_cache_at = now
        return list(records)


def _read_user(username: str, force=False):
    target = str(username or "").strip().casefold()
    if not target:
        return None
    for row in _load_users(force=force):
        if str(row.get("username", "")).strip().casefold() == target:
            active_raw = str(row.get("active", "TRUE")).strip().casefold()
            row["active"] = 1 if active_raw in {"1", "true", "yes", "y", "active"} else 0
            row["role"] = str(row.get("role", "user")).strip() or "user"
            row["allowed_brands"] = str(row.get("allowed_brands", "ALL")).strip() or "ALL"
            row["username"] = str(row.get("username", "")).strip()
            row["password_hash"] = str(row.get("password_hash", "")).strip()
            return row
    return None


def _update_last_login(username: str):
    try:
        ws = _get_users_worksheet()
        headers = [str(x).strip() for x in ws.row_values(1)]
        if "last_login" not in headers:
            return
        username_col = headers.index("username") + 1
        last_login_col = headers.index("last_login") + 1
        usernames = ws.col_values(username_col)
        target = str(username).strip().casefold()
        for row_num, value in enumerate(usernames[1:], start=2):
            if str(value).strip().casefold() == target:
                ws.update_cell(row_num, last_login_col, datetime.now().isoformat(timespec="seconds"))
                break
        _load_users(force=True)
    except Exception:
        # Login should not fail merely because last_login is unavailable.
        pass


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt_hex, hash_hex = stored_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        calculated = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations),
        )
        return hmac.compare_digest(calculated, bytes.fromhex(hash_hex))
    except Exception:
        return False


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def create_access_token(user: dict) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user["username"],
        "role": user["role"],
        "allowed_brands": user["allowed_brands"],
        "exp": int((now + timedelta(hours=TOKEN_EXPIRE_HOURS)).timestamp()),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload_part = _b64encode(payload_bytes)
    signature = hmac.new(AUTH_SECRET, payload_part.encode("ascii"), hashlib.sha256).digest()
    return f"{payload_part}.{_b64encode(signature)}"


def decode_access_token(token: str) -> dict:
    try:
        payload_part, signature_part = token.split(".", 1)
        expected_signature = hmac.new(AUTH_SECRET, payload_part.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected_signature, _b64decode(signature_part)):
            raise ValueError("Invalid signature")
        payload = json.loads(_b64decode(payload_part).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(datetime.now(timezone.utc).timestamp()):
            raise ValueError("Token expired")
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired login token")


def _get_token_from_request(authorization: str | None, token: str | None) -> str:
    if authorization:
        prefix = "Bearer "
        if authorization.startswith(prefix):
            return authorization[len(prefix):].strip()
    if token:
        return token.strip()
    raise HTTPException(status_code=401, detail="Login required")


def current_user(
    authorization: str | None = Header(default=None),
    token: str | None = Query(default=None),
):
    access_token = _get_token_from_request(authorization, token)
    payload = decode_access_token(access_token)
    user = _read_user(payload.get("sub", ""), force=True)
    if not user or user["active"] != 1:
        raise HTTPException(status_code=401, detail="User is inactive or no longer exists")
    return {
        "username": user["username"],
        "role": user["role"],
        "allowed_brands": user["allowed_brands"],
    }


def allowed_brand_set(user: dict):
    if user["role"] == "admin":
        return None

    raw = (user.get("allowed_brands") or "").strip()

    if not raw or raw.upper() == "ALL":
        return None

    return {
        item.strip().casefold()
        for item in raw.split(",")
        if item.strip()
    }


def user_can_access_brand(user: dict, brand: str | None) -> bool:
    allowed = allowed_brand_set(user)

    if allowed is None:
        return True

    return (brand or "").strip().casefold() in allowed


def require_admin(user: dict):
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )
    return user


def image_url(path: str, access_token: str | None = None) -> str:
    url = (
        API_PUBLIC_URL
        + "/image-by-path?path="
        + quote(str(path), safe="")
    )

    if access_token:
        url += "&token=" + quote(access_token, safe="")

    return url



CLIP_CSV_FILENAME = "final_cleaned_B2C 68_merged.csv"

# Show only these classified image types
ALLOWED_IMAGE_TYPES = {"coil", "dirty water"}
MAX_IMAGES_PER_CASE = 5

SERVICE_ACCOUNT_FILE = Path(
    os.getenv(
        "GOOGLE_SERVICE_ACCOUNT_FILE",
        str(BASE_DIR / "service_account.json"),
    )
)

# Public API URL used when the backend builds image URLs returned to the browser.
# Local default keeps the current local workflow unchanged.
API_PUBLIC_URL = os.getenv(
    "API_PUBLIC_URL",
    "http://127.0.0.1:8000",
).rstrip("/")

# ใส่ Folder ID ของ Shared folder ที่เก็บรูปทั้งหมด
DRIVE_ROOT_FOLDER_ID = (
    "11r6rLHnNFUj15KsJ1A5ebDERyQWKWjMC"
)

# ไฟล์ index ที่สร้างจาก folder จริง
DRIVE_INDEX_FILE = Path(
    os.getenv(
        "DRIVE_INDEX_FILE",
        str(BASE_DIR / "drive_path_index.json"),
    )
)

# Master copy of the Drive index stored privately in Google Drive.
# Local development will still use the local drive_path_index.json when it exists.
# On Render/another ephemeral host, the API downloads this file automatically
# when the local copy is missing.
DRIVE_INDEX_FILE_ID = os.getenv(
    "DRIVE_INDEX_FILE_ID",
    "1pSKJl4Ae161s4lkAzE3v9PMXWbA0dpYb",
).strip()

# ------------------------------------------------------------
# IMAGE DELIVERY OPTIMIZATION
# ------------------------------------------------------------
# รูปที่เคยโหลดสำเร็จจะถูกเก็บไว้ในเครื่อง
IMAGE_CACHE_DIR = BASE_DIR / "image_cache"
IMAGE_CACHE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

# จำกัดจำนวนการ download จาก Google Drive พร้อมกัน
# เพื่อป้องกัน SSL/connection หลุดเมื่อ browser ขอหลายรูปพร้อมกัน
MAX_CONCURRENT_DRIVE_DOWNLOADS = 3
DRIVE_DOWNLOAD_SEMAPHORE = threading.BoundedSemaphore(
    MAX_CONCURRENT_DRIVE_DOWNLOADS
)

# แยก Google Drive client ต่อ thread
# ป้องกัน httplib2/SSL connection ถูกหลาย request ใช้พร้อมกัน
_DRIVE_THREAD_LOCAL = threading.local()

SCOPES = [
    "https://www.googleapis.com/auth/drive.readonly"
]

IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".gif",
    ".bmp",
    ".tif",
    ".tiff",
}


# ============================================================
# MODEL -> BRAND
# ============================================================

MODEL_TO_BRAND = {

    # Toyota
    "fortuner": "Toyota",
    "revo": "Toyota",
    "hilux": "Toyota",
    "camry": "Toyota",
    "corolla": "Toyota",
    "corolla cross": "Toyota",
    "yaris": "Toyota",
    "yaris ativ": "Toyota",
    "vios": "Toyota",
    "altis": "Toyota",
    "avanza": "Toyota",
    "innova": "Toyota",
    "sienta": "Toyota",
    "chr": "Toyota",
    "c-hr": "Toyota",

    # Nissan
    "kicks": "Nissan",
    "kick": "Nissan",
    "navara": "Nissan",
    "almera": "Nissan",
    "march": "Nissan",
    "teana": "Nissan",
    "x-trail": "Nissan",
    "terra": "Nissan",
    "note": "Nissan",

    # Isuzu
    "d-max": "Isuzu",
    "dmax": "Isuzu",
    "mu-x": "Isuzu",
    "mux": "Isuzu",

    # Suzuki
    "carry": "Suzuki",
    "swift": "Suzuki",
    "ciaz": "Suzuki",
    "ertiga": "Suzuki",
    "xl7": "Suzuki",
    "celerio": "Suzuki",

    # Chevrolet
    "sonic": "Chevrolet",
    "cruze": "Chevrolet",
    "captiva": "Chevrolet",
    "trailblazer": "Chevrolet",
    "colorado": "Chevrolet",

    # Mitsubishi
    "pajero": "Mitsubishi",
    "pajero sport": "Mitsubishi",
    "triton": "Mitsubishi",
    "mirage": "Mitsubishi",
    "attrage": "Mitsubishi",
    "xpander": "Mitsubishi",

    # Honda
    "civic": "Honda",
    "city": "Honda",
    "jazz": "Honda",
    "br-v": "Honda",
    "brio": "Honda",
    "hr-v": "Honda",
    "hrv": "Honda",
    "cr-v": "Honda",
    "crv": "Honda",
    "mobilio": "Honda",

    # Mazda
    "mazda2": "Mazda",
    "mazda 2": "Mazda",
    "mazda3": "Mazda",
    "mazda 3": "Mazda",
    "cx-3": "Mazda",
    "cx-30": "Mazda",
    "cx-5": "Mazda",
    "cx-8": "Mazda",

    # Ford
    "ranger": "Ford",
    "everest": "Ford",
    "ecosport": "Ford",
    "mustang": "Ford",

    # MG
    "zs": "MG",
    "mg3": "MG",
    "mg5": "MG",
    "mg6": "MG",
    "mg hs": "MG",

    # Hyundai
    "h-1": "Hyundai",
    "h1": "Hyundai",
    "stargazer": "Hyundai",
    "creta": "Hyundai",
    "tucson": "Hyundai",

    # Kia
    "picanto": "Kia",
    "rio": "Kia",
    "sorento": "Kia",
    "sportage": "Kia",
}


BRANDS = sorted(
    {
        *MODEL_TO_BRAND.values(),
        "Mercedes-Benz",
        "Mercedes",
        "Audi",
        "Volvo",
        "Volkswagen",
        "Subaru",
        "BMW",
    },
    key=len,
    reverse=True,
)


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="Car AC Case API"
)

# Local development:
# The HTML may be opened directly as file:// (Origin: null)
# or served from a local web server on another port.
# Default "*" keeps local testing simple.
#
# Production/Render:
# Set ALLOWED_ORIGINS to a comma-separated list, e.g.
# ALLOWED_ORIGINS=https://your-domain.com,https://www.your-domain.com

_allowed_origins_raw = os.getenv("ALLOWED_ORIGINS", "*").strip()

if _allowed_origins_raw == "*":
    ALLOWED_ORIGINS = ["*"]
else:
    ALLOWED_ORIGINS = [
        item.strip()
        for item in _allowed_origins_raw.split(",")
        if item.strip()
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)


# ============================================================
# GOOGLE DRIVE
# ============================================================

def execute_with_retry(
    request,
    max_retries=5,
):

    last_error = None

    for attempt in range(
        1,
        max_retries + 1,
    ):

        try:
            return request.execute()

        except Exception as e:

            last_error = e

            wait_seconds = (
                attempt * 2
            )

            print(
                "[Drive API] "
                f"เชื่อมต่อหลุด "
                f"(ครั้งที่ "
                f"{attempt}/{max_retries}): "
                f"{e} "
                f"-> รออีก "
                f"{wait_seconds} วิ "
                f"แล้วลองใหม่"
            )

            time.sleep(
                wait_seconds
            )

    raise last_error


def get_drive():

    # ใช้ Drive client แยกต่อ thread
    # ไม่แชร์ HTTP connection เดียวกันระหว่างหลาย image requests

    drive = getattr(
        _DRIVE_THREAD_LOCAL,
        "drive",
        None,
    )

    if drive is not None:
        return drive

    if not SERVICE_ACCOUNT_FILE.exists():

        raise RuntimeError(
            "ไม่พบไฟล์ "
            f"{SERVICE_ACCOUNT_FILE}"
        )

    credentials = (
        service_account
        .Credentials
        .from_service_account_file(
            str(
                SERVICE_ACCOUNT_FILE
            ),
            scopes=SCOPES,
        )
    )

    drive = build(
        "drive",
        "v3",
        credentials=credentials,
        cache_discovery=False,
    )

    _DRIVE_THREAD_LOCAL.drive = drive

    return drive


# ============================================================
# STRING HELPERS
# ============================================================

def clean(value):

    if value is None:
        return None

    try:

        if pd.isna(value):
            return None

    except Exception:
        pass

    return value


def norm(value):

    if value is None:
        return ""

    value = (
        str(value)
        .replace("\\", "/")
        .replace("\u00a0", " ")
        .replace("\u200b", "")
    )

    return re.sub(
        r"\s+",
        " ",
        value,
    ).strip()


def norm_path(value):

    value = norm(value)

    while value.startswith("./"):
        value = value[2:]

    value = re.sub(
        r"/+",
        "/",
        value,
    )

    return value.strip(
        "/"
    ).lower()


def is_image_file(
    file_info
):

    mime = str(
        file_info.get(
            "mimeType",
            "",
        )
    ).lower()

    name = str(
        file_info.get(
            "name",
            "",
        )
    )

    return (
        mime.startswith("image/")
        or Path(
            name
        ).suffix.lower()
        in IMAGE_EXTENSIONS
    )


def case_folder(
    image_path
):

    parts = [
        p.strip()
        for p in norm(
            image_path
        ).split("/")
        if p.strip()
    ]

    for part in parts:

        if re.search(
            r"\bAP\d{2}-\d+\b",
            part,
            re.I,
        ):

            return part

    return ""


def remove_notes(
    value
):

    value = re.sub(
        r"\([^)]*\)",
        " ",
        value,
    )

    value = re.sub(
        r"\[[^\]]*\]",
        " ",
        value,
    )

    return re.sub(
        r"\s+",
        " ",
        value,
    ).strip()


# ============================================================
# BRAND / MODEL / YEAR
# ============================================================

def find_brand(
    value
):

    low = norm(
        value
    ).lower()

    for brand in BRANDS:

        if re.search(
            r"(?<![A-Za-z])"
            + re.escape(
                brand.lower()
            )
            + r"(?![A-Za-z])",
            low,
        ):

            return brand

    return None


def find_year(
    value
):

    for year in re.findall(
        r"(?<!\d)"
        r"(19\d{2}|20\d{2})"
        r"(?!\d)",
        value,
    ):

        year = int(year)

        if (
            1980
            <= year
            <= 2035
        ):

            return year

    return None


def find_model(
    value,
    brand=None,
):

    low = remove_notes(
        value
    ).lower()

    for model in sorted(
        MODEL_TO_BRAND,
        key=len,
        reverse=True,
    ):

        if re.search(
            r"(?<![a-z0-9])"
            + re.escape(
                model.lower()
            )
            + r"(?![a-z0-9])",
            low,
        ):

            model_brand = (
                MODEL_TO_BRAND[
                    model
                ]
            )

            if (
                brand is None
                or model_brand.lower()
                == brand.lower()
            ):

                return model

    return None


def parse_case(
    folder
):

    text = norm(
        folder
    )

    match = re.search(
        r"\b(AP\d{2}-\d+)\b",
        text,
        re.I,
    )

    case_id = (
        match.group(1).upper()
        if match
        else None
    )

    if match:

        rest = (
            text[:match.start()]
            + " "
            + text[match.end():]
        )

    else:

        rest = text

    brand = find_brand(
        rest
    )

    model = find_model(
        rest,
        brand,
    )

    # สำคัญ:
    # ถ้าเจอ model แต่ไม่ได้เขียน brand
    # ให้เดา brand จาก model
    if (
        brand is None
        and model
    ):

        brand = MODEL_TO_BRAND.get(
            model.lower()
        )

    year = find_year(
        rest
    )

    customer = None

    if brand:

        match_brand = re.search(
            re.escape(brand),
            rest,
            re.I,
        )

        if match_brand:

            customer = (
                rest[
                    :match_brand.start()
                ].strip()
                or None
            )

    elif model:

        match_model = re.search(
            re.escape(model),
            rest,
            re.I,
        )

        if match_model:

            customer = (
                rest[
                    :match_model.start()
                ].strip()
                or None
            )

    return {
        "case_id": case_id,
        "customer": customer,
        "brand": brand,
        "model": (
            model.title()
            if model
            else None
        ),
        "year": year,
    }


# ============================================================
# CSV
# ============================================================

@lru_cache(maxsize=1)
def load_df():

    csv_path = (
        BASE_DIR
        / CLIP_CSV_FILENAME
    )

    if not csv_path.exists():

        raise RuntimeError(
            "ไม่เจอไฟล์ "
            f"{CLIP_CSV_FILENAME}"
        )

    df = pd.read_csv(
        csv_path
    )

    required = {
        "Image",
        "Category",
    }

    missing = (
        required
        - set(df.columns)
    )

    if missing:

        raise RuntimeError(
            "CLIP CSV ขาด column: "
            + ", ".join(
                sorted(missing)
            )
        )

    return df


def row_text(row, key):
    value = clean(row.get(key))
    if value is None:
        return None
    value = str(value).strip()
    return value if value else None

def image_record(
    row
):
    path = clean(row.get("Image"))
    if not path:
        return None

    category = row_text(row, "Category") or "Other"
    if category.strip().lower() not in ALLOWED_IMAGE_TYPES:
        return None

    folder = case_folder(path)
    parsed = parse_case(folder)

    # Prefer the case_id and job-order fields already merged into the CSV.
    csv_case_id = row_text(row, "case_id")
    case_id = (csv_case_id or parsed["case_id"] or "").upper() or None

    return {
        "case_id": case_id,
        "customer": parsed["customer"],
        "brand": row_text(row, "brand") or parsed["brand"],
        "model": row_text(row, "model") or parsed["model"],
        "year": parsed["year"],
        "case_folder": folder,
        "received_date": row_text(row, "received_date"),
        "appointment_date": row_text(row, "appointment_date"),
        "mileage": row_text(row, "mileage"),
        "low_before": row_text(row, "low_before"),
        "low_after": row_text(row, "low_after"),
        "high_before": row_text(row, "high_before"),
        "high_after": row_text(row, "high_after"),
        "name": str(path).replace("\\", "/").split("/")[-1],
        "path": str(path),
        "type": category,
        "score": clean(row.get("Score")),
        "top2": clean(row.get("Top2")),
        "top3": clean(row.get("Top3")),
        "width": clean(row.get("Width")),
        "height": clean(row.get("Height")),
        "zip": clean(row.get("ZIP")),
    }


@lru_cache(maxsize=1)
def build_cases():

    cases = {}

    print("[Build cases] เริ่มอ่านข้อมูลจาก CSV...")
    rows = load_df().to_dict("records")
    total_rows = len(rows)

    for row_number, row in enumerate(rows, start=1):
        image = image_record(row)
        if not image or not image["case_id"]:
            continue

        case_id = image["case_id"]

        if case_id not in cases:
            cases[case_id] = {
                "case_id": case_id,
                "customer": image["customer"],
                "brand": image["brand"],
                "model": image["model"],
                "year": image["year"],
                "case_folder": image["case_folder"],
                "received_date": image["received_date"],
                "appointment_date": image["appointment_date"],
                "mileage": image["mileage"],
                "low_before": image["low_before"],
                "low_after": image["low_after"],
                "high_before": image["high_before"],
                "high_after": image["high_after"],
                "images": [],
            }

        case = cases[case_id]

        # Fill blanks from any later row of the same case.
        for key in (
            "customer", "brand", "model", "year",
            "received_date", "appointment_date", "mileage",
            "low_before", "low_after", "high_before", "high_after",
        ):
            if case.get(key) is None and image.get(key) is not None:
                case[key] = image[key]

        # Keep only Coil and Dirty Water images, maximum 5 per case.
        if len(case["images"]) < MAX_IMAGES_PER_CASE:
            case["images"].append(image)

        if row_number % 5000 == 0:
            print(f"[Build cases] {row_number:,}/{total_rows:,} rows | {len(cases):,} cases")

    print(f"[Build cases] DONE: {len(cases):,} cases from {total_rows:,} rows")
    return cases


# ============================================================
# DRIVE FOLDER SCAN
# ============================================================

_index_lock = threading.Lock()


def list_drive_children(
    folder_id
):

    files = []

    token = None

    while True:

        response = (
            execute_with_retry(
                get_drive()
                .files()
                .list(
                    q=(
                        f"'{folder_id}' "
                        "in parents "
                        "and trashed=false"
                    ),
                    fields=(
                        "nextPageToken,"
                        "files("
                        "id,"
                        "name,"
                        "mimeType"
                        ")"
                    ),
                    pageSize=1000,
                    pageToken=token,
                    supportsAllDrives=True,
                    includeItemsFromAllDrives=True,
                )
            )
        )

        files.extend(
            response.get(
                "files",
                [],
            )
        )

        token = response.get(
            "nextPageToken"
        )

        if not token:
            break

    return files


def build_drive_path_index(
    force=False
):

    """
    Scan เฉพาะ DRIVE_ROOT_FOLDER_ID
    แบบ recursive

    index:
        normalized relative path
        ->
        Drive file info
    """

    with _index_lock:

        if (
            DRIVE_INDEX_FILE.exists()
            and not force
        ):

            try:

                existing = json.loads(
                    DRIVE_INDEX_FILE.read_text(
                        encoding="utf-8"
                    )
                )

                if (
                    isinstance(
                        existing,
                        dict,
                    )
                    and existing
                ):

                    print(
                        "[Drive Index] "
                        "โหลด index เดิม: "
                        f"{len(existing):,} files"
                    )

                    return existing

            except Exception as e:

                print(
                    "[Drive Index] "
                    f"index เดิมอ่านไม่ได้: {e}"
                )

        print(
            "[Drive Index] "
            "เริ่ม scan folder..."
        )

        print(
            "[Drive Index] Root: "
            f"{DRIVE_ROOT_FOLDER_ID}"
        )

        index = {}

        folder_count = 0
        image_count = 0

        def walk(
            folder_id,
            current_path="",
        ):

            nonlocal folder_count
            nonlocal image_count

            folder_count += 1

            if (
                folder_count
                % 100
                == 0
            ):

                print(
                    "[Drive Index] "
                    f"folders="
                    f"{folder_count:,} | "
                    f"images="
                    f"{image_count:,}"
                )

            children = (
                list_drive_children(
                    folder_id
                )
            )

            for file_info in children:

                name = file_info.get(
                    "name",
                    "",
                )

                if not name:
                    continue

                relative_path = (
                    f"{current_path}/{name}"
                    if current_path
                    else name
                )

                mime = str(
                    file_info.get(
                        "mimeType",
                        "",
                    )
                )

                # Folder
                if (
                    mime
                    == "application/"
                    "vnd.google-apps.folder"
                ):

                    walk(
                        file_info["id"],
                        relative_path,
                    )

                    continue

                # Image
                if not is_image_file(
                    file_info
                ):
                    continue

                key = norm_path(
                    relative_path
                )

                index[
                    key
                ] = {

                    "id":
                        file_info["id"],

                    "name":
                        name,

                    "path":
                        relative_path,

                    "mimeType":
                        mime,
                }

                image_count += 1

        walk(
            DRIVE_ROOT_FOLDER_ID
        )

        DRIVE_INDEX_FILE.write_text(
            json.dumps(
                index,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        print(
            "[Drive Index] DONE"
        )

        print(
            "[Drive Index] "
            f"folders="
            f"{folder_count:,}"
        )

        print(
            "[Drive Index] "
            f"images="
            f"{image_count:,}"
        )

        print(
            "[Drive Index] saved: "
            f"{DRIVE_INDEX_FILE}"
        )

        return index


@lru_cache(maxsize=1)
def load_drive_path_index():

    if not DRIVE_INDEX_FILE.exists():
        return {}

    try:

        data = json.loads(
            DRIVE_INDEX_FILE.read_text(
                encoding="utf-8"
            )
        )

        if isinstance(
            data,
            dict,
        ):

            return data

    except Exception as e:

        print(
            "[Drive Index] "
            f"โหลดไม่ได้: {e}"
        )

    return {}


def download_drive_index_from_google_drive(force=False):

    """
    Download the master drive_path_index.json from Google Drive.

    This is used when the deployment filesystem does not contain a local
    index (for example after a Render Free instance restart). The downloaded
    copy is only a local cache; Google Drive remains the source of truth.
    """

    if not DRIVE_INDEX_FILE_ID:
        return False

    if DRIVE_INDEX_FILE.exists() and not force:
        return True

    DRIVE_INDEX_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp_file = DRIVE_INDEX_FILE.with_suffix(DRIVE_INDEX_FILE.suffix + ".tmp")

    print(
        "[Drive Index] Download master index from Google Drive: "
        f"{DRIVE_INDEX_FILE_ID}"
    )

    try:
        drive = get_drive()

        metadata = drive.files().get(
            fileId=DRIVE_INDEX_FILE_ID,
            fields="id,name,mimeType,size",
            supportsAllDrives=True,
        ).execute()

        if str(metadata.get("mimeType", "")) != "application/json":
            raise RuntimeError(
                "drive_path_index file on Google Drive is not JSON: "
                f"{metadata.get('mimeType')}"
            )

        request = drive.files().get_media(
            fileId=DRIVE_INDEX_FILE_ID,
            supportsAllDrives=True,
        )

        with open(temp_file, "wb") as fh:
            downloader = MediaIoBaseDownload(fh, request, chunksize=1024 * 1024)
            done = False
            while not done:
                _, done = downloader.next_chunk()

        # Validate before replacing the active index.
        with open(temp_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        if not isinstance(data, dict) or not data:
            raise RuntimeError("Downloaded Drive index is empty or invalid")

        temp_file.replace(DRIVE_INDEX_FILE)

        print(
            "[Drive Index] Downloaded successfully: "
            f"{len(data):,} files"
        )
        return True

    except Exception as e:
        try:
            if temp_file.exists():
                temp_file.unlink()
        except Exception:
            pass

        print(
            "[Drive Index] Download failed: "
            f"{e}"
        )
        return False


def ensure_drive_index():

    # 1. Prefer a local cached copy.
    index = load_drive_path_index()
    if index:
        return index

    # 2. If deployment has no local copy, restore it from the private
    #    Google Drive master copy.
    if download_drive_index_from_google_drive():
        load_drive_path_index.cache_clear()
        index = load_drive_path_index()
        if index:
            return index

    # 3. Last resort: build a new index by scanning the Drive tree.
    #    This keeps the API recoverable even if the master index is unavailable.
    index = build_drive_path_index()
    load_drive_path_index.cache_clear()
    return index


# ============================================================
# MATCH CSV PATH -> DRIVE FILE
# ============================================================

@lru_cache(maxsize=50000)
def find_drive_file(
    image_path
):

    if not image_path:
        return None

    csv_path = norm_path(
        image_path
    )

    if not csv_path:
        return None

    index = (
        ensure_drive_index()
    )

    # --------------------------------------------------------
    # 1. Exact full path
    # --------------------------------------------------------

    result = index.get(
        csv_path
    )

    if result:
        return result

    # --------------------------------------------------------
    # 2. Suffix path
    # --------------------------------------------------------

    suffix_matches = []

    for (
        drive_path,
        file_info
    ) in index.items():

        if (
            csv_path.endswith(
                "/" + drive_path
            )
            or drive_path.endswith(
                "/" + csv_path
            )
        ):

            suffix_matches.append(
                file_info
            )

            if (
                len(
                    suffix_matches
                )
                > 1
            ):

                break

    if (
        len(
            suffix_matches
        )
        == 1
    ):

        return suffix_matches[0]

    # --------------------------------------------------------
    # 3. Filename fallback
    #
    # ใช้เฉพาะกรณี filename unique
    # --------------------------------------------------------

    filename = (
        csv_path
        .split("/")[-1]
    )

    filename_matches = []

    for (
        drive_path,
        file_info
    ) in index.items():

        if (
            drive_path
            .split("/")[-1]
            == filename
        ):

            filename_matches.append(
                file_info
            )

            if (
                len(
                    filename_matches
                )
                > 1
            ):

                break

    if (
        len(
            filename_matches
        )
        == 1
    ):

        return filename_matches[0]

    return None


# ============================================================
# IMAGE
# ============================================================

def _cache_path(file_id):
    """
    สร้างชื่อ cache จาก Drive file ID
    เพื่อไม่ให้ชื่อไฟล์ภาษาไทย/อักขระพิเศษมีปัญหา
    """
    cache_name = (
        hashlib.sha256(
            file_id.encode("utf-8")
        ).hexdigest()[:40]
        + ".bin"
    )

    return IMAGE_CACHE_DIR / cache_name


def _guess_extension(mime_type):
    return {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/webp": ".webp",
        "image/gif": ".gif",
        "image/bmp": ".bmp",
        "image/tiff": ".tiff",
    }.get(
        str(mime_type).lower(),
        ".img",
    )


def _find_index_file_by_id(file_id):
    """
    ใช้เฉพาะ /image/{file_id} โดยตรง
    ปกติ /image-by-path จะมี file_info จาก index อยู่แล้ว
    """
    index = ensure_drive_index()

    for info in index.values():

        if info.get("id") == file_id:
            return info

    return None


def _valid_cached_file(cache_file):
    try:
        return (
            cache_file.exists()
            and cache_file.stat().st_size > 1000
        )
    except Exception:
        return False


def _download_drive_image(
    file_info
):
    """
    Download binary จาก Google Drive โดย:
    - ไม่เรียก metadata ซ้ำ
    - จำกัดจำนวน concurrent downloads
    - retry เมื่อ SSL/connection หลุด
    - validate image header
    - save local cache
    """

    file_id = file_info["id"]

    mime_type = (
        file_info.get("mimeType")
        or "image/jpeg"
    )

    file_name = (
        file_info.get("name")
        or file_id
    )

    if not str(
        mime_type
    ).startswith("image/"):

        raise HTTPException(
            status_code=400,
            detail=(
                f"ไฟล์นี้ไม่ใช่รูปภาพ: "
                f"{mime_type}"
            ),
        )

    cache_file = _cache_path(
        file_id
    )

    # --------------------------------------------------------
    # 1. Local cache
    # --------------------------------------------------------

    if _valid_cached_file(
        cache_file
    ):

        size = cache_file.stat().st_size

        print(
            f"[Image Cache] HIT: "
            f"{file_name} "
            f"({size:,} bytes)"
        )

        return cache_file

    # --------------------------------------------------------
    # 2. จำกัดจำนวน request ที่เข้า Google Drive พร้อมกัน
    # --------------------------------------------------------

    print(
        f"[Drive Image] "
        f"รอคิว download: "
        f"{file_name}"
    )

    with DRIVE_DOWNLOAD_SEMAPHORE:

        # ระหว่างรอคิว อาจมี request อื่นโหลดไฟล์นี้เสร็จแล้ว
        if _valid_cached_file(
            cache_file
        ):

            print(
                f"[Image Cache] "
                f"HIT หลังรอคิว: "
                f"{file_name}"
            )

            return cache_file

        max_retries = 5
        last_error = None

        for attempt in range(
            1,
            max_retries + 1,
        ):

            try:

                print(
                    f"[Drive Image] "
                    f"กำลัง download "
                    f"{file_name} "
                    f"(ครั้งที่ "
                    f"{attempt}/{max_retries})"
                )

                drive = get_drive()

                request = (
                    drive.files()
                    .get_media(
                        fileId=file_id,
                        supportsAllDrives=True,
                    )
                )

                buffer = BytesIO()

                downloader = MediaIoBaseDownload(
                    buffer,
                    request,
                    chunksize=1024 * 1024,
                )

                done = False

                while not done:

                    status, done = (
                        downloader.next_chunk()
                    )

                    if status:

                        print(
                            f"[Drive Image] "
                            f"{file_name} "
                            f"{int(status.progress() * 100)}%"
                        )

                data = buffer.getvalue()

                print(
                    f"[Drive Image] "
                    f"download สำเร็จ "
                    f"{file_name} "
                    f"({len(data):,} bytes)"
                )

                # ------------------------------------------------
                # Validate common image signatures
                # ------------------------------------------------

                valid = True

                if mime_type == "image/jpeg":
                    valid = data.startswith(
                        b"\xff\xd8\xff"
                    )

                elif mime_type == "image/png":
                    valid = data.startswith(
                        b"\x89PNG\r\n\x1a\n"
                    )

                elif mime_type == "image/gif":
                    valid = data.startswith(
                        (b"GIF87a", b"GIF89a")
                    )

                elif mime_type == "image/webp":
                    valid = (
                        len(data) >= 12
                        and data[:4] == b"RIFF"
                        and data[8:12] == b"WEBP"
                    )

                if not valid:

                    print(
                        "[Drive Image] "
                        "WARNING: "
                        "ข้อมูลที่ได้ไม่ใช่ "
                        f"{mime_type}"
                    )

                    print(
                        "[Drive Image] "
                        f"HEADER={data[:100]!r}"
                    )

                    raise RuntimeError(
                        "Google Drive "
                        "ไม่ได้ส่ง image binary กลับมา"
                    )

                # ------------------------------------------------
                # Save atomically
                # ------------------------------------------------

                temp_file = cache_file.with_suffix(
                    cache_file.suffix + ".tmp"
                )

                temp_file.write_bytes(
                    data
                )

                temp_file.replace(
                    cache_file
                )

                print(
                    f"[Image Cache] SAVE: "
                    f"{file_name}"
                )

                return cache_file

            except Exception as e:

                last_error = e

                print(
                    f"[Drive Image] "
                    f"download error "
                    f"(ครั้งที่ "
                    f"{attempt}/{max_retries}): "
                    f"{repr(e)}"
                )

                if attempt < max_retries:

                    wait_seconds = (
                        attempt * 2
                    )

                    print(
                        f"[Drive Image] "
                        f"รอ {wait_seconds} "
                        f"วินาทีแล้วลองใหม่..."
                    )

                    time.sleep(
                        wait_seconds
                    )

        raise HTTPException(
            status_code=502,
            detail=(
                "Google Drive download failed: "
                f"{repr(last_error)}"
            ),
        )


@app.get(
    "/image-by-path"
)
def get_image_by_path(
    path: str,
    authorization: str | None = Header(default=None),
    token: str | None = Query(default=None),
):

    current_user(authorization=authorization, token=token)

    # --------------------------------------------------------
    # ใช้ drive_path_index.json โดยตรง
    # ไม่ search filename ใน Google Drive
    # --------------------------------------------------------

    file_info = (
        find_drive_file(
            path
        )
    )

    if not file_info:

        raise HTTPException(
            status_code=404,
            detail=(
                "ไม่พบรูปใน "
                "drive_path_index.json "
                "จาก path: "
                f"{path}"
            ),
        )

    return _serve_cached_or_downloaded_image(
        file_info
    )


def _serve_cached_or_downloaded_image(
    file_info
):

    cache_file = (
        _download_drive_image(
            file_info
        )
    )

    mime_type = (
        file_info.get("mimeType")
        or "image/jpeg"
    )

    return StreamingResponse(
        open(
            cache_file,
            "rb",
        ),
        media_type=mime_type,
        headers={
            "Cache-Control":
                "public, "
                "max-age=86400",

            "Content-Length":
                str(
                    cache_file.stat().st_size
                ),
        },
    )


@app.get(
    "/image/{file_id}"
)
def get_image(
    file_id: str,
    authorization: str | None = Header(default=None),
    token: str | None = Query(default=None),
):

    current_user(authorization=authorization, token=token)

    # --------------------------------------------------------
    # ปกติ route นี้ไม่ถูกใช้จากหน้าเว็บแล้ว
    # แต่เก็บไว้สำหรับ direct testing
    # --------------------------------------------------------

    file_info = (
        _find_index_file_by_id(
            file_id
        )
    )

    if file_info:

        print(
            f"[Drive Image] "
            f"พบไฟล์จาก index: "
            f"{file_info.get('name')} | "
            f"ID={file_id} | "
            f"MIME={file_info.get('mimeType')}"
        )

        return _serve_cached_or_downloaded_image(
            file_info
        )

    # fallback เฉพาะกรณี ID ไม่อยู่ใน index
    # ไม่ใช้ใน normal image-by-path flow

    try:

        drive = get_drive()

        file_info = (
            execute_with_retry(
                drive.files()
                .get(
                    fileId=file_id,
                    fields=(
                        "id,name,mimeType"
                    ),
                    supportsAllDrives=True,
                    includeItemsFromAllDrives=True,
                )
            )
        )

    except Exception as e:

        print(
            f"[Drive Image] "
            f"metadata error: {repr(e)}"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "อ่านข้อมูลไฟล์จาก Google Drive "
                f"ไม่สำเร็จ: {e}"
            ),
        )

    return _serve_cached_or_downloaded_image(
        file_info
    )

# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {

        "message":
            "Car AC API is running",

        "csv":
            CLIP_CSV_FILENAME,

        "root_folder":
            DRIVE_ROOT_FOLDER_ID,

        "endpoints": [

            "/cases",

            "/cases/{case_id}",

            "/image-by-path",

            "/image/{file_id}",

            "/stats",

            "/drive-check",

            "/drive-index-status",

            "/build-drive-index",
        ],
    }


# ============================================================
# STATS
# ============================================================

@app.get(
    "/stats"
)
def stats(
    authorization: str | None = Header(default=None),
):

    user = current_user(authorization=authorization, token=None)
    require_admin(user)

    df = load_df()

    cases = set()

    categories = {}

    unparsed = 0

    for row in df.to_dict(
        "records"
    ):

        image = image_record(
            row
        )

        if not image:
            continue

        if image[
            "case_id"
        ]:

            cases.add(
                image[
                    "case_id"
                ]
            )

        else:

            unparsed += 1

        category = image[
            "type"
        ]

        categories[
            category
        ] = (
            categories.get(
                category,
                0,
            )
            + 1
        )

    return {

        "csv":
            CLIP_CSV_FILENAME,

        "images":
            len(df),

        "cases":
            len(cases),

        "unparsed_images":
            unparsed,

        "categories":
            categories,
    }


# ============================================================
# DRIVE INDEX STATUS
# ============================================================

@app.get(
    "/drive-index-status"
)
def drive_index_status(
    authorization: str | None = Header(default=None),
):

    user = current_user(authorization=authorization, token=None)
    require_admin(user)

    if not DRIVE_INDEX_FILE.exists():

        return {

            "ready":
                False,

            "files":
                0,

            "index_file":
                str(
                    DRIVE_INDEX_FILE
                ),

            "master_index_file_id":
                DRIVE_INDEX_FILE_ID,
        }

    try:

        index = json.loads(
            DRIVE_INDEX_FILE.read_text(
                encoding="utf-8"
            )
        )

        return {

            "ready":
                True,

            "files":
                len(index),

            "index_file":
                str(
                    DRIVE_INDEX_FILE
                ),

            "master_index_file_id":
                DRIVE_INDEX_FILE_ID,
        }

    except Exception as e:

        return {

            "ready":
                False,

            "files":
                0,

            "error":
                str(e),
        }


# ============================================================
# BUILD INDEX
# ============================================================

@app.post(
    "/build-drive-index"
)
def build_drive_index_api(
    authorization: str | None = Header(default=None),
):

    user = current_user(authorization=authorization, token=None)
    require_admin(user)

    result = (
        build_drive_path_index(
            force=True
        )
    )

    load_drive_path_index.cache_clear()

    find_drive_file.cache_clear()

    return {

        "status":
            "built",

        "files":
            len(result),

        "index_file":
            str(
                DRIVE_INDEX_FILE
            ),

        "master_index_file_id":
            DRIVE_INDEX_FILE_ID,
    }


# ============================================================
# DRIVE CHECK
# ============================================================

@app.get(
    "/drive-check"
)
def drive_check(
    path: str = None,
    authorization: str | None = Header(default=None),
):

    user = current_user(authorization=authorization, token=None)
    require_admin(user)

    if not path:

        cases = build_cases()

        for case in (
            cases.values()
        ):

            if case[
                "images"
            ]:

                path = case[
                    "images"
                ][0][
                    "path"
                ]

                break

    if not path:

        return {

            "found":
                False,

            "error":
                "ไม่พบ path "
                "ให้ทดสอบ",
        }

    file_info = (
        find_drive_file(
            path
        )
    )

    return {

        "tested_path":
            path,

        "found":
            file_info is not None,

        "file_info":
            file_info,

        "index_file":
            str(
                DRIVE_INDEX_FILE
            ),
    }


# ============================================================
# AUTH
# ============================================================

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(request: LoginRequest):
    username = request.username.strip()
    password = request.password
    user = _read_user(username, force=True)

    if (
        not user
        or user["active"] != 1
        or not verify_password(password, user["password_hash"])
    ):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    _update_last_login(user["username"])
    token = create_access_token(user)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in_hours": TOKEN_EXPIRE_HOURS,
        "user": {
            "username": user["username"],
            "role": user["role"],
            "allowed_brands": user["allowed_brands"],
        },
    }


# ============================================================
# CASE LIST
# ============================================================

@app.get(
    "/cases"
)
def get_cases(
    authorization: str | None = Header(default=None),
):

    user = current_user(authorization=authorization, token=None)

    output = []

    for case in build_cases().values():

        if not user_can_access_brand(user, case.get("brand")):
            continue

        preview_images = []

        for image in case["images"][:MAX_IMAGES_PER_CASE]:
            img = dict(image)
            path = img.get("path", "")

            if path:
                img["id"] = None
                access_token = _get_token_from_request(
                    authorization,
                    None,
                )

                img["url"] = image_url(
                    path,
                    access_token,
                )
            else:
                img["id"] = None
                img["url"] = None

            preview_images.append(img)

        output.append({
            "case_id": case["case_id"],
            "customer": case["customer"],
            "brand": case["brand"],
            "model": case["model"],
            "year": case["year"],
            "case_folder": case["case_folder"],
            "received_date": case["received_date"],
            "appointment_date": case["appointment_date"],
            "mileage": case["mileage"],
            "low_before": case["low_before"],
            "low_after": case["low_after"],
            "high_before": case["high_before"],
            "high_after": case["high_after"],
            "image_count": len(case["images"]),
            "images": preview_images,
        })

    return sorted(output, key=lambda x: x["case_id"] or "")


# ============================================================
# SINGLE CASE
# ============================================================

@app.get(
    "/cases/{case_id}"
)
def get_case(
    case_id: str,
    authorization: str | None = Header(default=None),
):

    user = current_user(authorization=authorization, token=None)

    case = (
        build_cases().get(
            case_id.strip().upper()
        )
    )

    if case is None:

        raise HTTPException(
            status_code=404,
            detail=(
                f"ไม่เจอเคส "
                f"{case_id}"
            ),
        )

    if not user_can_access_brand(
        user,
        case.get("brand"),
    ):
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to view this case",
        )

    result = {
        "case_id": case["case_id"],
        "customer": case["customer"],
        "brand": case["brand"],
        "model": case["model"],
        "year": case["year"],
        "case_folder": case["case_folder"],
        "received_date": case["received_date"],
        "appointment_date": case["appointment_date"],
        "mileage": case["mileage"],
        "low_before": case["low_before"],
        "low_after": case["low_after"],
        "high_before": case["high_before"],
        "high_after": case["high_after"],
        "images": [],
    }

    # รูปจะถูก resolve ตอน browser ขอจริง
    # ไม่ค้น Drive ทั้งหมดตอนเปิด case

    for image in case[
        "images"
    ]:

        img = dict(
            image
        )

        path = img.get(
            "path",
            "",
        )

        if path:

            img[
                "id"
            ] = None

            access_token = _get_token_from_request(
                authorization,
                None,
            )

            img[
                "url"
            ] = image_url(
                path,
                access_token,
            )

        else:

            img[
                "id"
            ] = None

            img[
                "url"
            ] = None

        result[
            "images"
        ].append(
            img
        )

    return result