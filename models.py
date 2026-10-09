import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Boolean, BigInteger, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DB_PATH = os.getenv("DB_PATH", "/data/panel.db")
try:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    open(DB_PATH, "a").close()
except OSError:
    DB_PATH = "./panel.db"

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()


class Endpoint(Base):
    __tablename__ = "endpoints"
    id = Column(Integer, primary_key=True)
    remark = Column(String, nullable=False)
    kind = Column(String, nullable=False)  # web-http | web-ws | edge-tcp | edge-http
    mode = Column(String, default="packet-up")
    path = Column(String, default="/s/")
    key_a = Column(String, default="")
    key_b = Column(String, default="")
    tag_id = Column(String, default="")
    enable = Column(Boolean, default=True)
    clients = relationship("Account", back_populates="endpoint", cascade="all, delete-orphan")


class Account(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id"), nullable=False)
    name = Column(String, nullable=False)
    uuid = Column(String, nullable=False)
    sub_token = Column(String, unique=True, nullable=False)
    total_bytes = Column(BigInteger, default=0)  # 0 = unlimited
    used_bytes = Column(BigInteger, default=0)
    up_bytes = Column(BigInteger, default=0)
    down_bytes = Column(BigInteger, default=0)
    limit_down_kbps = Column(BigInteger, default=0)  # 0 = unlimited
    limit_up_kbps = Column(BigInteger, default=0)    # 0 = unlimited
    expiry = Column(DateTime, nullable=True)  # UTC, None = never
    enable = Column(Boolean, default=True)
    created = Column(DateTime, default=datetime.utcnow)
    endpoint = relationship("Endpoint", back_populates="clients")


class DailyStat(Base):
    __tablename__ = "daily_stats"
    day = Column(String, primary_key=True)  # YYYY-MM-DD (UTC)
    up = Column(BigInteger, default=0)
    down = Column(BigInteger, default=0)


class Setting(Base):
    """Key/value settings edited from the dashboard (they override the environment defaults)."""
    __tablename__ = "settings"
    key = Column(String, primary_key=True)
    value = Column(Text, default="")


def _env_list(name):
    return os.getenv(name, "").replace("https://", "").replace("http://", "").strip().strip("/")


SETTING_DEFAULTS = {
    "domains": _env_list("PANEL_DOMAIN"),                 # comma separated; first is the main one
    "addresses": os.getenv("CLIENT_ADDRESS", ""),         # comma separated clean Cloudflare IPs
    "fp": os.getenv("CLIENT_FP", "chrome"),
    "alpn": os.getenv("CLIENT_ALPN", "h2"),
    "alpn_ws": os.getenv("CLIENT_ALPN_WS", "http/1.1"),
    "padding": "100-1000",
    "xhttp_obfs": "0",
    "frag": "1",              # TLS fragment in the JSON client config (hides the SNI from simple DPI)
    "frag_len": "100-200",
    "frag_int": "10-20",
    "vlessenc": "0",
    "venc_dec": "",
    "venc_enc": "",
}


def get_settings(db):
    d = dict(SETTING_DEFAULTS)
    for r in db.query(Setting).all():
        if r.key in d:
            d[r.key] = r.value or ""
    return d


def put_settings(db, items):
    for k, v in items.items():
        row = db.get(Setting, k)
        if row:
            row.value = str(v)
        else:
            db.add(Setting(key=k, value=str(v)))
    db.commit()
