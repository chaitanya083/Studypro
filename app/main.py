from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import base64
import json
from urllib.parse import parse_qs
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from . import models
from .database import Base, SessionLocal, engine
from .keycloak import KeycloakError
from .schemas import SessionRevokeRequest, SubscriptionCreate, UserCreate, UserLogin
from .security import bearer_scheme, current_keycloak_user, keycloak


Base.metadata.create_all(bind=engine)


def initialize_application() -> None:
    try:
        keycloak.bootstrap(["Free", "Basic", "Premium"])
    except KeycloakError:
        # Do not block app startup when Keycloak is not ready yet.
        pass

    with SessionLocal() as db:
        seed_plans(db)
        seed_courses(db)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    initialize_application()
    yield


app = FastAPI(
    title="StudyPro API - Keycloak + SQLite",
    version="2.0.0",
    lifespan=lifespan,
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def seed_plans(db: Session) -> None:
    defaults = [
        ("Free", 0, 2, 1, None),
        ("Basic", 99, 10, 2, 30),
        ("Premium", 199, 50, 3, 30),
    ]
    existing = {p.name for p in db.query(models.Plan).all()}
    changed = False
    for name, price, quota, sessions, duration in defaults:
        if name not in existing:
            db.add(
                models.Plan(
                    name=name,
                    price=price,
                    course_quota=quota,
                    concurrent_sessions=sessions,
                    duration_days=duration,
                )
            )
            changed = True
    if changed:
        db.commit()


def seed_courses(db: Session) -> None:
    if db.query(models.Course).count():
        return

    plans = {p.name: p.id for p in db.query(models.Plan).all()}
    required = [
        ("Python Basics", "Learn Python programming from scratch.", "Free"),
        ("Java Basics", "Learn Java fundamentals.", "Basic"),
        ("SQL Basics", "Learn relational database fundamentals.", "Basic"),
        ("MongoDB Basics", "Learn MongoDB and document databases.", "Basic"),
        ("Advanced AI", "Learn advanced AI concepts.", "Premium"),
    ]
    db.add_all(
        [
            models.Course(
                title=title,
                description=description,
                required_plan_id=plans[plan],
            )
            for title, description, plan in required
        ]
    )
    db.commit()


@app.middleware("http")
async def normalize_request_path(request: Request, call_next):
    # Avoid accidental trailing whitespace in paths while leaving normal paths unchanged.
    request.scope["path"] = request.scope["path"].rstrip()
    return await call_next(request)


def user_id(user: dict) -> str:
    subject = user.get("sub")
    if not subject:
        raise HTTPException(status_code=401, detail="Keycloak user ID missing from token")
    return str(subject)


def active_sessions_for(uid: str) -> list[dict]:
    try:
        return keycloak.user_sessions(uid)
    except KeycloakError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


def session_limit(uid: str, db: Session) -> int:
    sub = (
        db.query(models.Subscription)
        .filter(
            models.Subscription.keycloak_user_id == uid,
            models.Subscription.status == "ACTIVE",
        )
        .order_by(models.Subscription.id.desc())
        .first()
    )
    if not sub:
        return 1

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if sub.expiry_date and sub.expiry_date <= now:
        sub.status = "EXPIRED"
        db.commit()
        return 1

    plan = db.query(models.Plan).filter(models.Plan.id == sub.plan_id).first()
    return plan.concurrent_sessions if plan else 1


def serialize_session(session: dict) -> dict:
    return {
        "session_id": session.get("id"),
        "username": session.get("username"),
        "ip_address": session.get("ipAddress"),
        "start": session.get("start"),
        "last_access": session.get("lastAccess"),
        "clients": session.get("clients", {}),
    }

def token_session_id(token: str) -> str | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        sid = data.get("sid")
        return str(sid) if sid else None
    except (ValueError, TypeError, IndexError, json.JSONDecodeError):
        return None


def parse_login_credentials(request: Request, body: bytes) -> UserLogin:
    content_type = request.headers.get("content-type", "").lower()
    if "application/json" in content_type:
        try:
            raw = json.loads(body or b"{}")
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail="Invalid JSON body") from exc
        if raw.get("email") is None and raw.get("username") is not None:
            raw["email"] = raw["username"]
        try:
            return UserLogin(**raw)
        except Exception as exc:
            raise HTTPException(
                status_code=422,
                detail="Email and password are required",
            ) from exc

    form = parse_qs(body.decode("utf-8", errors="replace"))
    try:
        email = form.get("email", form.get("username", [None]))[0]
        password = form.get("password", [None])[0]
        return UserLogin(email=email, password=password)
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail="Email and password are required",
        ) from exc


def token_response(tokens: dict, limit: int, active: int) -> dict:
    return {
        "authenticated": True,
        "access_token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token"),
        "token_type": tokens.get("token_type", "bearer"),
        "expires_in": tokens.get("expires_in"),
        "session_limit": limit,
        "active_sessions": active,
    }


@app.get("/")
def home():
    return RedirectResponse(url="/docs")


@app.post("/signup")
def signup(user: UserCreate):
    try:
        created = keycloak.create_user(user.name, str(user.email), user.password)
    except KeycloakError as exc:
        status = 400 if "already registered" in str(exc).lower() else 502
        raise HTTPException(status_code=status, detail=str(exc)) from exc

    return {
        "message": "Account created successfully in Keycloak",
        "user_id": created["id"],
        "name": user.name.strip(),
        "email": str(user.email).lower(),
    }


@app.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    data = parse_login_credentials(request, await request.body())

    try:
        tokens = keycloak.login(str(data.email), data.password)
        user = keycloak.user_info(tokens["access_token"])
    except KeycloakError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    uid = user_id(user)
    limit = session_limit(uid, db)
    sessions = active_sessions_for(uid)

    # Keycloak creates a session before this check. Never delete an old session
    # automatically. If the limit is exceeded, remove only the just-created
    # session and return the existing sessions so the user can choose one.
    if len(sessions) > limit:
        new_session_id = token_session_id(tokens["access_token"])
        if new_session_id:
            try:
                keycloak.revoke_session(new_session_id)
            except KeycloakError as exc:
                raise HTTPException(status_code=502, detail=str(exc)) from exc

        sessions = active_sessions_for(uid)
        return {
            "authenticated": False,
            "session_limit_reached": True,
            "session_limit": limit,
            "active_sessions": len(sessions),
            "sessions": [serialize_session(s) for s in sessions],
            "message": (
                "Session limit reached. Select an existing session and call "
                "POST /login/remove-session."
            ),
        }

    return token_response(tokens, limit, len(sessions))


@app.post("/login/remove-session")
async def remove_session_before_login(
    request: Request, db: Session = Depends(get_db)
):
    body = await request.body()
    raw = parse_login_credentials(request, body)

    # session_id is accepted from JSON/form separately.
    content_type = request.headers.get("content-type", "").lower()
    if "application/json" in content_type:
        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail="Invalid JSON body") from exc
        session_id = payload.get("session_id")
    else:
        form = parse_qs(body.decode("utf-8", errors="replace"))
        session_id = form.get("session_id", [None])[0]

    if not session_id:
        raise HTTPException(status_code=422, detail="session_id is required")

    try:
        tokens = keycloak.login(str(raw.email), raw.password)
        user = keycloak.user_info(tokens["access_token"])
        uid = user_id(user)
        sessions = active_sessions_for(uid)

        if not any(s.get("id") == session_id for s in sessions):
            # The temporary login session is not wanted because no removal occurred.
            new_sid = token_session_id(tokens["access_token"])
            if new_sid:
                keycloak.revoke_session(new_sid)
            raise HTTPException(
                status_code=404,
                detail="Active session not found or does not belong to you",
            )

        keycloak.revoke_session(session_id)
        remaining = active_sessions_for(uid)
        limit = session_limit(uid, db)

        # The login that created `tokens` is still active. After deleting one
        # old session, it is now a valid session under the plan limit.
        return {
            **token_response(tokens, limit, len(remaining)),
            "message": "Selected session removed successfully and login completed",
            "removed_session_id": session_id,
        }
    except HTTPException:
        raise
    except KeycloakError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@app.get("/sessions")
def list_sessions(
    user: dict = Depends(current_keycloak_user),
    db: Session = Depends(get_db),
):
    uid = user_id(user)
    sessions = active_sessions_for(uid)
    limit = session_limit(uid, db)
    return {
        "session_limit": limit,
        "active_sessions": len(sessions),
        "sessions": [serialize_session(s) for s in sessions],
    }


@app.delete("/sessions/{session_id}")
def remove_session(
    session_id: str,
    user: dict = Depends(current_keycloak_user),
    db: Session = Depends(get_db),
):
    uid = user_id(user)
    sessions = active_sessions_for(uid)
    if not any(s.get("id") == session_id for s in sessions):
        raise HTTPException(
            status_code=404,
            detail="Active session not found or does not belong to you",
        )

    try:
        keycloak.revoke_session(session_id)
        remaining = active_sessions_for(uid)
    except KeycloakError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    limit = session_limit(uid, db)
    return {
        "message": "Selected Keycloak session removed successfully",
        "removed_session_id": session_id,
        "active_sessions": len(remaining),
        "session_limit": limit,
        "remaining_sessions": [serialize_session(s) for s in remaining],
    }


@app.get("/profile")
def profile(user: dict = Depends(current_keycloak_user)):
    return {
        "id": user_id(user),
        "name": user.get("given_name") or user.get("name") or user.get("preferred_username"),
        "email": user.get("email"),
        "username": user.get("preferred_username"),
        "identity_provider": "Keycloak",
    }


@app.post("/logout")
def logout(credentials = Depends(bearer_scheme)):
    token = credentials.credentials
    session_id = token_session_id(token)
    if not session_id:
        raise HTTPException(status_code=401, detail="Session ID missing from Keycloak token")

    try:
        keycloak.revoke_session(session_id)
    except KeycloakError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {"message": "Logged out successfully from Keycloak", "session_id": session_id}


@app.get("/plans")
def get_plans(db: Session = Depends(get_db)):
    return [
        {
            "id": p.id,
            "name": p.name,
            "price": p.price,
            "course_quota": p.course_quota,
            "concurrent_sessions": p.concurrent_sessions,
            "duration_days": p.duration_days,
        }
        for p in db.query(models.Plan).order_by(models.Plan.id).all()
    ]


def current_subscription(user: dict, db: Session) -> models.Subscription:
    uid = user_id(user)
    subscription = (
        db.query(models.Subscription)
        .filter(
            models.Subscription.keycloak_user_id == uid,
            models.Subscription.status == "ACTIVE",
        )
        .order_by(models.Subscription.id.desc())
        .first()
    )
    if not subscription:
        raise HTTPException(status_code=403, detail="No active subscription")

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if subscription.expiry_date and subscription.expiry_date <= now:
        subscription.status = "EXPIRED"
        db.commit()
        raise HTTPException(status_code=403, detail="Subscription has expired")
    return subscription


def current_plan(user: dict, db: Session) -> models.Plan:
    sub = current_subscription(user, db)
    plan = db.query(models.Plan).filter(models.Plan.id == sub.plan_id).first()
    if not plan:
        raise HTTPException(status_code=500, detail="Subscription plan not found")
    return plan


@app.post("/subscribe")
def subscribe(
    data: SubscriptionCreate,
    user: dict = Depends(current_keycloak_user),
    db: Session = Depends(get_db),
):
    uid = user_id(user)
    existing = current_subscription_if_any(uid, db)
    if existing:
        raise HTTPException(status_code=400, detail="User already has an active subscription")

    plan = db.query(models.Plan).filter(models.Plan.id == data.plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    expiry = now + timedelta(days=plan.duration_days) if plan.duration_days else None
    sub = models.Subscription(
        keycloak_user_id=uid,
        plan_id=plan.id,
        start_date=now,
        expiry_date=expiry,
        status="ACTIVE",
    )
    db.add(sub)
    db.flush()

    # Keep Keycloak group membership aligned with the SQLite subscription.
    # If Keycloak cannot be updated, roll the database transaction back so the
    # API never reports a half-created subscription.
    try:
        keycloak.remove_user_from_plan_groups(uid)
        keycloak.assign_user_to_plan(uid, plan.name)
    except KeycloakError as exc:
        db.rollback()
        raise HTTPException(
            status_code=502,
            detail=f"Could not synchronize subscription with Keycloak: {exc}",
        ) from exc

    db.commit()
    db.refresh(sub)

    return {
        "message": "Subscription created successfully",
        "subscription_id": sub.id,
        "plan": plan.name,
        "start_date": sub.start_date,
        "expiry_date": sub.expiry_date,
        "status": sub.status,
    }


def current_subscription_if_any(uid: str, db: Session) -> models.Subscription | None:
    sub = (
        db.query(models.Subscription)
        .filter(
            models.Subscription.keycloak_user_id == uid,
            models.Subscription.status == "ACTIVE",
        )
        .order_by(models.Subscription.id.desc())
        .first()
    )
    if sub and sub.expiry_date:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if sub.expiry_date <= now:
            sub.status = "EXPIRED"
            db.commit()
            return None
    return sub


@app.get("/subscription/access")
def subscription_access(
    user: dict = Depends(current_keycloak_user),
    db: Session = Depends(get_db),
):
    sub = current_subscription(user, db)
    return {
        "message": "Subscription is active",
        "subscription_id": sub.id,
        "status": sub.status,
    }


@app.get("/courses")
def get_courses(db: Session = Depends(get_db)):
    return [
        {
            "id": c.id,
            "title": c.title,
            "description": c.description,
            "required_plan_id": c.required_plan_id,
        }
        for c in db.query(models.Course).order_by(models.Course.id).all()
    ]


def count_used_courses(uid: str, db: Session) -> int:
    return (
        db.query(models.CourseAccess)
        .filter(models.CourseAccess.keycloak_user_id == uid)
        .count()
    )


@app.post("/courses/{course_id}/access")
def access_course(
    course_id: int,
    user: dict = Depends(current_keycloak_user),
    db: Session = Depends(get_db),
):
    uid = user_id(user)
    plan = current_plan(user, db)
    course = db.query(models.Course).filter(models.Course.id == course_id).first()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    # Course requirements are based on plan hierarchy: Free < Basic < Premium.
    required_plan = db.query(models.Plan).filter(
        models.Plan.id == course.required_plan_id
    ).first()
    if not required_plan:
        raise HTTPException(status_code=500, detail="Course requirement plan not found")

    hierarchy = {"Free": 1, "Basic": 2, "Premium": 3}
    if hierarchy.get(plan.name, 0) < hierarchy.get(required_plan.name, 99):
        raise HTTPException(status_code=403, detail="Your plan does not allow this course")

    existing = (
        db.query(models.CourseAccess)
        .filter(
            models.CourseAccess.keycloak_user_id == uid,
            models.CourseAccess.course_id == course.id,
        )
        .first()
    )
    used = count_used_courses(uid, db)

    if not existing and used >= plan.course_quota:
        raise HTTPException(status_code=403, detail="Course quota reached")

    if not existing:
        db.add(
            models.CourseAccess(
                keycloak_user_id=uid,
                course_id=course.id,
                accessed_at=datetime.now(timezone.utc).replace(tzinfo=None),
            )
        )
        db.commit()
        used += 1

    return {
        "message": "Course access granted",
        "course_id": course.id,
        "title": course.title,
        "quota": {
            "used": used,
            "limit": plan.course_quota,
            "remaining": max(plan.course_quota - used, 0),
        },
    }


@app.get("/dashboard")
def dashboard(
    user: dict = Depends(current_keycloak_user),
    db: Session = Depends(get_db),
):
    uid = user_id(user)
    sub = current_subscription(user, db)
    plan = db.query(models.Plan).filter(models.Plan.id == sub.plan_id).first()
    if not plan:
        raise HTTPException(status_code=500, detail="Subscription plan not found")

    used_courses = count_used_courses(uid, db)
    sessions = active_sessions_for(uid)
    return {
        "user": {
            "id": uid,
            "name": user.get("given_name") or user.get("name") or user.get("preferred_username"),
            "email": user.get("email"),
            "username": user.get("preferred_username"),
        },
        "subscription": {
            "plan": plan.name,
            "price": plan.price,
            "status": sub.status,
            "start_date": sub.start_date,
            "expiry_date": sub.expiry_date,
        },
        "course_usage": {
            "used": used_courses,
            "limit": plan.course_quota,
            "remaining": max(plan.course_quota - used_courses, 0),
        },
        "session_usage": {
            "active": len(sessions),
            "limit": plan.concurrent_sessions,
            "remaining": max(plan.concurrent_sessions - len(sessions), 0),
        },
    }
