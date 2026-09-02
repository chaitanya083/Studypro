from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class SessionRevokeRequest(BaseModel):
    email: EmailStr
    password: str
    session_id: str


class SubscriptionCreate(BaseModel):
    plan_id: int
