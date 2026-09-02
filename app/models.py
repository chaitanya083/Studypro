from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, UniqueConstraint

from .database import Base


class Plan(Base):
    __tablename__ = "plans"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    price = Column(Integer, nullable=False)
    course_quota = Column(Integer, nullable=False)
    concurrent_sessions = Column(Integer, nullable=False)
    duration_days = Column(Integer, nullable=True)


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    keycloak_user_id = Column(String, nullable=False, index=True)
    plan_id = Column(Integer, ForeignKey("plans.id"), nullable=False)
    start_date = Column(DateTime, nullable=False)
    expiry_date = Column(DateTime, nullable=True)
    status = Column(String, nullable=False)


class Course(Base):
    __tablename__ = "courses"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    required_plan_id = Column(Integer, ForeignKey("plans.id"), nullable=False)


class CourseAccess(Base):
    __tablename__ = "course_access"

    id = Column(Integer, primary_key=True, index=True)
    keycloak_user_id = Column(String, nullable=False, index=True)
    course_id = Column(Integer, ForeignKey("courses.id"), nullable=False)
    accessed_at = Column(DateTime, nullable=False)

    __table_args__ = (
        UniqueConstraint("keycloak_user_id", "course_id", name="uq_user_course"),
    )
