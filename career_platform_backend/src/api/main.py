from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Path, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field, constr

# PUBLIC_INTERFACE
def get_app() -> FastAPI:
    """Create and return the FastAPI application instance with routes and middleware."""
    app = FastAPI(
        title="Career Platform Backend",
        description=(
            "MVP backend for a career platform enabling users to authenticate, "
            "browse job listings, and manage user profiles. This API is designed "
            "for rapid prototyping with in-memory storage and comprehensive OpenAPI documentation."
        ),
        version="0.1.0",
        openapi_tags=[
            {"name": "health", "description": "Service readiness and liveness checks"},
            {"name": "auth", "description": "Authentication endpoints for login/logout"},
            {"name": "jobs", "description": "Browse and manage job listings"},
            {"name": "profiles", "description": "Manage user profiles"},
        ],
    )

    # CORS: For MVP allow all; production should restrict origins via environment variables
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # =========================
    # In-memory data stores (MVP)
    # =========================
    # Note: In production, replace with database and secure session/token handling.
    class _InMemoryStore:
        users: Dict[str, "User"] = {}
        sessions: Dict[str, str] = {}  # token -> user_id
        profiles: Dict[str, "UserProfile"] = {}
        jobs: Dict[str, "Job"] = {}

    # Seed some jobs for browsing
    def _seed_jobs() -> None:
        if _InMemoryStore.jobs:
            return
        now = datetime.now(tz=timezone.utc)
        samples = [
            JobCreate(
                title="Software Engineer",
                company="TechNova",
                location="Remote",
                description="Build and maintain scalable backend services.",
                salary_min=90000,
                salary_max=130000,
                tags=["python", "fastapi", "aws"],
            ),
            JobCreate(
                title="Frontend Developer",
                company="UXWorks",
                location="San Francisco, CA",
                description="Create engaging UI with React and TypeScript.",
                salary_min=100000,
                salary_max=140000,
                tags=["react", "typescript", "ui"],
            ),
            JobCreate(
                title="Data Analyst",
                company="Insightly",
                location="New York, NY",
                description="Analyze data and deliver actionable insights.",
                salary_min=80000,
                salary_max=110000,
                tags=["sql", "dashboards", "analytics"],
            ),
        ]
        for jc in samples:
            jid = secrets.token_urlsafe(8)
            _InMemoryStore.jobs[jid] = Job(
                id=jid,
                created_at=now,
                **jc.model_dump(),
            )

    # =========================
    # Models
    # =========================

    class HealthResponse(BaseModel):
        status: str = Field(..., description="Service health status")

    class AuthLoginRequest(BaseModel):
        email: EmailStr = Field(..., description="User email")
        password: constr(min_length=6, max_length=128) = Field(..., description="User password")

    class AuthLoginResponse(BaseModel):
        token: str = Field(..., description="Session token to be used as Bearer or X-Session-Token")
        token_type: str = Field("bearer", description="Token type, typically 'bearer'")
        expires_in: int = Field(..., description="Token expiry in seconds")

    class User(BaseModel):
        id: str = Field(..., description="User identifier")
        email: EmailStr = Field(..., description="User email")

    class UserProfile(BaseModel):
        user_id: str = Field(..., description="Associated user id")
        full_name: constr(min_length=1, max_length=100) = Field(..., description="Full name")
        headline: Optional[constr(max_length=140)] = Field(None, description="Short professional headline")
        location: Optional[constr(max_length=120)] = Field(None, description="Location")
        skills: List[constr(min_length=1, max_length=40)] = Field(default_factory=list, description="List of skills")
        bio: Optional[constr(max_length=2000)] = Field(None, description="Profile summary")

    class JobBase(BaseModel):
        title: constr(min_length=2, max_length=120) = Field(..., description="Job title")
        company: constr(min_length=2, max_length=120) = Field(..., description="Company name")
        location: constr(min_length=2, max_length=120) = Field(..., description="Job location")
        description: constr(min_length=10, max_length=5000) = Field(..., description="Job description")
        salary_min: Optional[int] = Field(None, ge=0, description="Minimum salary (annual USD)")
        salary_max: Optional[int] = Field(None, ge=0, description="Maximum salary (annual USD)")
        tags: List[constr(min_length=1, max_length=30)] = Field(default_factory=list, description="Job tags/keywords")

    class JobCreate(JobBase):
        pass

    class Job(JobBase):
        id: str = Field(..., description="Job identifier")
        created_at: datetime = Field(..., description="ISO timestamp of creation")

    class JobsListResponse(BaseModel):
        items: List[Job] = Field(..., description="Jobs for the current page")
        total: int = Field(..., description="Total number of jobs available")
        page: int = Field(..., ge=1, description="Current page number")
        size: int = Field(..., ge=1, description="Page size")

    # =========================
    # Utility / Dependencies
    # =========================

    def _raise_unauthorized() -> None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    # PUBLIC_INTERFACE
    def get_current_user(
        authorization: Optional[str] = Header(default=None, convert_underscores=False),
        x_session_token: Optional[str] = Header(default=None),
    ) -> User:
        """Authenticate request and return current user, if valid.

        Security controls applied:
        - Token read from Authorization: Bearer <token> or X-Session-Token header.
        - Token validated against in-memory session map.
        """
        token: Optional[str] = None
        if authorization:
            parts = authorization.split()
            if len(parts) == 2 and parts[0].lower() == "bearer":
                token = parts[1]
        if not token and x_session_token:
            token = x_session_token

        if not token:
            _raise_unauthorized()

        user_id = _InMemoryStore.sessions.get(token)
        if not user_id:
            _raise_unauthorized()

        user = _InMemoryStore.users.get(user_id)
        if not user:
            _raise_unauthorized()

        return user

    _seed_jobs()

    # =========================
    # Routes
    # =========================

    @app.get(
        "/",
        response_model=HealthResponse,
        summary="Health Check",
        tags=["health"],
    )
    def health_check() -> HealthResponse:
        """Readiness/liveness probe to assert service availability.

        Returns:
            HealthResponse: status field 'ok' when service is healthy.
        """
        return HealthResponse(status="ok")

    # ---------- Auth ----------

    @app.post(
        "/auth/login",
        response_model=AuthLoginResponse,
        summary="Login",
        description="Authenticate with email and password. Returns a session token for subsequent requests.",
        tags=["auth"],
    )
    def auth_login(payload: AuthLoginRequest) -> AuthLoginResponse:
        """Authenticate a user and return a session token.

        Note:
            This MVP does not verify passwords against a database and accepts any password meeting minimum criteria.
            A user is created in-memory on first login for a new email.

        Controls:
            - Validates email using EmailStr.
            - Validates password length.
            - Generates a cryptographically secure, random token (secrets.token_urlsafe).
        """
        # Create or fetch user
        user = None
        for u in _InMemoryStore.users.values():
            if u.email == payload.email:
                user = u
                break
        if not user:
            user_id = secrets.token_urlsafe(8)
            user = User(id=user_id, email=payload.email)
            _InMemoryStore.users[user_id] = user
            # Initialize empty profile
            _InMemoryStore.profiles[user_id] = UserProfile(
                user_id=user_id, full_name=payload.email.split("@")[0].title()
            )

        token = secrets.token_urlsafe(24)
        _InMemoryStore.sessions[token] = user.id

        # 24 hours validity hint (no server-side expiry enforcement in MVP)
        expires_in = int(timedelta(hours=24).total_seconds())

        return AuthLoginResponse(token=token, token_type="bearer", expires_in=expires_in)

    @app.post(
        "/auth/logout",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Logout",
        description="Invalidate the current session token.",
        tags=["auth"],
    )
    def auth_logout(current_user: User = Depends(get_current_user), authorization: Optional[str] = Header(default=None, convert_underscores=False), x_session_token: Optional[str] = Header(default=None)) -> None:
        """Invalidate the session corresponding to the provided token.

        Behavior:
            - Looks up token in Authorization or X-Session-Token header and removes it from the session store.
        """
        token: Optional[str] = None
        if authorization:
            parts = authorization.split()
            if len(parts) == 2 and parts[0].lower() == "bearer":
                token = parts[1]
        if not token and x_session_token:
            token = x_session_token

        if token and token in _InMemoryStore.sessions:
            # Safe deletion without logging sensitive token
            _InMemoryStore.sessions.pop(token, None)

    # ---------- Jobs ----------

    @app.get(
        "/jobs",
        response_model=JobsListResponse,
        summary="List jobs",
        description="Browse job listings with pagination and optional tag filtering.",
        tags=["jobs"],
    )
    def list_jobs(
        page: int = Query(1, ge=1, description="Page number starting from 1"),
        size: int = Query(10, ge=1, le=100, description="Page size"),
        q: Optional[str] = Query(None, description="Search term (title, company, location)"),
        tag: Optional[str] = Query(None, description="Filter by tag"),
    ) -> JobsListResponse:
        """List jobs with simple filtering and pagination."""
        jobs = list(_InMemoryStore.jobs.values())

        # Filter by search term
        if q:
            q_lower = q.lower()
            jobs = [
                j
                for j in jobs
                if q_lower in j.title.lower()
                or q_lower in j.company.lower()
                or q_lower in j.location.lower()
                or q_lower in j.description.lower()
            ]

        # Filter by single tag
        if tag:
            tag_l = tag.lower()
            jobs = [j for j in jobs if any(t.lower() == tag_l for t in j.tags)]

        total = len(jobs)
        start = (page - 1) * size
        end = start + size
        items = jobs[start:end]

        return JobsListResponse(items=items, total=total, page=page, size=size)

    @app.get(
        "/jobs/{job_id}",
        response_model=Job,
        summary="Get job",
        description="Retrieve a single job by its identifier.",
        tags=["jobs"],
    )
    def get_job(
        job_id: str = Path(..., description="Job identifier"),
    ) -> Job:
        """Retrieve a single job."""
        job = _InMemoryStore.jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
        return job

    @app.post(
        "/jobs",
        response_model=Job,
        status_code=status.HTTP_201_CREATED,
        summary="Create job (demo)",
        description="Create a job entry (MVP demo). Requires authentication.",
        tags=["jobs"],
    )
    def create_job(
        payload: JobCreate,
        current_user: User = Depends(get_current_user),
    ) -> Job:
        """Create a job listing (MVP)."""
        if payload.salary_min is not None and payload.salary_max is not None:
            if payload.salary_min > payload.salary_max:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="salary_min must be <= salary_max",
                )

        jid = secrets.token_urlsafe(8)
        job = Job(
            id=jid,
            created_at=datetime.now(tz=timezone.utc),
            **payload.model_dump(),
        )
        _InMemoryStore.jobs[jid] = job
        return job

    # ---------- Profiles ----------

    class ProfileUpdateRequest(BaseModel):
        full_name: Optional[constr(min_length=1, max_length=100)] = Field(None, description="Full name")
        headline: Optional[constr(max_length=140)] = Field(None, description="Headline")
        location: Optional[constr(max_length=120)] = Field(None, description="Location")
        skills: Optional[List[constr(min_length=1, max_length=40)]] = Field(None, description="Skills")
        bio: Optional[constr(max_length=2000)] = Field(None, description="Bio")

    @app.get(
        "/profiles/me",
        response_model=UserProfile,
        summary="Get my profile",
        description="Retrieve the profile of the current authenticated user.",
        tags=["profiles"],
    )
    def get_my_profile(current_user: User = Depends(get_current_user)) -> UserProfile:
        """Return current user's profile, creating a default one if missing."""
        prof = _InMemoryStore.profiles.get(current_user.id)
        if not prof:
            prof = UserProfile(user_id=current_user.id, full_name=current_user.email.split("@")[0].title())
            _InMemoryStore.profiles[current_user.id] = prof
        return prof

    @app.put(
        "/profiles/me",
        response_model=UserProfile,
        summary="Update my profile",
        description="Update fields in the current authenticated user's profile.",
        tags=["profiles"],
    )
    def update_my_profile(
        payload: ProfileUpdateRequest,
        current_user: User = Depends(get_current_user),
    ) -> UserProfile:
        """Update the current user's profile with provided fields."""
        existing = _InMemoryStore.profiles.get(current_user.id)
        if not existing:
            existing = UserProfile(user_id=current_user.id, full_name=current_user.email.split("@")[0].title())

        data = existing.model_dump()
        for k, v in payload.model_dump(exclude_unset=True).items():
            data[k] = v
        updated = UserProfile(**data)
        _InMemoryStore.profiles[current_user.id] = updated
        return updated

    return app


app = get_app()
