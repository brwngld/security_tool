from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.web.config import WebConfig, load_web_config
from app.web.db import Base, make_engine, make_session_factory
from app.web.models import AuditEventRecord, Job, Report, Target, User
from app.web.security import csrf_token, sign_session, verify_csrf_token, verify_session
from app.web.services import authenticate_user, bootstrap_admin, create_job, create_target, create_user

SESSION_COOKIE = "pshield_session"
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app(config: WebConfig | None = None) -> FastAPI:
    active_config = config or load_web_config()
    engine = make_engine(active_config)
    Base.metadata.create_all(engine)
    session_factory = make_session_factory(active_config)

    with session_factory() as session:
        bootstrap_admin(session, active_config)
        session.commit()

    web_app = FastAPI(title="PsyberShield Dashboard")
    web_app.state.config = active_config
    web_app.state.session_factory = session_factory
    web_app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    templates = Jinja2Templates(directory=TEMPLATE_DIR)

    @web_app.exception_handler(401)
    def unauthorized_handler(request: Request, exc: HTTPException):
        return RedirectResponse("/login", status_code=303)

    def get_db() -> Session:
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    def current_user(request: Request, db: Session = Depends(get_db)) -> User:
        token = request.cookies.get(SESSION_COOKIE)
        user_id = verify_session(token or "", active_config.secret_key) if token else None
        if user_id is None:
            raise HTTPException(status_code=401)
        user = db.get(User, user_id)
        if user is None or not user.is_active:
            raise HTTPException(status_code=401)
        return user

    def optional_user(request: Request, db: Session = Depends(get_db)) -> User | None:
        token = request.cookies.get(SESSION_COOKIE)
        user_id = verify_session(token or "", active_config.secret_key) if token else None
        return db.get(User, user_id) if user_id is not None else None

    def require_operator(user: User = Depends(current_user)) -> User:
        if user.role not in {"admin", "operator"}:
            raise HTTPException(status_code=403)
        return user

    def require_admin(user: User = Depends(current_user)) -> User:
        if user.role != "admin":
            raise HTTPException(status_code=403)
        return user

    def csrf_for_request(request: Request) -> str:
        return csrf_token(request.cookies.get(SESSION_COOKIE, ""), active_config.secret_key)

    def require_csrf(request: Request, submitted_token: str) -> None:
        if not verify_csrf_token(request.cookies.get(SESSION_COOKIE, ""), submitted_token, active_config.secret_key):
            raise HTTPException(status_code=403, detail="Invalid CSRF token.")

    def render(request: Request, template: str, context: dict) -> HTMLResponse:
        context.setdefault("csrf_token", csrf_for_request(request))
        return templates.TemplateResponse(request, template, context)

    @web_app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @web_app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request, user: User | None = Depends(optional_user)):
        if user is not None:
            return RedirectResponse("/", status_code=303)
        return render(request, "login.html", {"error": None})

    @web_app.post("/login")
    def login(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
        user = authenticate_user(db, email, password)
        if user is None:
            return templates.TemplateResponse(request, "login.html", {"error": "Invalid login"}, status_code=400)
        db.commit()
        redirect = RedirectResponse("/", status_code=303)
        redirect.set_cookie(
            SESSION_COOKIE,
            sign_session(user.id, active_config.secret_key),
            httponly=True,
            samesite="lax",
        )
        return redirect

    @web_app.post("/logout")
    def logout(request: Request, csrf_token: str = Form("")):
        require_csrf(request, csrf_token)
        redirect = RedirectResponse("/login", status_code=303)
        redirect.delete_cookie(SESSION_COOKIE)
        return redirect

    @web_app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
        jobs = db.scalars(select(Job).order_by(Job.created_at.desc()).limit(8)).all()
        targets = db.scalars(select(Target).order_by(Target.created_at.desc()).limit(8)).all()
        return render(request, "dashboard.html", {"user": user, "jobs": jobs, "targets": targets})

    @web_app.get("/targets", response_class=HTMLResponse)
    def targets_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
        targets = db.scalars(select(Target).order_by(Target.created_at.desc())).all()
        return render(request, "targets.html", {"user": user, "targets": targets})

    @web_app.post("/targets")
    def add_target(
        request: Request,
        name: str = Form(...),
        url: str = Form(...),
        csrf_token: str = Form(""),
        user: User = Depends(require_operator),
        db: Session = Depends(get_db),
    ):
        require_csrf(request, csrf_token)
        create_target(db, name=name, url=url, created_by_user_id=user.id)
        db.commit()
        return RedirectResponse("/targets", status_code=303)

    @web_app.get("/jobs", response_class=HTMLResponse)
    def jobs_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
        jobs = db.scalars(select(Job).order_by(Job.created_at.desc()).limit(100)).all()
        return render(request, "jobs.html", {"user": user, "jobs": jobs})

    @web_app.get("/jobs/new", response_class=HTMLResponse)
    def new_job_page(request: Request, user: User = Depends(require_operator), db: Session = Depends(get_db)):
        targets = db.scalars(select(Target).order_by(Target.name.asc())).all()
        return render(request, "new_job.html", {"user": user, "targets": targets})

    @web_app.post("/jobs")
    def add_job(
        request: Request,
        job_type: str = Form(...),
        target_id: str | None = Form(None),
        target_url: str | None = Form(None),
        root: str | None = Form(None),
        old_report: str | None = Form(None),
        new_report: str | None = Form(None),
        report_path: str | None = Form(None),
        logs: str | None = Form(None),
        baseline_path: str | None = Form(None),
        extra_paths: str | None = Form(None),
        env_file: str | None = Form(None),
        nginx_config: str | None = Form(None),
        policy_path: str | None = Form(None),
        audit_log: str | None = Form(None),
        incident_report: str | None = Form(None),
        tail_file: str | None = Form(None),
        journal_unit: str | None = Form(None),
        event_log_name: str | None = Form(None),
        auth_method: str | None = Form(None),
        login_url: str | None = Form(None),
        username: str | None = Form(None),
        password_env: str | None = Form(None),
        auth_check_url: str | None = Form(None),
        browser_username_selector: str | None = Form(None),
        browser_password_selector: str | None = Form(None),
        browser_submit_selector: str | None = Form(None),
        storage_state: str | None = Form(None),
        session_file: str | None = Form(None),
        cookie: str | None = Form(None),
        include_osv: bool = Form(False),
        compact: bool = Form(True),
        browser_headless: bool = Form(True),
        block_threshold: int = Form(5),
        max_pages: int = Form(100),
        max_depth: int = Form(2),
        csrf_token: str = Form(""),
        user: User = Depends(require_operator),
        db: Session = Depends(get_db),
    ):
        require_csrf(request, csrf_token)
        parsed_target_id = int(target_id) if target_id and target_id.isdigit() else None
        target = db.get(Target, parsed_target_id) if parsed_target_id else None
        resolved_url = target.url if target is not None else target_url
        params = {
            "target_url": resolved_url,
            "root": root or ".",
            "old_report": old_report,
            "new_report": new_report,
            "report_path": report_path,
            "logs": logs,
            "baseline_path": baseline_path,
            "extra_paths": extra_paths,
            "env_file": env_file,
            "nginx_config": nginx_config,
            "policy_path": policy_path,
            "audit_log": audit_log,
            "incident_report": incident_report,
            "tail_file": tail_file,
            "journal_unit": journal_unit,
            "event_log_name": event_log_name,
            "auth_method": auth_method,
            "login_url": login_url,
            "username": username,
            "auth_env_ref": password_env,
            "auth_check_url": auth_check_url,
            "browser_username_selector": browser_username_selector,
            "browser_password_selector": browser_password_selector,
            "browser_submit_selector": browser_submit_selector,
            "storage_state": storage_state,
            "session_file": session_file,
            "cookie": cookie,
            "include_osv": include_osv,
            "compact": compact,
            "browser_headless": browser_headless,
            "block_threshold": block_threshold,
            "max_pages": max_pages,
            "max_depth": max_depth,
            "seed_robots": True,
            "seed_sitemap": True,
        }
        try:
            job = create_job(
                db,
                job_type=job_type,
                created_by_user_id=user.id,
                target_id=target.id if target is not None else None,
                target_url=resolved_url,
                params=params,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        db.commit()
        return RedirectResponse(f"/jobs/{job.id}", status_code=303)

    @web_app.get("/jobs/{job_id}", response_class=HTMLResponse)
    def job_detail(job_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
        job = db.get(Job, job_id)
        if job is None:
            raise HTTPException(status_code=404)
        reports = db.scalars(select(Report).where(Report.job_id == job.id)).all()
        events = db.scalars(select(AuditEventRecord).where(AuditEventRecord.job_id == job.id).order_by(AuditEventRecord.created_at.desc())).all()
        return render(request, "job_detail.html", {"user": user, "job": job, "reports": reports, "events": events})

    @web_app.get("/reports/{report_id}/download/{format_name}")
    def download_report(report_id: int, format_name: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
        report = db.get(Report, report_id)
        if report is None:
            raise HTTPException(status_code=404)
        path_map = {"json": report.json_path, "markdown": report.markdown_path, "html": report.html_path}
        path_value = path_map.get(format_name)
        if path_value is None:
            raise HTTPException(status_code=404)
        path = Path(path_value)
        if not path.exists():
            raise HTTPException(status_code=404)
        return FileResponse(path)

    @web_app.get("/reports/{report_id}/preview/{format_name}", response_class=HTMLResponse)
    def preview_report(report_id: int, format_name: str, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
        report = db.get(Report, report_id)
        if report is None:
            raise HTTPException(status_code=404)
        path_map = {"json": report.json_path, "markdown": report.markdown_path, "html": report.html_path}
        path_value = path_map.get(format_name)
        if path_value is None:
            raise HTTPException(status_code=404)
        path = Path(path_value)
        if not path.exists():
            raise HTTPException(status_code=404)
        if format_name == "html":
            content = ""
        else:
            content = path.read_text(encoding="utf-8", errors="replace")[:200_000]
        return render(
            request,
            "report_preview.html",
            {"user": user, "report": report, "format_name": format_name, "content": content},
        )

    @web_app.get("/audit", response_class=HTMLResponse)
    def audit_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
        events = db.scalars(select(AuditEventRecord).order_by(AuditEventRecord.created_at.desc()).limit(100)).all()
        return render(request, "audit.html", {"user": user, "events": events})

    @web_app.get("/admin/users", response_class=HTMLResponse)
    def users_page(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
        users = db.scalars(select(User).order_by(User.email.asc())).all()
        return render(request, "users.html", {"user": user, "users": users})

    @web_app.post("/admin/users")
    def add_user(
        request: Request,
        email: str = Form(...),
        password: str = Form(...),
        role: str = Form("viewer"),
        csrf_token: str = Form(""),
        user: User = Depends(require_admin),
        db: Session = Depends(get_db),
    ):
        require_csrf(request, csrf_token)
        create_user(db, email=email, password=password, role=role)
        db.commit()
        return RedirectResponse("/admin/users", status_code=303)

    @web_app.post("/admin/users/{user_id}/toggle")
    def toggle_user(user_id: int, request: Request, csrf_token: str = Form(""), user: User = Depends(require_admin), db: Session = Depends(get_db)):
        require_csrf(request, csrf_token)
        target_user = db.get(User, user_id)
        if target_user is None:
            raise HTTPException(status_code=404)
        if target_user.id == user.id:
            raise HTTPException(status_code=400, detail="Admins cannot disable their own account.")
        target_user.is_active = not target_user.is_active
        db.commit()
        return RedirectResponse("/admin/users", status_code=303)

    return web_app
