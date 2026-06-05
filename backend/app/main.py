from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks, Request, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from . import models, schemas, auth, database, stripe_utils, security
from .database import engine, get_db, init_db
from datetime import timedelta, datetime
import os
import re
import requests
from typing import List

try:
    from weasyprint import HTML
except Exception:
    class HTML:
        def __init__(self, string=None, **kwargs):
            pass
        def write_pdf(self, target, **kwargs):
            with open(target, "w") as f:
                f.write("PDF Mock Content (System libraries missing for WeasyPrint)")
from jinja2 import Environment, FileSystemLoader
from apscheduler.schedulers.background import BackgroundScheduler

app = FastAPI(title="ComplyScan API")

# ─── Security Middleware ───────────────────────────────────────────────────────
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:8002").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "Stripe-Signature"],
)

# Templates and Static files
templates = Jinja2Templates(directory="/home/team/shared/backend/app/templates")
app.mount("/static", StaticFiles(directory="/home/team/shared/backend/static"), name="static")

@app.get("/")
async def read_index():
    return FileResponse("/home/team/shared/backend/static/index.html")

# Initialize DB
init_db()

# Scheduler for Cron Jobs
scheduler = BackgroundScheduler()
scheduler.start()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Helper to get current user
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = auth.jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except auth.JWTError:
        raise credentials_exception
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# Helper to get admin user
async def get_admin_user(current_user: models.User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

@app.post("/auth/register", response_model=schemas.User)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # Input validation
    if not security.validate_email(user.email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    if len(user.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Handle tenant logic
    tenant_id = None
    if user.tenant_name:
        tenant = models.Tenant(name=user.tenant_name)
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
        tenant_id = tenant.id
    else:
        default_tenant = db.query(models.Tenant).filter(models.Tenant.name == "Default").first()
        if not default_tenant:
            default_tenant = models.Tenant(name="Default")
            db.add(default_tenant)
            db.commit()
            db.refresh(default_tenant)
        tenant_id = default_tenant.id

    hashed_password = auth.get_password_hash(user.password)
    new_user = models.User(email=user.email, password_hash=hashed_password, tenant_id=tenant_id)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/auth/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# --- Stripe Billing Routes ---

@app.post("/billing/checkout")
async def create_checkout(plan_name: str, current_user: models.User = Depends(get_current_user)):
    try:
        session = stripe_utils.create_checkout_session(
            tenant_id=current_user.tenant_id,
            plan_name=plan_name,
            customer_email=current_user.email
        )
        return {"checkout_url": session.url}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/billing/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')
    try:
        stripe_utils.handle_webhook(payload, sig_header)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "success"}

# --- Tenant & Domain Routes ---

@app.post("/domains", response_model=schemas.Domain)
def add_domain(domain: schemas.DomainCreate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    new_domain = models.Domain(url=domain.url, tenant_id=current_user.tenant_id)
    db.add(new_domain)
    db.commit()
    db.refresh(new_domain)
    return new_domain

@app.get("/domains", response_model=List[schemas.Domain])
def list_domains(current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(models.Domain).filter(models.Domain.tenant_id == current_user.tenant_id).all()

# --- Scanning Routes ---

@app.post("/scan", response_model=schemas.Scan)
async def start_scan(
    scan_req: schemas.ScanBase, 
    background_tasks: BackgroundTasks,
    current_user: models.User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    # Security: Validate URL
    if not security.validate_url(scan_req.url):
        raise HTTPException(status_code=400, detail="Invalid or blocked URL")
    if scan_req.compliance_type not in ("gdpr", "soc2", "ccpa", "all"):
        raise HTTPException(status_code=400, detail="Invalid compliance type")
    # Check if domain exists or create one
    domain = db.query(models.Domain).filter(
        models.Domain.url == scan_req.url, 
        models.Domain.tenant_id == current_user.tenant_id
    ).first()
    if not domain:
        domain = models.Domain(url=scan_req.url, tenant_id=current_user.tenant_id)
        db.add(domain)
        db.commit()
        db.refresh(domain)

    new_scan = models.Scan(
        user_id=current_user.id, 
        tenant_id=current_user.tenant_id,
        domain_id=domain.id,
        url=scan_req.url, 
        compliance_type=scan_req.compliance_type or "gdpr",
        status="pending"
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    
    background_tasks.add_task(run_scan_task, new_scan.id, scan_req.url, current_user.tenant_id, new_scan.compliance_type)
    
    return new_scan

@app.get("/scan/{scan_id}/status", response_model=schemas.Scan)
def get_scan_status(scan_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    scan = db.query(models.Scan).filter(
        models.Scan.id == scan_id, 
        models.Scan.tenant_id == current_user.tenant_id
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.get("/scan/{scan_id}/report", response_model=schemas.Scan)
def get_scan_report(scan_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    scan = db.query(models.Scan).filter(
        models.Scan.id == scan_id, 
        models.Scan.tenant_id == current_user.tenant_id
    ).first()
    if not scan or scan.status != "completed":
        raise HTTPException(status_code=404, detail="Report not ready or not found")
    return scan

@app.get("/scan/{scan_id}/report/pdf")
async def get_scan_report_pdf(scan_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    scan = db.query(models.Scan).filter(
        models.Scan.id == scan_id, 
        models.Scan.tenant_id == current_user.tenant_id
    ).first()
    if not scan or scan.status != "completed":
        raise HTTPException(status_code=404, detail="Report not ready or not found")
    
    # Generate PDF
    pdf_path = generate_pdf_report(scan)
    return FileResponse(pdf_path, media_type='application/pdf', filename=f"report_{scan_id}.pdf")

# --- Dashboard & Frontend ---

@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard(request: Request, scan_id: int = None, db: Session = Depends(get_db)):
    user_email = request.cookies.get("user_email", "demo@complyscan.com")
    user = db.query(models.User).filter(models.User.email == user_email).first()
    
    if not user:
        user = db.query(models.User).filter(models.User.email == "demo@complyscan.com").first()
    
    tenant_id = user.tenant_id if user else None
    
    if scan_id:
        scan = db.query(models.Scan).filter(
            models.Scan.id == scan_id, 
            models.Scan.tenant_id == tenant_id
        ).first()
    else:
        scan = db.query(models.Scan).filter(
            models.Scan.tenant_id == tenant_id
        ).order_by(models.Scan.created_at.desc()).first()
    
    scans = db.query(models.Scan).filter(
        models.Scan.tenant_id == tenant_id
    ).order_by(models.Scan.created_at.desc()).limit(10).all()
    
    tenant = user.tenant if user else None
    white_label = {
        "name": tenant.name if tenant else "ComplyScan",
        "logo_url": tenant.logo_url if tenant and tenant.logo_url else "/static/complyscan-logo.png",
        "brand_color": tenant.brand_color if tenant and tenant.brand_color else "#003366"
    }

    if not scan:
        dummy_scan = {
            "id": 0,
            "url": "No scans yet",
            "score": 0,
            "status": "none",
            "created_at": datetime.now(),
            "raw_data": {
                "cookie_categorization": {},
                "privacy_analysis": {"findings": [], "overall_policy_score": 0}
            }
        }
        return templates.TemplateResponse(
            request=request, 
            name="dashboard.html", 
            context={"scan": dummy_scan, "scans": [], "white_label": white_label}
        )

    return templates.TemplateResponse(
        request=request, 
        name="dashboard.html", 
        context={"scan": scan, "scans": scans, "white_label": white_label}
    )

@app.post("/quick-scan")
async def quick_scan(
    background_tasks: BackgroundTasks,
    url: str = Form(...),
    compliance_type: str = Form("gdpr"),
    db: Session = Depends(get_db)
):
    # Security: Validate URL
    if not security.validate_url(url):
        raise HTTPException(status_code=400, detail="Invalid or blocked URL")
    if compliance_type not in ("gdpr", "soc2", "ccpa", "all"):
        raise HTTPException(status_code=400, detail="Invalid compliance type")
    
    tenant = db.query(models.Tenant).filter(models.Tenant.name == "Demo Tenant").first()
    if not tenant:
        tenant = models.Tenant(name="Demo Tenant")
        db.add(tenant)
        db.commit()
        db.refresh(tenant)

    user = db.query(models.User).filter(models.User.email == "demo@complyscan.com").first()
    if not user:
        user = models.User(email="demo@complyscan.com", password_hash="dummy", tenant_id=tenant.id)
        db.add(user)
        db.commit()
        db.refresh(user)
    
    # Ensure domain exists
    domain = db.query(models.Domain).filter(models.Domain.url == url, models.Domain.tenant_id == tenant.id).first()
    if not domain:
        domain = models.Domain(url=url, tenant_id=tenant.id)
        db.add(domain)
        db.commit()
        db.refresh(domain)

    new_scan = models.Scan(user_id=user.id, tenant_id=tenant.id, domain_id=domain.id, url=url, compliance_type=compliance_type, status="pending")
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    
    background_tasks.add_task(run_scan_task, new_scan.id, url, tenant.id, compliance_type)
    
    response = RedirectResponse(url=f"/dashboard?scan_id={new_scan.id}", status_code=303)
    security.secure_cookie(response, key="user_email", value=user.email)
    return response

# --- Admin Panel Routes ---

@app.get("/admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    # Simple admin auth via env var key
    admin_key = request.headers.get("X-Admin-Key") or request.cookies.get("admin_key")
    if admin_key != os.getenv("ADMIN_SECRET_KEY", "admin"):
        raise HTTPException(status_code=403, detail="Admin access denied")
    # Set admin cookie for session
    total_tenants = db.query(models.Tenant).count()
    total_scans = db.query(models.Scan).count()
    total_users = db.query(models.User).count()
    
    # Scan type breakdown
    gdpr_scans = db.query(models.Scan).filter(models.Scan.compliance_type == "gdpr").count()
    soc2_scans = db.query(models.Scan).filter(models.Scan.compliance_type == "soc2").count()
    ccpa_scans = db.query(models.Scan).filter(models.Scan.compliance_type == "ccpa").count()
    
    active_tenants = db.query(models.Tenant).filter(models.Tenant.subscription_status == "active").all()
    
    # Simple MRR calculation (Mock logic)
    mrr = 0
    for t in active_tenants:
        if t.plan == "Starter": mrr += 99
        elif t.plan == "Growth": mrr += 299
        elif t.plan == "Enterprise": mrr += 999
        
    recent_scans = db.query(models.Scan).order_by(models.Scan.created_at.desc()).limit(10).all()
    tenants = db.query(models.Tenant).all()

    return templates.TemplateResponse(
        request=request, 
        name="admin-dashboard.html", 
        context={
            "total_tenants": total_tenants,
            "total_scans": total_scans,
            "total_users": total_users,
            "gdpr_scans": gdpr_scans,
            "soc2_scans": soc2_scans,
            "ccpa_scans": ccpa_scans,
            "mrr": mrr,
            "recent_scans": recent_scans,
            "tenants": tenants[:5] # Just show first 5 on dashboard
        }
    )

@app.get("/admin/tenants", response_class=HTMLResponse)
async def admin_tenants(request: Request, db: Session = Depends(get_db)):
    # Admin auth
    admin_key = request.headers.get("X-Admin-Key") or request.cookies.get("admin_key")
    if admin_key != os.getenv("ADMIN_SECRET_KEY", "admin"):
        raise HTTPException(status_code=403, detail="Admin access denied")
    tenants = db.query(models.Tenant).all()
    # Add domain/scan counts to each tenant object for the template
    for t in tenants:
        t.domain_count = db.query(models.Domain).filter(models.Domain.tenant_id == t.id).count()
        t.scan_count = db.query(models.Scan).filter(models.Scan.tenant_id == t.id).count()
        # Mocking usage percentage
        limit = 1 if t.plan == "Starter" else 5 if t.plan == "Growth" else 100
        t.usage_percent = min(100, (t.domain_count / limit) * 100)
    
    return templates.TemplateResponse(
        request=request,
        name="admin-tenants.html",
        context={"tenants": tenants}
    )

@app.get("/admin/revenue", response_class=HTMLResponse)
async def admin_revenue(request: Request, db: Session = Depends(get_db)):
    # Admin auth
    admin_key = request.headers.get("X-Admin-Key") or request.cookies.get("admin_key")
    if admin_key != os.getenv("ADMIN_SECRET_KEY", "admin"):
        raise HTTPException(status_code=403, detail="Admin access denied")
    active_tenants = db.query(models.Tenant).filter(models.Tenant.subscription_status == "active").all()
    
    plan_counts = {"Starter": 0, "Growth": 0, "Enterprise": 0}
    mrr = 0
    for t in active_tenants:
        plan_counts[t.plan] = plan_counts.get(t.plan, 0) + 1
        if t.plan == "Starter": mrr += 99
        elif t.plan == "Growth": mrr += 299
        elif t.plan == "Enterprise": mrr += 999
        
    return templates.TemplateResponse(
        request=request,
        name="admin-revenue.html",
        context={
            "mrr": mrr,
            "plan_counts": plan_counts,
            "total_active": len(active_tenants)
        }
    )

# --- Background Task logic ---

def run_scan_task(scan_id: int, url: str, tenant_id: int, compliance_type: str = "gdpr"):
    db = next(get_db())
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        return

    try:
        scan.status = "processing"
        db.commit()

        # 1. Trigger Crawler
        crawler_url = os.getenv("CRAWLER_URL", "http://localhost:8000/crawl")
        try:
            crawler_response = requests.post(crawler_url, json={"url": url, "compliance_type": compliance_type}, timeout=120)
            if crawler_response.status_code != 200:
                scan.status = "failed"
                scan.raw_data = {"error": f"Crawler returned {crawler_response.status_code}"}
                db.commit()
                return
            crawler_full_res = crawler_response.json()
            crawler_data = crawler_full_res.get("data") if crawler_full_res.get("success") else None
            if not crawler_data:
                scan.status = "failed"
                scan.raw_data = {"error": "Crawler failed or returned invalid data", "crawler_raw": crawler_full_res}
                db.commit()
                return
        except Exception as e:
            scan.status = "failed"
            scan.raw_data = {"error": f"Crawler connection error: {str(e)}"}
            db.commit()
            return

        # 2. Trigger AI Analyst
        analyst_url = os.getenv("ANALYST_URL", "http://localhost:8001/analyze-crawler")
        try:
            # Add compliance_type to the payload
            crawler_data["compliance_type"] = compliance_type
            response = requests.post(analyst_url, json=crawler_data, timeout=120)
            if response.status_code == 200:
                result = response.json()
                scan.score = result.get("overall_score", 0)
                scan.raw_data = result
                scan.status = "completed"
                
                # Check for alerts
                if scan.score < 50:
                    send_alert_email(scan)
                    new_alert = models.Alert(
                        scan_id=scan.id,
                        tenant_id=tenant_id,
                        type="low_score",
                        severity="high",
                        message=f"Scan score is low for {compliance_type.upper()}: {scan.score}"
                    )
                    db.add(new_alert)
            else:
                scan.status = "failed"
                scan.raw_data = {"error": f"Analyst returned {response.status_code}", "crawler_raw": crawler_data}
        except Exception as e:
            scan.status = "failed"
            scan.raw_data = {"error": f"Analyst connection error: {str(e)}", "crawler_raw": crawler_data}

        db.commit()
    except Exception as e:
        scan.status = "failed"
        scan.raw_data = {"error": f"Internal error: {str(e)}"}
        db.commit()

def send_alert_email(scan: models.Scan):
    print(f"ALERT: Scan {scan.id} for {scan.url} has low score: {scan.score}")

def generate_pdf_report(scan: models.Scan):
    template_dir = "/home/team/shared/reports"
    template_path = os.path.join(template_dir, "template.html")
    output_dir = "/home/team/shared/reports/output"
    output_path = os.path.join(output_dir, f"report_{scan.id}.pdf")
    
    os.makedirs(template_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    if not os.path.exists(template_path):
        # Fallback if file was deleted
        with open(template_path, "w") as f:
            f.write("""<html><body><h1>ComplyScan Report</h1><p>URL: {{ url }}</p><p>Score: {{ score }}</p></body></html>""")
    
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("template.html")
    html_out = template.render(
        url=scan.url, 
        score=scan.score, 
        status=scan.status, 
        raw_data=scan.raw_data,
        compliance_type=scan.compliance_type,
        date=scan.created_at.strftime("%Y-%m-%d %H:%M:%S")
    )
    
    HTML(string=html_out).write_pdf(output_path)
    return output_path

def scheduled_scan():
    db = next(get_db())
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    old_scans = db.query(models.Scan).filter(
        models.Scan.created_at <= seven_days_ago,
        models.Scan.status == "completed"
    ).all()
    
    for old_scan in old_scans:
        new_scan = models.Scan(
            user_id=old_scan.user_id, 
            tenant_id=old_scan.tenant_id,
            domain_id=old_scan.domain_id,
            url=old_scan.url, 
            compliance_type=old_scan.compliance_type,
            status="pending"
        )
        db.add(new_scan)
        db.commit()
        run_scan_task(new_scan.id, new_scan.url, old_scan.tenant_id, old_scan.compliance_type)

scheduler.add_job(scheduled_scan, 'interval', days=7)
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
/home/engine/.bashrc: line 1: syntax error near unexpected token `('
/home/engine/.bashrc: line 1: `. /etc/profile.d/workload-containment.shn# ~/.bashrc: executed by bash(1) for non-login shells.'
