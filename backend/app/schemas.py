from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Any
from datetime import datetime

class TenantBase(BaseModel):
    name: str
    logo_url: Optional[str] = None
    brand_color: Optional[str] = None

class TenantCreate(TenantBase):
    pass

class Tenant(TenantBase):
    id: int
    stripe_customer_id: Optional[str] = None
    subscription_status: str
    plan: str
    created_at: datetime

    class Config:
        from_attributes = True

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str
    tenant_name: Optional[str] = None # For onboarding

class User(UserBase):
    id: int
    is_admin: int
    tenant_id: int
    created_at: datetime

    class Config:
        from_attributes = True

class DomainBase(BaseModel):
    url: str

class DomainCreate(DomainBase):
    pass

class Domain(DomainBase):
    id: int
    tenant_id: int
    created_at: datetime

    class Config:
        from_attributes = True

class ScanBase(BaseModel):
    url: str
    compliance_type: Optional[str] = "gdpr"

class ScanCreate(ScanBase):
    user_id: int
    tenant_id: int
    domain_id: Optional[int] = None

class Scan(ScanBase):
    id: int
    status: str
    score: Optional[float] = None
    raw_data: Optional[Dict[str, Any]] = None
    created_at: datetime
    tenant_id: int
    domain_id: Optional[int] = None

    class Config:
        from_attributes = True

class AlertBase(BaseModel):
    type: str
    severity: str
    message: str

class Alert(AlertBase):
    id: int
    scan_id: int
    tenant_id: Optional[int] = None
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None
    tenant_id: Optional[int] = None
