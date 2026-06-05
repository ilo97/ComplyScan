from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime

Base = declarative_base()

class Tenant(Base):
    __tablename__ = 'tenants'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    logo_url = Column(String, nullable=True)
    brand_color = Column(String, nullable=True) # Hex code
    stripe_customer_id = Column(String, nullable=True)
    subscription_status = Column(String, default="inactive") # active, trialing, past_due, canceled
    plan = Column(String, default="Starter")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    users = relationship("User", back_populates="tenant")
    domains = relationship("Domain", back_populates="tenant")
    scans = relationship("Scan", back_populates="tenant")

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    is_admin = Column(Integer, default=0) # 0: False, 1: True
    tenant_id = Column(Integer, ForeignKey('tenants.id'))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    tenant = relationship("Tenant", back_populates="users")
    scans = relationship("Scan", back_populates="owner")

class Domain(Base):
    __tablename__ = 'domains'
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey('tenants.id'))
    url = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    tenant = relationship("Tenant", back_populates="domains")
    scans = relationship("Scan", back_populates="domain")

class Scan(Base):
    __tablename__ = 'scans'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    tenant_id = Column(Integer, ForeignKey('tenants.id'))
    domain_id = Column(Integer, ForeignKey('domains.id'), nullable=True)
    url = Column(String)
    compliance_type = Column(String, default="gdpr")
    status = Column(String)  # 'pending', 'processing', 'completed', 'failed'
    score = Column(Float, nullable=True)
    raw_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    owner = relationship("User", back_populates="scans")
    tenant = relationship("Tenant", back_populates="scans")
    domain = relationship("Domain", back_populates="scans")
    alerts = relationship("Alert", back_populates="scan")

class Alert(Base):
    __tablename__ = 'alerts'
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    tenant_id = Column(Integer, ForeignKey('tenants.id'), nullable=True)
    type = Column(String)
    severity = Column(String) # 'low', 'medium', 'high', 'critical'
    message = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    scan = relationship("Scan", back_populates="alerts")
