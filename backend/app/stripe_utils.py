import stripe
import os
from sqlalchemy.orm import Session
from . import models

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

# Plan mapping (Prices should be created in Stripe dashboard)
PLANS = {
    "Starter": os.getenv("STRIPE_PRICE_STARTER", "price_starter_id"),
    "Growth": os.getenv("STRIPE_PRICE_GROWTH", "price_growth_id"),
    "Enterprise": os.getenv("STRIPE_PRICE_ENTERPRISE", "price_enterprise_id"),
}

def create_checkout_session(tenant_id: int, plan_name: str, customer_email: str):
    price_id = PLANS.get(plan_name)
    if not price_id:
        raise ValueError("Invalid plan name")

    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price': price_id,
            'quantity': 1,
        }],
        mode='subscription',
        subscription_data={
            'trial_period_days': 7,
        },
        success_url=os.getenv("BASE_URL", "http://localhost:8002") + "/dashboard?session_id={CHECKOUT_SESSION_ID}",
        cancel_url=os.getenv("BASE_URL", "http://localhost:8002") + "/billing",
        customer_email=customer_email,
        metadata={
            "tenant_id": tenant_id,
            "plan_name": plan_name
        }
    )
    return session

def handle_webhook(payload, sig_header):
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        # Invalid payload
        raise e
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        raise e

    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        # Fullfill the purchase
        _handle_checkout_completed(session)
    elif event['type'] == 'customer.subscription.updated':
        subscription = event['data']['object']
        _handle_subscription_updated(subscription)
    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        _handle_subscription_deleted(subscription)

    return True

def _handle_checkout_completed(session):
    from .database import SessionLocal
    db = SessionLocal()
    tenant_id = session['metadata'].get('tenant_id')
    plan_name = session['metadata'].get('plan_name')
    stripe_customer_id = session['customer']
    
    if tenant_id:
        tenant = db.query(models.Tenant).filter(models.Tenant.id == tenant_id).first()
        if tenant:
            tenant.stripe_customer_id = stripe_customer_id
            tenant.subscription_status = "active"
            tenant.plan = plan_name
            db.commit()
    db.close()

def _handle_subscription_updated(subscription):
    from .database import SessionLocal
    db = SessionLocal()
    stripe_customer_id = subscription['customer']
    status = subscription['status']
    
    tenant = db.query(models.Tenant).filter(models.Tenant.stripe_customer_id == stripe_customer_id).first()
    if tenant:
        tenant.subscription_status = status
        # Update plan if changed (simplified)
        db.commit()
    db.close()

def _handle_subscription_deleted(subscription):
    from .database import SessionLocal
    db = SessionLocal()
    stripe_customer_id = subscription['customer']
    
    tenant = db.query(models.Tenant).filter(models.Tenant.stripe_customer_id == stripe_customer_id).first()
    if tenant:
        tenant.subscription_status = "canceled"
        db.commit()
    db.close()
