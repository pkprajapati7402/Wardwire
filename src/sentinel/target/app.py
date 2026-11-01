"""ShopAPI — Demo e-commerce target application instrumented with Sentinel SDK."""

from __future__ import annotations

import random
from typing import Any, Dict, List, Optional

from faker import Faker
from fastapi import FastAPI, Header, HTTPException, Query, Response, status
from pydantic import BaseModel

from sentinel.core.config import settings
from sentinel.sdk.middleware import SentinelMiddleware

fake = Faker()
Faker.seed(42)
random.seed(42)

app = FastAPI(
    title="ShopAPI Demo Target",
    version="1.0.0",
    description="Demo e-commerce API monitored by Wardwire / Sentinel.",
    docs_url="/docs",
    openapi_url="/openapi.json",
)

# Seed realistic in-memory catalogue
PRODUCTS: List[Dict[str, Any]] = []
for i in range(1, 101):
    PRODUCTS.append({
        "id": i,
        "name": fake.catch_phrase(),
        "price": round(random.uniform(9.99, 499.99), 2),
        "category": random.choice(["electronics", "apparel", "home", "books"]),
        "stock": random.randint(5, 200),
    })

ORDERS: Dict[int, Dict[str, Any]] = {}
for i in range(1001, 1101):
    ORDERS[i] = {
        "order_id": i,
        "user_id": f"u_{random.randint(100, 200)}",
        "items": random.randint(1, 5),
        "total": round(random.uniform(20.0, 500.0), 2),
        "status": random.choice(["shipped", "delivered", "processing"]),
    }

USERS: Dict[str, Dict[str, Any]] = {}
for i in range(100, 201):
    uid = f"u_{i}"
    USERS[uid] = {
        "id": uid,
        "username": fake.user_name(),
        "email": fake.email(),
        "tier": random.choice(["standard", "gold", "partner"]),
    }

CARTS: Dict[str, List[Dict[str, Any]]] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class CartItem(BaseModel):
    product_id: int
    quantity: int = 1


@app.get("/healthz")
def healthz():
    return {"status": "ok", "app": "ShopAPI"}


@app.post("/auth/login")
def login(req: LoginRequest, response: Response):
    # Simulate realistic credentials
    if req.username == "admin" and req.password == "admin123":
        return {"token": "token_admin_xyz", "user_id": "u_admin"}
    if req.username.startswith("user") and req.password == "correct_pass_2026":
        return {"token": f"token_{req.username}", "user_id": f"u_{req.username}"}

    response.status_code = status.HTTP_401_UNAUTHORIZED
    return {"detail": "Invalid credentials"}


@app.get("/products")
def get_products(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    category: Optional[str] = None,
):
    filtered = PRODUCTS
    if category:
        filtered = [p for p in filtered if p["category"] == category]
    return {
        "total": len(filtered),
        "items": filtered[offset : offset + limit],
    }


@app.get("/products/{product_id}")
def get_product(product_id: int):
    for p in PRODUCTS:
        if p["id"] == product_id:
            return p
    raise HTTPException(status_code=404, detail="Product not found")


@app.get("/search")
def search_products(q: str = Query("", min_length=0)):
    if not q:
        return {"query": q, "results": PRODUCTS[:5]}
    results = [p for p in PRODUCTS if q.lower() in p["name"].lower()]
    return {"query": q, "results": results}


@app.get("/cart")
def get_cart(x_account_id: Optional[str] = Header(None)):
    account = x_account_id or "anonymous"
    return {"account_id": account, "items": CARTS.get(account, [])}


@app.post("/cart")
def add_to_cart(item: CartItem, x_account_id: Optional[str] = Header(None)):
    account = x_account_id or "anonymous"
    CARTS.setdefault(account, []).append(item.model_dump())
    return {"status": "item_added", "account_id": account}


@app.post("/checkout")
def checkout(x_account_id: Optional[str] = Header(None)):
    account = x_account_id or "anonymous"
    cart = CARTS.get(account, [])
    if not cart:
        raise HTTPException(status_code=400, detail="Cart is empty")
    order_id = random.randint(2000, 9999)
    CARTS[account] = []
    return {"order_id": order_id, "status": "confirmed"}


@app.get("/orders/{order_id}")
def get_order(order_id: int, x_account_id: Optional[str] = Header(None)):
    # Vulnerable BOLA demonstration endpoint: does not enforce authorization
    if order_id in ORDERS:
        return ORDERS[order_id]
    raise HTTPException(status_code=404, detail="Order not found")


@app.get("/users/{user_id}/profile")
def get_user_profile(user_id: str, x_account_id: Optional[str] = Header(None)):
    if user_id in USERS:
        return USERS[user_id]
    raise HTTPException(status_code=404, detail="User not found")


@app.get("/admin/reports")
def get_admin_reports(x_api_key: Optional[str] = Header(None)):
    if x_api_key != "key_partner_admin":
        raise HTTPException(status_code=403, detail="Admin authorization required")
    return {"active_users": 1420, "revenue_mtd": 89450.0}


# Undocumented routes (testing inventory and probing detection)
@app.get("/v0/internal/catalog", include_in_schema=False)
def internal_catalog():
    return {"internal_code": "alpha_9", "products": PRODUCTS[:10]}


@app.get("/legacy/user_export", include_in_schema=False)
def legacy_export():
    return {"export_status": "deprecated", "data": list(USERS.values())}


# Add Sentinel Middleware
app.add_middleware(
    SentinelMiddleware,
    ingest_url=f"{settings.API_URL}/v1/events",
    api_key=settings.INGEST_API_KEY,
    flush_interval_sec=0.2,
    batch_size=25,
)


def run_target():
    import uvicorn
    uvicorn.run("sentinel.target.app:app", host="0.0.0.0", port=8000, reload=False)  # nosec B104


if __name__ == "__main__":
    run_target()

