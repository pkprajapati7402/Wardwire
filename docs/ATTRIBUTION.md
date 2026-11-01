# Wardwire — Data and Software Attribution

## 1. Synthetic Data Declaration

All datasets, user accounts, orders, products, and telemetry events utilized in Wardwire, the Attack Lab, and evaluation benchmarks are **100% synthetically generated** using deterministic generators (`sentinel.sim.traffic_generator` and `Faker`).
No real personal data, proprietary enterprise logs, or external third-party traffic were used.

---

## 2. Third-Party Open Source Libraries

| Library | License | Purpose in Wardwire |
|---|---|---|
| **FastAPI** | MIT | Core REST API, Ingestion Gateway, and ShopAPI Target |
| **Uvicorn** | BSD-3-Clause | ASGI Server Implementation |
| **Pydantic** | MIT | Data Validation & Strict Boundary Schemas |
| **Pydantic-Settings** | MIT | Environment Configuration Management |
| **Redis-py** | MIT | Async Redis Streams & Caching Client |
| **SQLAlchemy** | MIT | Database ORM & Connection Pool (SQLite WAL / PostgreSQL) |
| **River** | BSD-3-Clause | Online Machine Learning & Streaming Anomaly Trees (`HalfSpaceTrees`) |
| **Scikit-Learn** | BSD-3-Clause | Offline Isolation Forest Comparator for Benchmark Evaluation |
| **NumPy & SciPy** | BSD-3-Clause | Statistical Computations & Jensen-Shannon Divergence |
| **HTTPX** | BSD-3-Clause | Async HTTP Telemetry Client in Middleware & Simulator |
| **Faker** | MIT | Deterministic Synthetic Seed Data Generation |
| **React & Vite** | MIT | Frontend Single-Page Application Framework & Build Tooling |
| **Tailwind CSS** | MIT | Modern Responsive Utility Styling |
| **Lucide React** | ISC | Vector Interface Icons |
| **Bandit** | Apache-2.0 | Static Application Security Testing (SAST) |
| **Pip-Audit** | Apache-2.0 | Dependency Vulnerability Auditing |
| **CycloneDX-py** | Apache-2.0 | Software Bill of Materials (SBOM) Generation |

