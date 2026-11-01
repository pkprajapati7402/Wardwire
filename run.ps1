# Wardwire Windows PowerShell Runner Script
param (
    [Parameter(Position=0)]
    [string]$Command = "help"
)

$VENV_PYTHON = ".\.venv\Scripts\python.exe"

switch ($Command.ToLower()) {
    "init" {
        Write-Host "[*] Generating .env with cryptographically secure secrets..." -ForegroundColor Cyan
        & $VENV_PYTHON scripts/init_env.py
    }
    "test" {
        Write-Host "[*] Running Pytest test suite..." -ForegroundColor Cyan
        & $VENV_PYTHON -m pytest tests/ -v
    }
    "eval" {
        Write-Host "[*] Running Evaluation Harness across all attack families..." -ForegroundColor Cyan
        & $VENV_PYTHON -m sentinel.eval.harness --seed 42 --output reports/
    }
    "bench" {
        Write-Host "[*] Running Throughput, Latency, and Memory benchmarks..." -ForegroundColor Cyan
        & $VENV_PYTHON -m sentinel.eval.benchmark --events 5000 --output reports/bench.json
    }
    "scan" {
        Write-Host "[*] Running Pip-Audit and Bandit security scans..." -ForegroundColor Cyan
        & $VENV_PYTHON -m pip_audit
        & $VENV_PYTHON -m bandit -r src/ -ll
    }
    "docker-demo" {
        Write-Host "[*] Launching full stack via Docker Compose..." -ForegroundColor Cyan
        docker compose --profile lab up -d
        Write-Host "[*] Seeding initial history dataset..." -ForegroundColor Cyan
        Start-Sleep -Seconds 3
        & $VENV_PYTHON scripts/wait_and_seed.py
        Write-Host "[+] All services live! Open http://localhost:3000 in your browser." -ForegroundColor Green
    }
    "docker-down" {
        Write-Host "[*] Stopping Docker Compose services..." -ForegroundColor Cyan
        docker compose --profile lab down
    }
    "seed" {
        Write-Host "[*] Seeding database history..." -ForegroundColor Cyan
        & $VENV_PYTHON scripts/wait_and_seed.py
    }
    default {
        Write-Host "==========================================================" -ForegroundColor Cyan
        Write-Host "  Wardwire Platform Runner (Windows PowerShell)" -ForegroundColor White
        Write-Host "==========================================================" -ForegroundColor Cyan
        Write-Host "  .\run.ps1 init        - Generate .env secrets"
        Write-Host "  .\run.ps1 docker-demo - Launch full stack in Docker & open UI"
        Write-Host "  .\run.ps1 docker-down - Stop Docker services"
        Write-Host "  .\run.ps1 test        - Run all 27 unit, security, integration tests"
        Write-Host "  .\run.ps1 eval        - Run leakage-free evaluation harness"
        Write-Host "  .\run.ps1 bench       - Run performance benchmarks"
        Write-Host "  .\run.ps1 scan        - Run SAST and vulnerability scans"
        Write-Host "  .\run.ps1 seed        - Seed sample incidents into database"
        Write-Host "==========================================================" -ForegroundColor Cyan
    }
}
