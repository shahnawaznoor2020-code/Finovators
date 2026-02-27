# Architecture

## Layers

1. Flutter mobile app (worker)
2. Web frontend (landing + admin)
3. Node.js API (shared business logic)
4. PostgreSQL + Redis (data + cache)

## Core Flow

Earn -> Sync -> Withdraw -> Claim -> Manage
