from __future__ import annotations

import asyncio
from typing import Protocol

from fastapi import FastAPI, HTTPException

from workers.common.protocol.schemas import (
    FrameworkExecutionRequest,
    FrameworkExecutionResult,
    WorkerCapability,
    WorkerHealth,
)


class FrameworkRunner(Protocol):
    framework_name: str

    async def health(self) -> WorkerHealth:
        ...

    async def version(self) -> dict:
        ...

    async def capabilities(self) -> list[WorkerCapability]:
        ...

    async def validate_campaign(self, request: FrameworkExecutionRequest) -> dict:
        ...

    async def execute(self, request: FrameworkExecutionRequest) -> FrameworkExecutionResult:
        ...

    async def cancel(self, execution_id: str) -> dict:
        ...

    async def status(self, execution_id: str) -> dict:
        ...

    async def result(self, execution_id: str) -> FrameworkExecutionResult:
        ...


def create_worker_app(runner: FrameworkRunner) -> FastAPI:
    app = FastAPI(title=f"{runner.framework_name} Worker", version="0.1.0")
    results: dict[str, FrameworkExecutionResult] = {}
    tasks: dict[str, asyncio.Task] = {}

    @app.get("/health")
    async def health() -> WorkerHealth:
        return await runner.health()

    @app.get("/version")
    async def version() -> dict:
        return await runner.version()

    @app.get("/capabilities")
    async def capabilities() -> dict:
        return {"capabilities": [item.model_dump(mode="json") for item in await runner.capabilities()]}

    @app.post("/validate-campaign")
    async def validate_campaign(request: FrameworkExecutionRequest) -> dict:
        return await runner.validate_campaign(request)

    @app.post("/execute")
    async def execute(request: FrameworkExecutionRequest) -> FrameworkExecutionResult:
        result = await runner.execute(request)
        results[request.execution_id] = result
        return result

    @app.post("/execute-async")
    async def execute_async(request: FrameworkExecutionRequest) -> dict:
        async def run() -> None:
            results[request.execution_id] = await runner.execute(request)

        task = asyncio.create_task(run())
        tasks[request.execution_id] = task
        return {"execution_id": request.execution_id, "status": "queued"}

    @app.post("/cancel/{execution_id}")
    async def cancel(execution_id: str) -> dict:
        task = tasks.get(execution_id)
        if task:
            task.cancel()
        return await runner.cancel(execution_id)

    @app.get("/status/{execution_id}")
    async def status(execution_id: str) -> dict:
        if execution_id in results:
            return {"execution_id": execution_id, "status": results[execution_id].status}
        return await runner.status(execution_id)

    @app.get("/result/{execution_id}")
    async def result(execution_id: str) -> FrameworkExecutionResult:
        if execution_id not in results:
            raise HTTPException(status_code=404, detail="Result not available")
        return results[execution_id]

    return app

