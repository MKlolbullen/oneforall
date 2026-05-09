from fastapi import APIRouter, HTTPException, Query

from app.services.tool_availability import (
    check_tool_availability,
    list_tool_availability,
    profile_availability,
)
from app.services.tool_registry import get_registry

router = APIRouter(prefix="/tools", tags=["tools"])


@router.get("")
def list_tools():
    return [tool.model_dump() for tool in get_registry().list_tools()]


@router.get("/availability")
def tool_availability(force: bool = Query(default=False)):
    return [item.model_dump() for item in list_tool_availability(get_registry(), force=force)]


@router.get("/profiles")
def list_profiles():
    return get_registry().list_profiles()


@router.get("/profiles/{profile_id}/availability")
def get_profile_availability(profile_id: str, force: bool = Query(default=False)):
    try:
        return profile_availability(get_registry(), profile_id, force=force).model_dump()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{tool_id}")
def get_tool(tool_id: str):
    try:
        return get_registry().get_tool(tool_id).model_dump()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{tool_id}/availability")
def get_tool_availability(tool_id: str, force: bool = Query(default=False)):
    try:
        tool = get_registry().get_tool(tool_id)
        return check_tool_availability(tool, force=force).model_dump()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
