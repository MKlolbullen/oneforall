from fastapi import APIRouter

from app.services.platform_config import (
    clear_platform_config_cache,
    list_wordlists,
    load_grep_patterns,
    load_platform_config,
    plugin_matrix,
)

router = APIRouter(prefix='/config', tags=['configuration'])


@router.get('/effective')
def effective_config():
    return load_platform_config()


@router.get('/grep-patterns')
def grep_patterns():
    return load_grep_patterns()


@router.get('/wordlists')
def wordlists():
    return list_wordlists()


@router.get('/plugin-matrix')
def plugins():
    return plugin_matrix()


@router.post('/reload')
def reload_config():
    clear_platform_config_cache()
    return {'status': 'reloaded'}
