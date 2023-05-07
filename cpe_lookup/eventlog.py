from typing import Dict

from fastapi.encoders import jsonable_encoder
from httpx import HTTPStatusError, RequestError


def json_event_encoder(_, __, event_dict: Dict) -> Dict[str, str]:
    return jsonable_encoder(event_dict)


def error_event_handler(_, __, event_dict: Dict) -> Dict[str, str]:
    """If the event_dict has 'error' key, encode the value from exception to json."""
    if "error" in event_dict.keys():
        exc: Exception = event_dict.pop("error")
        err = dict()
        if isinstance(exc, RequestError):
            err = {
                "exception.details": {
                    "request.url": str(exc.request.url),
                    "request.headers": exc.request.headers,
                    "request.method": exc.request.method,
                    "request.content": exc.request.content,
                },
                "exception.type": f"{exc.__module__}.{exc.__class__.__name__}",
                "exception.message": str(exc),
            }
        elif isinstance(exc, HTTPStatusError):
            err = {
                "exception.details": {
                    "request.url": str(exc.request.url),
                    "request.headers": exc.request.headers,
                    "request.method": exc.request.method,
                    "request.content": exc.request.content,
                    "response.status_code": exc.response.status_code,
                    "response.headers": exc.response.headers,
                    "response.content": exc.response.content,
                },
                "exception.type": f"{exc.__module__}.{exc.__class__.__name__}",
                "exception.message": str(exc),
            }
        elif isinstance(exc, Exception):  # pragma: no cover
            err = {
                "exception.type": f"{exc.__module__}.{exc.__class__.__name__}",
                "exception.message": str(exc),
            }
        event_dict["exception"] = err
    return event_dict
