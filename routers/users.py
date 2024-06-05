import sys

sys.path.append("..")

from fastapi import Depends, Form, HTTPException, Request, Response, status, APIRouter
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .auth import get_current_user, get_password_hash, verify_password
from .todos import db_dependency
import models

router = APIRouter(
    prefix="/users", tags=["users"], responses={401: {"user": "Not authorized"}}
)

templates = Jinja2Templates(directory="templates/")


@router.get("/password", response_class=HTMLResponse)
async def password_change_page(request: Request):
    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse(
        "change_password.html", {"request": request, "user": user}
    )


@router.post("/password", response_class=HTMLResponse)
async def password_change(
    request: Request,
    db: db_dependency,
    password: str = Form(...),
    new_password: str = Form(...),
    new_password2: str = Form(...),
):
    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)

    user_model = (
        db.query(models.Users).filter(models.Users.id == user.get("id")).first()
    )

    if new_password != new_password2 or not verify_password(
        password, user_model.hashed_password
    ):
        msg = "Error changing password"
        return templates.TemplateResponse(
            "change_password.html", {"request": request, "msg": msg, "user": user}
        )

    user_model.hashed_password = get_password_hash(new_password)

    db.add(user_model)
    db.commit()
    msg = "Successfully changed password"
    return templates.TemplateResponse(
        "change_password.html", {"request": request, "msg": msg, "user": user}
    )
