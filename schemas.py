from pydantic import BaseModel, EmailStr, constr
from typing import Optional

class UserBase(BaseModel):
    name: str
    email: EmailStr
    username: constr(min_length=3, max_length=20)

class UserCreate(UserBase):
    password: constr(min_length=8)
    password_confirm: str

class UserResponse(UserBase):
    id: int

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str