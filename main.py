from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
import httpx
from datetime import datetime, timedelta
from typing import List
import jwt
import os
from passlib.context import CryptContext
from schemas import UserResponse, UserCreate
from db_model import User, QuizResult
from user_db import SessionLocal
from dotenv import load_dotenv

load_dotenv()
import random

app = FastAPI(title="Resource Conservation Quiz")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# JWT settings
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# Dependencies
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


CONSERVATION_CATEGORIES = {
    'water': {
        'category_id': 17,  # Science & Nature
        'difficulty': 'medium',
        'keywords': ['water', 'ocean', 'river', 'conservation', 'environment']
    },
    'energy': {
        'category_id': 17,  # Science & Nature
        'difficulty': 'medium',
        'keywords': ['energy', 'renewable', 'solar', 'wind', 'conservation']
    },
    'environment': {
        'category_id': 17,  # Science & Nature
        'difficulty': 'medium',
        'keywords': ['climate', 'pollution', 'ecosystem', 'conservation']
    }
}

async def get_quiz_questions(category_key: str):
    """
    Fetch quiz questions from the API based on the specified category key.
    """
    if category_key not in CONSERVATION_CATEGORIES:
        raise ValueError(f"Invalid category: {category_key}")

    category = CONSERVATION_CATEGORIES[category_key]

    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://opentdb.com/api.php",
            params={
                "amount": 10,
                "category": category['category_id'],
                "difficulty": category['difficulty'],
                "type": "multiple"
            }
        )
        return response.json().get("results", [])

@app.post("/register", response_model=UserResponse)
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    if user.password != user.password_confirm:
        raise HTTPException(
            status_code=400,
            detail="Passwords do not match"
        )

    # Check if username or email exists
    existing_user = db.query(User).filter(
        (User.username == user.username) | (User.email == user.email)
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username or email already registered"
        )

    db_user = User(
        name=user.name,
        email=user.email,
        username=user.username,
        hashed_password=get_password_hash(user.password)
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token")
async def login(
        form_data: OAuth2PasswordRequestForm = Depends(),
        db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/quiz")
async def get_quiz(category: str, token: str = Depends(oauth2_scheme)):
    if category not in CONSERVATION_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail="Invalid category. Choose from 'water', 'energy', or 'environment'."
        )

    try:
        questions = await get_quiz_questions(category)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {"category": category, "questions": questions}

@app.post("/quiz/submit")
async def submit_quiz(
        answers: List[str],
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    # Verify token and get user
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username = payload.get("sub")
    user = db.query(User).filter(User.username == username).first()

    # Calculate score (simplified scoring logic)
    score = len([a for a in answers if a == "correct"]) / len(answers) * 100

    # Save quiz result
    quiz_result = QuizResult(
        user_id=user.id,
        score=score,
        completed_at=datetime.utcnow().isoformat()
    )
    db.add(quiz_result)
    db.commit()

    return {"score": score}

if __name__ == "__main__":
    import uvicorn

    Base.metadata.create_all(bind=engine)
    uvicorn.run(app, host="0.0.0.0", port=8000)