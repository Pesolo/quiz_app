from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
import httpx
from datetime import datetime, timedelta
from typing import List, Dict, Any
from fastapi.responses import JSONResponse
import jwt
import os
from passlib.context import CryptContext
from schemas import UserResponse, UserCreate
from db_model import User, QuizResult
from user_db import SessionLocal
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Resource Conservation Quiz")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# JWT settings
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OpenTrivia Database API URL
OTDB_API_URL = "https://opentdb.com/api.php"

CONSERVATION_CATEGORIES = {
    'water': {
        'category_id': 17,
        'difficulty': 'medium',
        'keywords': ['water', 'ocean', 'river', 'conservation', 'environment'],
        'description': 'Test your knowledge about water conservation and marine ecosystems'
    },
    'energy': {
        'category_id': 17,
        'difficulty': 'medium',
        'keywords': ['energy', 'renewable', 'solar', 'wind', 'conservation'],
        'description': 'Learn about renewable energy and energy conservation'
    },
    'environment': {
        'category_id': 17,
        'difficulty': 'medium',
        'keywords': ['climate', 'pollution', 'ecosystem', 'conservation'],
        'description': 'Explore environmental conservation and climate change topics'
    }
}


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


def filter_and_process_questions(questions: List[Dict[Any, Any]]) -> List[Dict[Any, Any]]:
    """
    Filter and process questions to ensure they're relevant and properly formatted
    """
    processed_questions = []

    for question in questions:
        # Create a processed question object
        processed_question = {
            'question': question['question'],
            'correct_answer': question['correct_answer'],
            'options': question['incorrect_answers'] + [question['correct_answer']],
            'difficulty': question['difficulty']
        }

        # Shuffle the options
        import random
        random.shuffle(processed_question['options'])

        processed_questions.append(processed_question)

    return processed_questions


@app.get("/api/quiz-topics")
async def get_quiz_topics():
    """
    Return available quiz topics with descriptions
    """
    topics = {
        topic: {
            'description': info['description'],
            'difficulty': info['difficulty']
        }
        for topic, info in CONSERVATION_CATEGORIES.items()
    }
    return JSONResponse(content=topics)


@app.get("/api/generate-quiz")
async def generate_quiz(topic: str = 'water', token: str = Depends(oauth2_scheme)):
    """
    Generate a quiz based on selected topic
    """
    if topic not in CONSERVATION_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail="Invalid topic. Choose from 'water', 'energy', or 'environment'."
        )

    category_info = CONSERVATION_CATEGORIES[topic]

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                OTDB_API_URL,
                params={
                    'amount': 10,
                    'category': category_info['category_id'],
                    'difficulty': category_info['difficulty'],
                    'type': 'multiple'
                }
            )

            quiz_data = response.json()

            if quiz_data.get('response_code') != 0:
                raise HTTPException(
                    status_code=500,
                    detail="Unable to fetch questions from the quiz database"
                )

            processed_questions = filter_and_process_questions(quiz_data['results'])

            return {
                'topic': topic,
                'description': category_info['description'],
                'questions': processed_questions
            }

    except httpx.RequestError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch quiz questions: {str(e)}"
        )


@app.post("/register", response_model=UserResponse)
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    if user.password != user.password_confirm:
        raise HTTPException(
            status_code=400,
            detail="Passwords do not match"
        )

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


@app.post("/api/quiz/submit")
async def submit_quiz(
        answers: List[Dict[str, str]],
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    """
    Submit quiz answers and get results
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        user = db.query(User).filter(User.username == username).first()

        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )

        # Calculate score
        correct_answers = sum(1 for answer in answers if answer.get('is_correct', False))
        score = (correct_answers / len(answers)) * 100

        # Save quiz result
        quiz_result = QuizResult(
            user_id=user.id,
            score=score,
            completed_at=datetime.utcnow()
        )
        db.add(quiz_result)
        db.commit()

        return {
            'score': score,
            'total_questions': len(answers),
            'correct_answers': correct_answers
        }

    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


if __name__ == "__main__":
    import uvicorn
    from db_model import Base
    from user_db import engine

    Base.metadata.create_all(bind=engine)
    uvicorn.run(app, host="0.0.0.0", port=8000)