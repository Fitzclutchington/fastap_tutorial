from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# SQLALCHEMY_DATABASE_URL = "sqlite:///./todos.db"

# engine = create_engine(
#     SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
# )


SQLALCHEMY_DATABASE_URL = "postgresql://todo_app_3gyt_user:fQljlyDpZ3JrtHLdYCc7dHoF6vGLthAe@dpg-cpgaesol5elc738qn2dg-a.ohio-postgres.render.com/todo_app_3gyt"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
