from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from database import Base

class UserInDb(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String, index=True)
    disabled = Column(Boolean)

class Email(Base):
    __tablename__ = "emails"
    
    id = Column(Integer, primary_key=True)
    sender = Column(String, index=True)
    recipient = Column(String, index=True)
    subject = Column(String, index=True)
    message = Column(String, index=True)
    starred_by_recepient = Column(Boolean)
    starred_by_sender = Column(Boolean)
    read = Column(Boolean)
