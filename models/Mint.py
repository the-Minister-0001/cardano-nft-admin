from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy import ForeignKey
from sqlalchemy.orm import declarative_base

from .base import Base

class Mint(Base):
    __tablename__ = 'mints'

    id = Column(Integer, primary_key=True)
    token_id = Column(Integer, ForeignKey('tokens.id'))
    amount = Column(Integer)
    addr = Column(String)
    in_progress = Column(Boolean)
    completed = Column(Boolean)
