from sqlalchemy import Column, Integer
from sqlalchemy.orm import declarative_base

from .base import Base

class SaleSize(Base):
    __tablename__ = 'salesizes'
    id = Column(Integer, primary_key=True)
    amount = Column(Integer)
