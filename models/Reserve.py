from sqlalchemy import Column, Integer
from sqlalchemy import ForeignKey
from sqlalchemy.orm import declarative_base

from .base import Base

class Reserve(Base):
    __tablename__ = 'reserves'

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('projects.id'))
    dust = Column(Integer) # In lovelaces
    mintage_id = Column(Integer, ForeignKey('mints.id'))
