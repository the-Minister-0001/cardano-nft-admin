from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy import ForeignKey
from sqlalchemy.orm import declarative_base

from .base import Base

class Token(Base):
    __tablename__ = 'tokens'

    id = Column(Integer, primary_key=True)
    asset_name = Column(String)
    minted = Column(Integer)
    max_mints = Column(Integer)
    token_metadata = Column(String)
    project_id = Column(Integer, ForeignKey('projects.id'))
