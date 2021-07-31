from sqlalchemy import Column, Integer
from sqlalchemy import ForeignKey
from sqlalchemy.orm import declarative_base

from .base import Base

class RelSaleSizeProject(Base):
    __tablename__ = 'rel_salesizes_projects'
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('projects.id'))
    salesize_id = Column(Integer, ForeignKey('salesizes.id'))

