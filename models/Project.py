from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy import ForeignKey
from sqlalchemy.orm import declarative_base

from .base import Base

class Project(Base):
    __tablename__ = 'projects'

    id = Column(Integer, primary_key=True)
    policy_id = Column(Integer, ForeignKey('policies.id'))
    wallet_id = Column(Integer, ForeignKey('wallets.id'))
    project_name = Column(String)
    dynamic = Column(Boolean)
    lock_sales = Column(Boolean)
    price = Column(Integer) # In lovelace
