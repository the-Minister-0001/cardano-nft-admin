from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base

from .base import Base

class Policy(Base):
    __tablename__ = 'policies'
    
    id = Column(Integer, primary_key=True)
    policy_id = Column(String)
    policy_script = Column(String)
    policy_vkey = Column(String)
    policy_skey = Column(String)
    before = Column(Integer)
    after = Column(Integer)

    def __repr__(Base):
        return f"<Policy(id={self.id})>"
