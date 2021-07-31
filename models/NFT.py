from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy import ForeignKey
from sqlalchemy.orm import declarative_base

from .base import Base

class NFT(Base):
    __tablename__ = 'nfts'

    id = Column(Integer, primary_key=True)
    asset_name = Column(String)
    minted = Column(Boolean)
    nft_metadata = Column(String)
    project_id = Column(Integer, ForeignKey('projects.id'))
