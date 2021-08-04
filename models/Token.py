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

    # This is required to support both live minting and sending out pre-minted tokens
    # Pre-Mints are already minted but not distributed yet
    sent_out = Column(Integer)

    # In order to properly raffle set amounts of FTs there needs to be a start and ending index
    # If it's an uncapped FT this can also be used to determine rarities
    start_idx = Column(Integer)
    end_idx = Column(Integer)

    # To select a random token:
    #   start_idx = lowest start_idx of tokens in the project
    #   end_idx = highest end_idx of tokens in the project
    #   select random integer from start_idx to end_idx (both ends included) which has not been chosen in this session
    #   select the token in the project where start_idx <= randint <= end_idx
    #   if start_idx + minted <= randint: it's not yet distributed, choose this one
    #   else: it's already distributed, get the next one
