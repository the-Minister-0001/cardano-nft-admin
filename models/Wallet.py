from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base

from .base import Base
class Wallet(Base):                                        
    __tablename__ = 'wallets'  
                                                           
    id = Column(Integer, primary_key=True)
    staking_vkey = Column(String)                                                                                     
    staking_skey = Column(String)                                                                                     
    payment_vkey = Column(String)
    payment_skey = Column(String)
    payment_addr = Column(String)                          
                                                           
    def __repr__(self):                                    
        return f"<Wallet(vkey={self.payment_vkey})>" 
