#!/usr/bin/env python3
import random

def create_random_id():
    return hex(random.getrandbits(16 ** 2))[2:]
