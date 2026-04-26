# WRAITH ghost.py — sig.int.ghost brand voice
# random sayings on exit and key events
# passive observer. anomaly is the signal.

import random

GHOST_SAYINGS = [
    'anomaly is the signal.',
    'passive observer. never the noise.',
    'the wire remembers everything. even silence.',
    'systems reveal themselves under observation.',
    'every packet has a story. WRAITH just listens.',
    'the device does not know it has been seen.',
    'patterns in noise. signal in chaos.',
    'ghost in the machine. reading the wire.',
    'open is a confession. filtered is a whisper.',
    'instance is identity. network is territory.',
    'if you found this, you are already in the wire.',
    'the network speaks. WRAITH translates.',
    'silence on 47808 is not absence. it is waiting.',
    'BACnet does not lie. controllers do not hide.',
    'every broadcast is a heartbeat. WRAITH counts them.',
    'the BBMD knows the topology. so does WRAITH.',
    'registers hold truth. WRAITH reads it directly.',
    '%X0.0 — first rung. first contact.',
    '%MW100 — memory word. state unknown.',
    'anomaly detected. logging. watching. waiting.',
]

def ghost_exit():
    saying = random.choice(GHOST_SAYINGS)
    print(f'\n  \033[2m{saying}\033[0m')
    print(f'  \033[36m\033[2mghost offline.\033[0m\n')

def ghost_banner():
    saying = random.choice(GHOST_SAYINGS)
    print(f'  \033[2m{saying}\033[0m')
