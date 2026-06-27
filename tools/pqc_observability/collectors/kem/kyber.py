# collectors/kem/kyber.py
from quantcrypt.kem import MLKEM_512 as Kyber512
from tools.utils.timer import timed

@timed
def run_kyber():
    kem = Kyber512()
    pk, sk = kem.generate_keypair()
    ct, ss1 = kem.encapsulate(pk)
    ss2 = kem.decapsulate(ct, sk)
    assert ss1 == ss2

    return {
        "pk_len": len(pk),
        "sk_len": len(sk),
        "ct_len": len(ct)
    }
