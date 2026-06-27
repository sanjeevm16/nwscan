# collectors/protocols/tls_probe.py
import ssl, socket, time

def pqc_tls_handshake(host, port=443):
    ctx = ssl.create_default_context()
    ctx.set_ciphersuites("TLS_AES_256_GCM_SHA384:TLS_KYBER_DILITHIUM_SHA256")

    start = time.perf_counter()
    with socket.create_connection((host, port)) as sock:
        with ctx.wrap_socket(sock, server_hostname=host):
            pass
    end = time.perf_counter()

    return {
        "host": host,
        "handshake_ms": (end - start) * 1000
    }
