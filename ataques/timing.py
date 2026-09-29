# Análisis de canal lateral de tiempo: compara "==" frente a hmac.compare_digest.
"""
    python -m ataques.timing

Compara un MAC secreto con MACs falsos que aciertan los N primeros bytes.
- Con "==" la comparación para en el primer byte distinto: cuantos más bytes aciertas, más tarda.
  Midiendo esos tiempos un atacante puede adivinar el MAC byte a byte.
- Con hmac.compare_digest siempre recorre todo: tarda lo mismo acierte lo que acierte.

Para que la diferencia se vea por encima del ruido se usa un secreto largo (LONGITUD);
con un MAC real de 64 caracteres pasa lo mismo, pero hacen falta muchas más mediciones.
Guarda los datos en evidencias/timing.csv para hacer la gráfica en la memoria.
"""
import csv
import hmac
import secrets
import timeit
from pathlib import Path

LONGITUD = 100_000
REPETICIONES, VECES = 7, 2_000
SECRETO = secrets.token_hex(LONGITUD // 2).encode()
SALIDA = Path(__file__).resolve().parent.parent / "evidencias" / "timing.csv"


def medir(funcion, candidato):
    # El mínimo de varias tandas es la medida menos afectada por el ruido del sistema
    return min(timeit.repeat(lambda: funcion(SECRETO, candidato), number=VECES, repeat=REPETICIONES)) / VECES * 1e6


def main():
    filas = []
    print(f"{'% acertado':>11} | {'== (µs)':>9} | {'compare_digest (µs)':>20}")
    for porcentaje in (0, 10, 25, 50, 75, 90, 100):
        n = LONGITUD * porcentaje // 100
        # "x" no es hexadecimal: falla justo en el byte n. bytearray fuerza una copia: si fuera el mismo
        # objeto que SECRETO, Python ni compararía (atajo por identidad) y la medida del 100% saldría falsa
        candidato = bytes(bytearray(SECRETO[:n] + b"x" * (LONGITUD - n)))
        t_igual = medir(lambda a, b: a == b, candidato)
        t_cd = medir(hmac.compare_digest, candidato)
        filas.append((porcentaje, round(t_igual, 3), round(t_cd, 3)))
        print(f"{porcentaje:>10}% | {t_igual:>9.3f} | {t_cd:>20.3f}")

    SALIDA.parent.mkdir(parents=True, exist_ok=True)
    with SALIDA.open("w", newline="") as f:
        csv.writer(f).writerows([("porcentaje_acertado", "igual_us", "compare_digest_us"), *filas])
    print(f"\nDatos guardados en {SALIDA}")


if __name__ == "__main__":
    main()
