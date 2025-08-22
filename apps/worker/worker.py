"""
Worker stub: consume queue and launch pipeline.
Replace with Redis/Rabbit/SQS adapter + logging.
"""
import time
def main():
    print("[worker] starting (stub)…")
    while True:
        time.sleep(5)
if __name__ == "__main__":
    main()
