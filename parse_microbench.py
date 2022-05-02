import datetime
import sys

def main():
    base = sys.argv[1]
    for x in range(1, 11):
        with open(f"{base}.{x}") as f:
            laststep = None
            lastdt = None
            for line in f:
                if not line.startswith("2022/05/02"):
                    continue
                date, time, step = line.split(' ', 2)
                step = step.strip()
                dt = datetime.datetime.strptime(f'{date} {time}', '%Y/%m/%d %H:%M:%S.%f')
                if laststep and lastdt:
                    td = dt - lastdt
                    seconds = td.total_seconds()
                    ms = seconds * 1000
                    print(f"{laststep}->{step},{ms}")
                laststep = step
                lastdt = dt


if __name__ == '__main__':
    main()
