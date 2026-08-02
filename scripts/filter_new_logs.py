import sys
from datetime import datetime

CUTOFF = datetime.strptime("17/Jul/2026:23:22:00", "%d/%b/%Y:%H:%M:%S")

def filter_log(infile, outfile):
    kept = 0
    total = 0
    with open(infile, 'r', errors='ignore') as f_in, open(outfile, 'w') as f_out:
        for line in f_in:
            total += 1
            try:
                ts_str = line.split('[')[1].split(']')[0].split(' ')[0]
                ts = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
                if ts >= CUTOFF:
                    f_out.write(line)
                    kept += 1
            except (IndexError, ValueError):
                continue
    print(f"{infile}: zadrzano {kept}/{total} linija")

if __name__ == "__main__":
    filter_log(sys.argv[1], sys.argv[2])
