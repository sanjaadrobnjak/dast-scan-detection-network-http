import re
import sys
import glob
import pandas as pd
import numpy as np
from datetime import datetime
from collections import defaultdict

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) - \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d+) (?P<size>\S+) '
    r'"(?P<agent>[^"]*)" (?P<reqtime>\S+)'
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S"
WINDOW_SECONDS = 1

def parse_log_line(line):
    m = LOG_PATTERN.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    try:
        ts_str = d['time'].split(' ')[0]
        ts = datetime.strptime(ts_str, TIME_FORMAT)
    except ValueError:
        return None

    request_parts = d['request'].split(' ')
    url = request_parts[1] if len(request_parts) >= 2 else d['request']

    try:
        size = int(d['size']) if d['size'] != '-' else 0
    except ValueError:
        size = 0

    try:
        reqtime = float(d['reqtime']) if d['reqtime'] != '-' else 0.0
    except ValueError:
        reqtime = 0.0

    return {
        'ip': d['ip'],
        'timestamp': ts,
        'url': url,
        'status': int(d['status']),
        'size': size,
        'agent': d['agent'],
        'reqtime': reqtime
    }

def extract_features(log_file, label):
    records = []
    with open(log_file, 'r', errors='ignore') as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                records.append(parsed)

    if not records:
        print(f"  UPOZORENJE: nijedna linija parsirana iz {log_file}")
        return []

    records.sort(key=lambda r: r['timestamp'])

    sessions = defaultdict(list)
    base_time = records[0]['timestamp']
    for r in records:
        window_idx = int((r['timestamp'] - base_time).total_seconds() // WINDOW_SECONDS)
        key = (r['ip'], window_idx)
        sessions[key].append(r)

    rows = []
    for (ip, window_idx), reqs in sessions.items():
        total = len(reqs)
        statuses = [r['status'] for r in reqs]
        sizes = [r['size'] for r in reqs]
        urls = [r['url'] for r in reqs]
        agents = [r['agent'] for r in reqs]
        reqtimes = [r['reqtime'] for r in reqs]

        unique_urls = len(set(urls))
        unique_agents = len(set(agents))

        window_start = base_time.timestamp() + window_idx * WINDOW_SECONDS
        window_end = window_start + WINDOW_SECONDS

        row = {
            'src_ip': ip,
            'window_start_epoch': window_start,
            'window_end_epoch': window_end,
            'total_requests': total,
            'ratio_404': statuses.count(404) / total,
            'ratio_200': statuses.count(200) / total,
            'ratio_302': statuses.count(302) / total,
            'ratio_500': statuses.count(500) / total,
            'unique_url_ratio': unique_urls / total,
            'unique_agent_ratio': 1 - (unique_agents - 1) / total,
            'size_mean': np.mean(sizes),
            'size_std': np.std(sizes),
            'reqtime_mean': np.mean(reqtimes),
            'reqtime_std': np.std(reqtimes),
            'label': label
        }
        rows.append(row)

    return rows

def main():
    if len(sys.argv) < 4:
        print("Upotreba: python3 extract_http_features.py <log_file> <label> <output_csv>")
        sys.exit(1)

    log_file, label, output_csv = sys.argv[1], sys.argv[2], sys.argv[3]

    print(f"Obradujem {log_file} (label={label}, prozor={WINDOW_SECONDS}s)...")
    rows = extract_features(log_file, label)
    df = pd.DataFrame(rows)
    df.to_csv(output_csv, index=False)
    print(f"Sacuvano {len(rows)} sesija u {output_csv}")

if __name__ == "__main__":
    main()
