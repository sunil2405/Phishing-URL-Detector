# src/build_dataset.py
import csv
from pathlib import Path
from random import choice, randint
from urllib.parse import quote_plus

SAMPLES = 1000

benign_bases = [
    "https://www.google.com/search?q={}",
    "https://www.github.com/{}/repo",
    "https://www.amazon.com/dp/{}",
    "https://en.wikipedia.org/wiki/{}",
    "https://www.example.com/{}/info",
]

phish_patterns = [
    "http://{}-secure-login.com/{}",
    "http://login.{}.account.verify/{}/",
    "http://{}-paypal.com/{}",
    "http://secure-{}.com/login/{}",
    "http://{}-banking.com/{}"
]

def make_random_token(n=8):
    import random, string
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def generate():
    rows = []
    for i in range(SAMPLES):
        if i % 2 == 0:
            # benign
            base = choice(benign_bases)
            token = make_random_token(6)
            url = base.format(quote_plus(token))
            label = 0
        else:
            base = choice(phish_patterns)
            host = make_random_token(6)
            token = make_random_token(randint(4, 12))
            url = base.format(host, token)
            # randomly sometimes add IP-host style
            if randint(0, 10) > 8:
                url = url.replace(host, "192.168.{}.{}".format(randint(0,255), randint(0,255)))
            label = 1
        rows.append([url, label])
    return rows

def save_csv(out_path="data/synthetic_urls.csv"):
    Path("data").mkdir(parents=True, exist_ok=True)
    rows = generate()
    with open(out_path, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url","label"])
        writer.writerows(rows)
    print("Saved", out_path)

if __name__ == "__main__":
    save_csv()
