import requests
data = {
    'uid': '0887d14fbe253e8b6a7b8193f3891e04f88a9ed744b91f4990d567ffc8b18e5f',
}
res = requests.post('http://213.133.99.53:20000/public_key', json=data)

for _ in range(1):
    import time

    start = time.time()
    res = requests.post('http://213.133.99.53:20000/public_key', json=data)
    end = time.time()
    print(end - start)
    print(res.text)

for _ in range(1):
    import time

    start = time.time()
    # res = requests.post('http://135.181.203.7:3906/public_key', json=data)
    res = requests.get('http://5.75.143.249:3906/public_key', json=data)
    end = time.time()
    print(end - start)
    print(res.text)
