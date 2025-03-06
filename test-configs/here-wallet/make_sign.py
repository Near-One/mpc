from random import random, sample

import requests
import time
import asyncio
import time
import httpx

data = [
    {
        'uid': '0887d14fbe253e8b6a7b8193f3891e04f88a9ed744b91f4990d567ffc8b18e5f',
        'message': '57f42da8350f6a7c6ad567d678355a3bbd17a681117e7a892db30656d5caee32',
        'proof': {
            "message_body": "S8safEk4JWgnJsVKxans4TqBL796cEuV5GcrqnFHPdNW91AupymrQ6zgwEXoeRb6P3nyaSskoFtMJzaskXTDAnQUTKs5dGMWQHsz7irQJJ2UA2aDHSQ4qxgsU3h1U83nkq4rBstK8PL1xm6WygSYihvBTmuaMjuKCK6JT1tB4Uw71kGV262kU914YDwJa53BiNLuVi3s2rj5tboEwsSEpyJo9x5diq4Ckmzf51ZjZEDYCH8TdrP1dcY4FqkTCBA7JhjfCTToJR5r74ApfnNJLnDhTxkvJb4ReR9T9Ga7hPNazCFGE8Xq1deu44kcPjXNvb1GJGWLAZ5k1wxq9nnARb3bvkqBTmeYiDcPDamauhrwYWZkMNUsHtoMwF6286gcmY3ZgE3jja1NGuYKYQHnvscUqcutuT9qH",
            "user_payloads": ['{"auth_method":0,"signatures":["HZUhhJamfp8GJLL8gEa2F2qZ6TXPu4PYzzWkDqsTQsMcW9rQsG2Hof4eD2Vex6he2fVVy3UNhgi631CY8E9StAH"]}'],
        },
        "key_type": 0
    },
    {
        'uid': '0887d14fbe253e8b6a7b8193f3891e04f88a9ed744b91f4990d567ffc8b18e5f',
        'message': '57f42da8350f6a7c6ad567d678355a3bbd17a681117e7a892db30656d5caee32',
        'proof': {
            "message_body": "S8safEk4JWgnJsVKxans4TqBL796cEuV5GcrqnFHPdNW91AupymrQ6zgwEXoeRb6P3nyaSskoFtMJzaskXTDAnQUTKs5dGMWQHsz7irQJJ2UA2aDHSQ4qxgsU3h1U83nkq4rBstK8PL1xm6WygSYihvBTmuaMjuKCK6JT1tB4Uw71kGV262kU914YDwJa53BiNLuVi3s2rj5tboEwsSEpyJo9x5diq4Ckmzf51ZjZEDYCH8TdrP1dcY4FqkTCBA7JhjfCTToJR5r74ApfnNJLnDhTxkvJb4ReR9T9Ga7hPNazCFGE8Xq1deu44kcPjXNvb1GJGWLAZ5k1wxq9nnARb3bvkqBTmeYiDcPDamauhrwYWZkMNUsHtoMwF6286gcmY3ZgE3jja1NGuYKYQHnvscUqcutuT9qH",
            "user_payloads": ['{"auth_method":0,"signatures":["HZUhhJamfp8GJLL8gEa2F2qZ6TXPu4PYzzWkDqsTQsMcW9rQsG2Hof4eD2Vex6he2fVVy3UNhgi631CY8E9StAH"]}'],
        },
        "key_type": 1
    },
    # { # Base
    #     'uid': '6c2015fd2a1a858144749d55d0f38f0632b8342f59a2d44ee374d64047b0f4f4',
    #     'message': 'ef32edffb454d2a3172fd0af3fdb0e43fac5060a929f1b83b6de2b73754e3f45',
    #     'proof': {
    #         "auth_id": 0,
    #         "user_payload": '00000000000000000000000000000000000000000000005e095d2c286c4414050000000000000000000000000000000000000000000000000000000000000000',
    #         "account_id": "0x42351e68420D16613BBE5A7d8cB337A9969980b4"
    #     }
    # },
]

ips = [
    # 'http://5.75.143.249:40000',
    # 'http://37.27.114.137:40000',


    # 'http://213.133.99.53:20000',
    # 'http://135.181.220.41:20000',
    # 'http://65.21.68.199:20000',
    # 'http://35.228.224.49:20000',

    'http://139.162.173.142:40000'
]


success = 0
total = 0

async def make_request(client, payload, semaphore):
    global total, success
    [ip] = sample(ips, 1)
    url = f'{ip}/sign'
    total += 1

    async with semaphore:
        try:
            start = time.time()
            res = await client.post(url, json=payload)
            end = time.time()
            print(end - start)
            print(res.text)
            success += 1
        except Exception as e:
            print(e)
            print("Error")
    percentage = success / total
    print(f"{percentage:.2f}%, success: {success}, total: {total}")

async def main():
    semaphore = asyncio.Semaphore(1)
    payload = data[1]

    async with httpx.AsyncClient() as client:
        while True:
            tasks = [
                make_request(client, payload, semaphore)
                for _ in range(20)
            ]
            await asyncio.gather(*tasks)
            await asyncio.sleep(1)  # Pause to maintain RPS

# Run the async function
asyncio.run(main())