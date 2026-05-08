with open("/home/svag/Dev/hyrule-cloud/hyrule_cloud/api/routes.py", "r") as f:
    text = f.read()

text = text.replace('["BTC", "XMR"]', '["BTC", "XMR", "ZEC"]')
text = text.replace('Use BTC or XMR', 'Use BTC, XMR, or ZEC')

with open("/home/svag/Dev/hyrule-cloud/hyrule_cloud/api/routes.py", "w") as f:
    f.write(text)
