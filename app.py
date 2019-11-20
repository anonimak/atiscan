
from module import threatcrowd

p1 = threatcrowd.ThreatcrowdScan("detik.com")
p1.run()
# response = requests.get(
#     'http://apps.sucaco.com/service/category'
# )

# View the new `text-matches` array which provides information
# about your search term within the results
# json_response = response.json()
# category = json_response['data'][0]
# print(f'Text matches: {category}')

