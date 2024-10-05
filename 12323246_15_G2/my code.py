import csv
import bcrypt
import getpass
import logging
import requests

logging.basicConfig(filename='log.txt', level=logging.INFO)

# Load user credentials from CSV file
users = {}
with open('users.csv', 'r') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        email, hashed_password, security_question = row
        users[email] = {'hashed_password': hashed_password, 'security_question': security_question}

def validate_email(email):
    # Email validation logic here
    return True

def validate_password(password):
    # Password validation logic here
    return True

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def login():
    email = input("Enter your email: ")
    password = getpass.getpass("Enter your password: ")
    if email in users:
        hashed_password = users[email]['hashed_password']
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
            return email
        else:
            logging.warning(f"Invalid password for {email}")
            return None
    else:
        logging.warning(f"User   {email} not found")
        return None

def forgot_password():
    email = input("Enter your email: ")
    if email in users:
        security_question = users[email]['security_question']
        answer = input(f"Enter your security question answer: ")
        if answer == security_question:
            new_password = input("Enter a new password: ")
            if validate_password(new_password):
                hashed_password = hash_password(new_password)
                users[email]['hashed_password'] = hashed_password
                with open('users.csv', 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    for email, user in users.items():
                        writer.writerow([email, user['hashed_password'], user['security_question']])
                logging.info(f"Password reset for {email}")
                return True
            else:
                logging.warning(f"Invalid password for {email}")
                return False
        else:
            logging.warning(f"Incorrect security question answer for {email}")
            return False
    else:
        logging.warning(f"User   {email} not found")
        return False

def search_game(game_name):
    api_key = "YOUR_CHEAPSHARK_API_KEY"
    url = f"https://www.cheapshark.com/api/1.0/games?title={game_name}&key={api_key}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        deals = []
        for game in data['games']:
            for deal in game['deals']:
                deals.append({
                    'game_title': game['title'],
                    'store_name': deal['store']['name'],
                    'normal_price': deal['normal_price'],
                    'sale_price': deal['sale_price'],
                    'savings': deal['savings'],
                    'deal_rating': deal['deal_rating'],
                    'store_url': deal['store']['url']
                })
        return deals
    else:
        return None

def search_game_deals(email):
    game_name = input("Enter a game name: ")
    deals = search_game(game_name)
    if deals:
        logging.info(f"Game deals found for {game_name}")
        for deal in deals:
            print(f"Game Title: {deal['game_title']}")
            print(f"Store Name: {deal['store_name']}")
            print(f"Normal Price: {deal['normal_price']}")
            print(f"Sale Price: {deal['sale_price']}")
            print(f"Savings: {deal['savings']}%")
            print(f"Deal Rating: {deal['deal_rating']}")
            print(f"Link to Store: {deal['store_url']}")
            print()
    else:
        logging.warning(f"No game deals found for {game_name}")

def main():
    login_attempts = 0
    while login_attempts < 5:
        print("1. Login")
        print("2. Forgot Password")
        choice = input("Enter your choice: ")
        if choice == "1":
            email = login()
            if email:
                logging.info(f"Login successful for {email}")
                search_game_deals(email)
                break
            else:
                login_attempts += 1
                logging.warning(f"Login failed. {5 - login_attempts} attempts remaining")
        elif choice == "2":
            if forgot_password():
                print("Password reset successfully")
            else:
                print("Password reset failed")
        else:
            print("Invalid choice")
    else:
        logging.warning("Login attempts exceeded. Terminating application")
        print("Login attempts exceeded. Terminating application")

if __name__ == "__main__":
    main()