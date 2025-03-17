from flask import Flask
from routes import routes
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Set the secret key from environment variable or use a default
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

# Register the routes blueprint
app.register_blueprint(routes)

# Run the app
if __name__ == '__main__':
    app.run(debug=True)

            