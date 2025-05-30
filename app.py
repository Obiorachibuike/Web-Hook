import os
from flask import Flask, request, jsonify, abort
from pymongo import MongoClient
from datetime import datetime
import hmac
import hashlib

app = Flask(__name__)

# --- Configuration (Load from .env for security and flexibility) ---
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("python-dotenv not installed. Please install it (`pip install python-dotenv`) or set environment variables manually.")

MONGO_URI = os.getenv("MONGO_URI")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
# It's good practice to get the port from environment variables too, for flexible deployment
PORT = int(os.getenv("PORT", 5000)) # Default to 5000 if not set

if not MONGO_URI:
    print("Error: MONGO_URI environment variable not set.")
    exit(1)

# MongoDB Connection
try:
    client = MongoClient(MONGO_URI)
    db = client['github_webhooks_db'] # Choose your database name
    actions_collection = db['actions'] # Choose your collection name
    print("Connected to MongoDB successfully!")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    exit(1)


# --- Helper Function for Webhook Signature Verification ---
def verify_github_signature(data, signature):
    if not GITHUB_WEBHOOK_SECRET:
        print("Warning: GITHUB_WEBHOOK_SECRET is not set. Webhook signature will not be verified.")
        return True # Proceed without verification if no secret is set (NOT recommended for production)

    if signature.startswith('sha256='):
        hash_algorithm = 'sha256'
        signature_hash = signature[7:]
    elif signature.startswith('sha1='):
        hash_algorithm = 'sha1'
        signature_hash = signature[5:]
    else:
        return False

    mac = hmac.new(GITHUB_WEBHOOK_SECRET.encode('utf-8'), msg=data, digestmod=getattr(hashlib, hash_algorithm))
    return hmac.compare_digest(mac.hexdigest(), signature_hash)


# --- Webhook Endpoint ---
@app.route('/webhook', methods=['POST'])
def github_webhook():
    if request.method == 'POST':
        github_signature = request.headers.get('X-Hub-Signature-256') or request.headers.get('X-Hub-Signature')
        if github_signature is None:
            print("No GitHub signature found in headers.")
            if GITHUB_WEBHOOK_SECRET:
                abort(403)

        request_data = request.get_data()
        if not verify_github_signature(request_data, github_signature):
            print("Webhook signature verification failed.")
            abort(403)

        event_type = request.headers.get('X-GitHub-Event')
        payload = request.json

        print(f"Received GitHub event: {event_type}")

        processed_data = {}
        try:
            timestamp = datetime.utcnow().isoformat(timespec='seconds') + 'Z'

            if event_type == 'push':
                processed_data = process_push_event(payload, timestamp)
            elif event_type == 'pull_request':
                if payload['action'] == 'opened':
                    processed_data = process_pull_request_opened_event(payload, timestamp)
                elif payload['action'] == 'closed' and payload['pull_request']['merged']:
                    processed_data = process_merge_event(payload, timestamp)
                else:
                    print(f"Ignoring pull_request event action: {payload['action']}")
                    return jsonify({'status': 'ignored', 'message': 'Pull Request action not relevant'}), 200
            else:
                print(f"Ignoring GitHub event type: {event_type}")
                return jsonify({'status': 'ignored', 'message': 'Event type not relevant'}), 200

            if processed_data:
                actions_collection.insert_one(processed_data)
                print(f"Data stored in MongoDB: {processed_data}")
                return jsonify({'status': 'success', 'message': 'Webhook received and processed'}), 200
            else:
                return jsonify({'status': 'ignored', 'message': 'Event processed but no data to store'}), 200

        except KeyError as e:
            print(f"KeyError processing webhook payload: {e}. Payload structure mismatch.")
            return jsonify({'status': 'error', 'message': f'Payload key missing: {e}'}), 400
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return jsonify({'status': 'error', 'message': f'Internal server error: {e}'}), 500

    return jsonify({'status': 'error', 'message': 'Method Not Allowed'}), 405


# --- Payload Processing Functions ---

def process_push_event(payload, timestamp):
    author = payload['pusher']['name'] if 'pusher' in payload and 'name' in payload['pusher'] else 'Unknown'
    to_branch = payload['ref'].split('/')[-1] if 'ref' in payload else 'Unknown'
    request_id = payload['after']

    if not author:
        author = payload['sender']['login'] if 'sender' in payload and 'login' in payload['sender'] else 'Unknown'

    return {
        'request_id': request_id,
        'author': author,
        'action': 'PUSH',
        'from_branch': '',
        'to_branch': to_branch,
        'timestamp': timestamp
    }

def process_pull_request_opened_event(payload, timestamp):
    pr = payload['pull_request']
    return {
        'request_id': str(pr['id']),
        'author': pr['user']['login'],
        'action': 'PULL_REQUEST',
        'from_branch': pr['head']['ref'],
        'to_branch': pr['base']['ref'],
        'timestamp': timestamp
    }

def process_merge_event(payload, timestamp):
    pr = payload['pull_request']
    return {
        'request_id': str(pr['merge_commit_sha']) if pr['merge_commit_sha'] else str(pr['id']),
        'author': pr['merged_by']['login'] if pr['merged_by'] else pr['user']['login'],
        'action': 'MERGE',
        'from_branch': pr['head']['ref'],
        'to_branch': pr['base']['ref'],
        'timestamp': timestamp
    }


# --- UI Data Endpoint (for polling from the UI) ---
@app.route('/data', methods=['GET'])
def get_data():
    try:
        latest_actions = list(actions_collection.find().sort('timestamp', -1).limit(10))

        for action in latest_actions:
            action['_id'] = str(action['_id'])
        
        return jsonify(latest_actions), 200
    except Exception as e:
        print(f"Error fetching data from MongoDB: {e}")
        return jsonify({'status': 'error', 'message': 'Could not retrieve data'}), 500

# Removed the if __name__ == '__main__': block
# Gunicorn will now directly import and run the 'app' object
