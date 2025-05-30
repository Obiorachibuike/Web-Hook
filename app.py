import os
from flask import Flask, request, jsonify, abort
from pymongo import MongoClient
from datetime import datetime
import hmac
import hashlib

app = Flask(__name__)

# --- Configuration (Load from .env for security and flexibility) ---
# It's crucial to use environment variables for sensitive info like MongoDB URI and webhook secret.
# Create a .env file in the same directory as app.py with these variables:
# MONGO_URI="mongodb://localhost:27017/" # Or your MongoDB Atlas URI
# GITHUB_WEBHOOK_SECRET="your_github_webhook_secret_here" # Matches the secret set in GitHub webhook config

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("python-dotenv not installed. Please install it (`pip install python-dotenv`) or set environment variables manually.")

MONGO_URI = os.getenv("MONGO_URI")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")

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

    # GitHub sends 'X-Hub-Signature-256' for SHA256, or 'X-Hub-Signature' for SHA1
    # Check for SHA256 first
    if signature.startswith('sha256='):
        hash_algorithm = 'sha256'
        signature_hash = signature[7:] # Remove 'sha256='
    elif signature.startswith('sha1='):
        hash_algorithm = 'sha1'
        signature_hash = signature[5:] # Remove 'sha1='
    else:
        return False # Unknown signature format

    mac = hmac.new(GITHUB_WEBHOOK_SECRET.encode('utf-8'), msg=data, digestmod=getattr(hashlib, hash_algorithm))
    return hmac.compare_digest(mac.hexdigest(), signature_hash)


# --- Webhook Endpoint ---
@app.route('/webhook', methods=['POST'])
def github_webhook():
    if request.method == 'POST':
        # 1. Verify GitHub Signature (Highly Recommended for Security)
        github_signature = request.headers.get('X-Hub-Signature-256') or request.headers.get('X-Hub-Signature')
        if github_signature is None:
            print("No GitHub signature found in headers.")
            # Depending on your setup, you might want to abort here if no secret is expected
            if GITHUB_WEBHOOK_SECRET:
                abort(403) # Forbidden if secret is configured but no signature is provided

        request_data = request.get_data()
        if not verify_github_signature(request_data, github_signature):
            print("Webhook signature verification failed.")
            abort(403) # Forbidden

        # 2. Get GitHub Event Type
        event_type = request.headers.get('X-GitHub-Event')
        payload = request.json # GitHub sends JSON payloads

        print(f"Received GitHub event: {event_type}")
        # print(f"Payload: {payload}") # Uncomment for debugging payload structure

        # 3. Process Payload based on Event Type
        processed_data = {}
        try:
            timestamp = datetime.utcnow().isoformat(timespec='seconds') + 'Z' # UTC format

            if event_type == 'push':
                processed_data = process_push_event(payload, timestamp)
            elif event_type == 'pull_request':
                # Pull Request events cover 'opened', 'reopened', 'closed', 'assigned', etc.
                # We are interested in 'opened' (for PR creation) and 'closed' (for merge).
                if payload['action'] == 'opened':
                    processed_data = process_pull_request_opened_event(payload, timestamp)
                elif payload['action'] == 'closed' and payload['pull_request']['merged']:
                    # This covers the MERGE action as a 'closed' PR that was 'merged'
                    processed_data = process_merge_event(payload, timestamp)
                else:
                    print(f"Ignoring pull_request event action: {payload['action']}")
                    return jsonify({'status': 'ignored', 'message': 'Pull Request action not relevant'}), 200
            # For other merge scenarios (e.g., direct pushes to master that result in a merge,
            # or different ways a 'merge' might be represented by GitHub's events),
            # you might need to add more `elif` conditions or refine the `process_merge_event` logic.
            # This is a common point for adjustment based on specific GitHub workflows.
            else:
                print(f"Ignoring GitHub event type: {event_type}")
                return jsonify({'status': 'ignored', 'message': 'Event type not relevant'}), 200

            if processed_data:
                # 4. Store Data in MongoDB
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
    # This is a simplified extraction. GitHub push payloads are extensive.
    # You'll need to carefully examine the payload structure for the exact fields.
    # Check payload['head_commit'] and payload['pusher']
    author = payload['pusher']['name'] if 'pusher' in payload and 'name' in payload['pusher'] else 'Unknown'
    to_branch = payload['ref'].split('/')[-1] if 'ref' in payload else 'Unknown' # e.g., "refs/heads/master" -> "master"
    request_id = payload['after'] # Commit hash after the push

    # Ensure author is not None or empty
    if not author:
        author = payload['sender']['login'] if 'sender' in payload and 'login' in payload['sender'] else 'Unknown'

    return {
        'request_id': request_id,
        'author': author,
        'action': 'PUSH',
        'from_branch': '', # PUSH doesn't explicitly have a 'from_branch' in the same way PRs do
        'to_branch': to_branch,
        'timestamp': timestamp
    }

def process_pull_request_opened_event(payload, timestamp):
    # Extract details for a new pull request
    pr = payload['pull_request']
    return {
        'request_id': str(pr['id']), # PR ID
        'author': pr['user']['login'],
        'action': 'PULL_REQUEST',
        'from_branch': pr['head']['ref'],
        'to_branch': pr['base']['ref'],
        'timestamp': timestamp
    }

def process_merge_event(payload, timestamp):
    # This specifically handles a Pull Request being merged.
    # GitHub often sends 'pull_request' event with action 'closed' and 'merged: true'.
    pr = payload['pull_request']
    return {
        'request_id': str(pr['merge_commit_sha']) if pr['merge_commit_sha'] else str(pr['id']), # Use merge commit SHA or PR ID
        'author': pr['merged_by']['login'] if pr['merged_by'] else pr['user']['login'], # Who merged it
        'action': 'MERGE',
        'from_branch': pr['head']['ref'],
        'to_branch': pr['base']['ref'],
        'timestamp': timestamp
    }


# --- UI Data Endpoint (for polling from the UI) ---
@app.route('/data', methods=['GET'])
def get_data():
    try:
        # Fetch the latest 10 (or more, adjust as needed) actions, sorted by timestamp descending
        latest_actions = list(actions_collection.find().sort('timestamp', -1).limit(10))

        # MongoDB's _id is an ObjectId, which is not directly JSON serializable. Convert it to string.
        for action in latest_actions:
            action['_id'] = str(action['_id'])
        
        return jsonify(latest_actions), 200
    except Exception as e:
        print(f"Error fetching data from MongoDB: {e}")
        return jsonify({'status': 'error', 'message': 'Could not retrieve data'}), 500


# --- Run the Flask app ---
if __name__ == '__main__':
    # For local development, set host to '0.0.0.0' to be accessible over network (e.g., by ngrok)
    # In production, use a production-ready WSGI server like Gunicorn.
    app.run(debug=True, host='0.0.0.0', port=5000)
