import os
import uuid
import logging
from flask import Flask, request, jsonify
from pymongo import MongoClient
from datetime import datetime
import hmac
import hashlib

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,  # Change to DEBUG for verbose output
    format="%(asctime)s [%(levelname)s] %(message)s",
)

app = Flask(__name__)

# --- Load Environment Variables ---
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    logging.warning("python-dotenv not installed. Install it or set env variables manually.")

MONGO_URI = os.getenv("MONGO_URI")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
PORT = int(os.getenv("PORT", 5000))

if not MONGO_URI:
    logging.error("MONGO_URI environment variable not set.")
    exit(1)

# --- MongoDB Connection ---
try:
    client = MongoClient(MONGO_URI)
    db = client['github_webhooks_db']
    actions_collection = db['actions']
    logging.info("Connected to MongoDB successfully.")
except Exception as e:
    logging.error(f"Error connecting to MongoDB: {e}")
    exit(1)

# --- Verify GitHub Signature ---
def verify_github_signature(data, signature):
    if not GITHUB_WEBHOOK_SECRET:
        logging.warning("GITHUB_WEBHOOK_SECRET is not set. Webhook signature will not be verified.")
        return True

    if signature.startswith('sha256='):
        hash_algorithm = 'sha256'
        signature_hash = signature[7:]
    elif signature.startswith('sha1='):
        hash_algorithm = 'sha1'
        signature_hash = signature[5:]
    else:
        return False

    mac = hmac.new(GITHUB_WEBHOOK_SECRET.encode(), msg=data, digestmod=getattr(hashlib, hash_algorithm))
    return hmac.compare_digest(mac.hexdigest(), signature_hash)

# --- Webhook Endpoint ---
@app.route('/webhook', methods=['POST'])
def github_webhook():
    request_id = str(uuid.uuid4())
    logging.info(f"[{request_id}] --- New Webhook Request ---")

    github_signature = request.headers.get('X-Hub-Signature-256') or request.headers.get('X-Hub-Signature')
    if not github_signature and GITHUB_WEBHOOK_SECRET:
        logging.warning(f"[{request_id}] GitHub signature missing.")
        return jsonify({'status': 'error', 'message': 'GitHub signature missing in headers.'}), 403

    request_data = request.get_data()
    if not verify_github_signature(request_data, github_signature):
        logging.warning(f"[{request_id}] Webhook signature verification failed.")
        return jsonify({'status': 'error', 'message': 'Webhook signature verification failed.'}), 403

    event_type = request.headers.get('X-GitHub-Event')
    payload = request.json

    logging.info(f"[{request_id}] Received GitHub event: {event_type}")

    try:
        timestamp = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        processed_data = {}

        if event_type == 'push':
            processed_data = process_push_event(payload, timestamp)
        elif event_type == 'pull_request':
            if payload['action'] == 'opened':
                processed_data = process_pull_request_opened_event(payload, timestamp)
            elif payload['action'] == 'closed' and payload['pull_request']['merged']:
                processed_data = process_merge_event(payload, timestamp)
            else:
                logging.info(f"[{request_id}] Ignored pull_request action: {payload['action']}")
                return jsonify({'status': 'ignored', 'message': f'Pull Request action not relevant: {payload["action"]}'}), 200
        else:
            logging.info(f"[{request_id}] Ignored GitHub event type: {event_type}")
            return jsonify({'status': 'ignored', 'message': f'Event type not relevant: {event_type}'}), 200

        if processed_data:
            actions_collection.insert_one(processed_data)
            logging.info(f"[{request_id}] Data stored in MongoDB: {processed_data}")
            return jsonify({'status': 'success', 'message': 'Webhook received and processed', 'data': processed_data}), 200
        else:
            logging.info(f"[{request_id}] Event processed but no data to store.")
            return jsonify({'status': 'ignored', 'message': 'No data extracted from event'}), 200

    except KeyError as e:
        logging.error(f"[{request_id}] KeyError: {e}")
        return jsonify({'status': 'error', 'message': f'Payload key missing: {e}'}), 400
    except Exception as e:
        logging.exception(f"[{request_id}] Unexpected error during webhook processing")
        return jsonify({'status': 'error', 'message': f'Internal server error: {e}'}), 500

# --- Payload Processing ---
def process_push_event(payload, timestamp):
    author = payload.get('pusher', {}).get('name', payload.get('sender', {}).get('login', 'Unknown'))
    to_branch = payload.get('ref', '').split('/')[-1]
    request_id = payload.get('after', 'N/A')
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
        'request_id': pr['merge_commit_sha'] or str(pr['id']),
        'author': pr['merged_by']['login'] if pr.get('merged_by') else pr['user']['login'],
        'action': 'MERGE',
        'from_branch': pr['head']['ref'],
        'to_branch': pr['base']['ref'],
        'timestamp': timestamp
    }

# --- Data Fetching Endpoint ---
@app.route('/data', methods=['GET'])
def get_data():
    request_id = str(uuid.uuid4())
    logging.info(f"[{request_id}] --- New /data Request ---")

    try:
        latest_actions = list(actions_collection.find().sort('timestamp', -1).limit(10))
        for action in latest_actions:
            action['_id'] = str(action['_id'])

        if not latest_actions:
            logging.info(f"[{request_id}] No actions found. Sending empty response.")
            return jsonify({
                'status': 'empty',
                'message': 'No data found in the database.',
                'data': []
            }), 200

        logging.info(f"[{request_id}] Retrieved {len(latest_actions)} actions.")
        logging.debug(f"[{request_id}] Response Data: {latest_actions}")

        return jsonify({
            'status': 'success',
            'data': latest_actions
        }), 200

    except Exception as e:
        logging.error(f"[{request_id}] Failed to fetch data: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Could not retrieve data: {e}',
            'data': []
        }), 500

# --- Main Entry ---
if __name__ == '__main__':
    logging.info(f"Starting Flask app on port {PORT}...")
    app.run(host='0.0.0.0', port=PORT)