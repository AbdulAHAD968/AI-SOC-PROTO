from flask import Flask
from flask_restx import Api, Resource, fields
from pymongo import MongoClient
from dotenv import load_dotenv
from flask import request
import os
from flask_cors import CORS
from datetime import datetime
from models.rule_engine import RuleEngine
from models.log_parser import LogParser
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Load environment variables
load_dotenv()

# Initialize Flask app with CORS and disabled strict slashes
app = Flask(__name__)
app.url_map.strict_slashes = False
CORS(app)

# Initialize API
api = Api(app, version='1.0', title='SOC Shield API',
          description='A simple SOC alerting system')

# MongoDB setup
mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(mongo_uri)
db = client.soc_shield

# Initialize services
rule_engine = RuleEngine()

# Namespaces
logs_ns = api.namespace('api/logs', description='Log operations')
alerts_ns = api.namespace('api/alerts', description='Alert operations')

# Models
log_model = api.model('Log', {
    'timestamp': fields.DateTime(required=False, description='Log timestamp'),
    'source_ip': fields.String(required=False, description='Source IP address'),
    'destination_ip': fields.String(required=False, description='Destination IP address'),
    'event_type': fields.String(required=False, description='Type of event'),
    'raw_log': fields.String(required=True, description='Raw log content')
})

@logs_ns.route('')
class LogCollection(Resource):
    @logs_ns.doc('list_logs')
    def get(self):
        """List all raw logs (for testing)"""
        logs = list(db.logs_raw.find().limit(50))
        for log in logs:
            log['_id'] = str(log['_id'])
        return logs

    @logs_ns.expect(log_model)
    @logs_ns.response(201, 'Log successfully created.')
    @logs_ns.response(400, 'Invalid log format')
    def post(self):
        """Ingest a new log entry"""
        data = api.payload

        if 'raw_log' not in data:
            return {"message": "raw_log field is required"}, 400

        # Add timestamp if not provided
        if 'timestamp' not in data:
            data['timestamp'] = datetime.utcnow().isoformat()

        log_id = db.logs_raw.insert_one(data).inserted_id

        parsed_log = parse_log(data)
        parsed_id = db.logs_parsed.insert_one(parsed_log).inserted_id

        process_for_alerts(parsed_log)

        return {
            "message": "Log processed",
            "log_id": str(log_id),
            "parsed_id": str(parsed_id)
        }, 201

@alerts_ns.route('')
class AlertCollection(Resource):
    @alerts_ns.doc('list_alerts')
    @alerts_ns.response(200, 'Successfully retrieved alerts.')
    def get(self):
        """Retrieve all prioritized alerts"""
        try:
            alerts = list(db.alerts.find({"severity": {"$gt": 0}}).sort("severity", -1))
            
            # Convert MongoDB ObjectId to string for JSON serialization
            for alert in alerts:
                alert['_id'] = str(alert['_id'])
            
            return alerts, 200
        except Exception as e:
            return {"message": str(e)}, 500

def parse_log(raw_log):
    parsed = LogParser.parse(raw_log['raw_log'])
    parsed['raw_log_id'] = str(raw_log.get('_id', ''))  # Fallback if _id missing
    return parsed

def process_for_alerts(parsed_log):
    alerts = rule_engine.evaluate_log(parsed_log)
    if alerts:
        db.alerts.insert_many(alerts)

if __name__ == '__main__':
    app.run(debug=True)

