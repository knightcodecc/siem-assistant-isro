from flask import Flask, request, jsonify
from flask_cors import CORS
import os

app = Flask(__name__)

# Enable CORS
CORS(app, resources={
    r"/*": {
        "origins": "*"  # Allow all origins for now
    }
})

@app.route('/')
def home():
    return jsonify({
        "message": "SIEM Assistant Backend",
        "status": "active",
        "version": "1.0"
    })

@app.route('/api/chat', methods=['POST', 'OPTIONS'])
def chat():
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.json
        message = data.get('message', '')
        
        # Your chatbot logic here
        response = {
            "response": f"Received: {message}",
            "status": "success"
        }
        
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# This is crucial for Vercel
if __name__ == '__main__':
    app.run()
