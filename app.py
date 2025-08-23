from flask import Flask, request, render_template_string
import pickle
import os

app = Flask(__name__)

@app.route('/')
def hello():
    template = '''
    <h1>Vulnerable Python App</h1>
    <p>This app uses older dependencies with known vulnerabilities</p>
    <p>Flask Version: {{ flask_version }}</p>
    <p>Build: {{ build_number }}</p>
    '''
    build_number = os.environ.get('BUILD_NUMBER', 'local')
    return render_template_string(template, 
                                flask_version=Flask.__version__,
                                build_number=build_number)

@app.route('/health')
def health():
    return {'status': 'healthy', 'version': '1.0'}

@app.route('/deserialize', methods=['POST'])
def deserialize():
    # Vulnerable deserialization endpoint
    data = request.get_data()
    try:
        result = pickle.loads(data)
        return f"Deserialized: {result}"
    except Exception as e:
        return f"Error in deserialization: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
