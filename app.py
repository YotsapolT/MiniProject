from flask import Flask, request

app = Flask(__name__)

def allow_file(filename):
    print('.' in filename)
    print(filename.rsplit('.', 1)[1].lower() in {
        'pcap',
        'cap'
    })
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {
        'pcap',
        'cap'
    }

@app.route('/', methods=['GET', 'POST'])
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if request.method == 'GET':
        return {'text': "this is Dashboard!"}
    else:
        if 'file' not in request.files:
            return {'error': "No file provided"}, 400
        
        imported_file = request.files['file']
        print(imported_file)
        
        if imported_file == "":
            return {'error': "No file selected"}, 400
        if imported_file and allow_file(imported_file.filename):   
            return {'text': "imported file is ready!"}
        else:
            return {'error': "Invalid file format, allow file types are .pacp or .cap"}, 400
        

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=10000)