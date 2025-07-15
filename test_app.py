from flask import Flask, request, make_response, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    return 'Hello, World!'

@app.route('/xss', methods=['GET', 'POST'])
def xss():
    # Vulnerable to GET parameter XSS
    param = request.args.get('param', '')

    # Vulnerable to POST form XSS
    form_param = request.form.get('form_param', '')

    # Vulnerable to POST JSON XSS
    json_param = ''
    if request.is_json:
        json_param = request.json.get('json_param', '')

    # Vulnerable to Header XSS
    user_agent = request.headers.get('User-Agent', '')

    # Vulnerable to Cookie XSS
    cookie_param = request.cookies.get('cookie_param', '')

    # Vulnerable to Path XSS
    path = request.path

    # Vulnerable to Fragment XSS
    fragment = '' # Fragment is not directly accessible on the server side

    return render_template_string(
        f"""
        <h1>XSS Test Page</h1>
        <p>GET param: {param}</p>
        <p>POST form param: {form_param}</p>
        <p>POST JSON param: {json_param}</p>
        <p>User-Agent: {user_agent}</p>
        <p>Cookie param: {cookie_param}</p>
        <p>Path: {path}</p>
        <div id="fragment"></div>
        <script>
            document.getElementById('fragment').innerHTML = window.location.hash.substring(1);
        </script>
        <form method="POST">
            <input type="text" name="form_param" value="test">
            <input type="submit" value="Submit">
        </form>
        """
    )

if __name__ == '__main__':
    app.run(debug=True, port=5001)
