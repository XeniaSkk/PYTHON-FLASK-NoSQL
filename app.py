from flask import Flask, render_template, request, url_for, redirect, session
import pymongo
import bcrypt


app = Flask(__name__)
app.secret_key = "polly"
client = pymongo.MongoClient("mongodb://127.0.0.1:27017/")
db = client.get_database('users_records')
records = db.users

@app.route("/", methods=["POST", "GET"])
def index():
    message = ''
    if "username" in session:
        return redirect(url_for("logged_in"))
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        
        user_found = records.find_one({"username": username})
        email_found = records.find_one({"email": email})
        if user_found:
            message = 'This username already exists'
            return render_template('index.html', message=message)
        if email_found:
            message = 'This email already exists'
            return render_template('index.html', message=message)
        if password1 != password2:
            message = 'Passwords should match!'
            return render_template('index.html', message=message)
        else:
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            user_input = {'username': username, 'email': email, 'password': hashed}
            records.insert_one(user_input)
            
            user_data = records.find_one({"username": username})
            new_username = user_data['username']
            session["username"] = new_username
            return redirect(url_for('logged_in'))
    return render_template('index.html')


@app.route('/logged_in')
def logged_in():
    if "username" in session:
        username = session["username"]
        return render_template('logged_in.html', username=username)
    else:
        return redirect(url_for("login"))


@app.route("/login", methods=["POST", "GET"])
def login():
    message = 'Please login to your account'
    if "username" in session:
        return redirect(url_for("logged_in"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

       
        user_found = records.find_one({"username": username})
        if user_found:
            user_val = user_found['username']
            passwordcheck = user_found['password']
            
            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["username"] = user_val
                return redirect(url_for('logged_in'))
            else:
                if "username" in session:
                    return redirect(url_for("logged_in"))
                message = 'Wrong password'
                return render_template('login.html', message=message)
        else:
            message = 'Username not found'
            return render_template('login.html', message=message)
    return render_template('login.html', message=message)



@app.route("/logout", methods=["POST", "GET"])
def logout():
    if "username" in session:
        session.pop("username", None)
        return render_template("signout.html")
    else:
        return render_template('index.html')

if __name__ == "__main__":
  app.run(debug=True)


