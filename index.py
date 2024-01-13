from flask import Flask, request, make_response,jsonify,render_template,redirect, url_for
import mysql.connector
import random
import os
from flask_mail import Mail,Message
import bcrypt
import jwt
import datetime

app = Flask(__name__)

app.secret_key = os.getenv('APP_SECRET_KEY')



app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = ''
app.config['MAIL_PASWORD'] = ''

mail = Mail(app)

connection=mysql.connector.connect(host=os.getenv('HOST_NAME'),user=os.getenv('USER'),passwd=os.getenv('DATABASE_KEY'),database=os.getenv('DATABASE_NAME'))
cur=connection.cursor()
salt = bcrypt.gensalt()


def get_token(email):
     # Define a secret key (this should be kept secret)
        secret_key = os.getenv('SECRET_KEY')

        # Define the payload (claims) of the token
        payload = {
            "email": email,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)  # Token expiration time
        }

        # Generate the token
        token = jwt.encode(payload, secret_key, algorithm='HS256')

        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        return token

def send_mail(user):
    token = get_token(user['email'])
    msg = Message('Password Reset Request',recipients = [user['email']],sender='noreply@gmail.com')
    msg.body = f''' To reset the password. Please follow the link below.

    {url_for('reset_token',token= token,_external=True)}
    
    If you didn't send a password reset request. Please ignore this message.

    '''
    mail.send(msg)

def verify_token(token):
    secret_key = os.getenv('SECRET_KEY')
    try:
        # Verify and decode the token
        decoded_payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        # Store the decoded payload for future use if needed
        request.user = decoded_payload
    except :
        return None
    return request.user['email']

    

# @app.route("/signup")
# def signup():
#     return render_template("signup.html")


@app.before_request
def before_request():
    secret_key = os.getenv('SECRET_KEY')
    # Exclude specific routes from token verification (e.g., login route)
    if request.endpoint and request.endpoint != 'login' and request.endpoint != 'register':
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        try:
            # Verify and decode the token
            decoded_payload = jwt.decode(token, secret_key, algorithms=['HS256'])
            # Store the decoded payload for future use if needed
            request.current_user = decoded_payload
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

@app.route("/register", methods=['POST'])
def register():
    try:
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        phone_no = request.form['phone_no']

        if not phone_no.isdigit() or len(phone_no) != 10:
            return make_response("Phone number must be a 10-digit number.", 400)

        if password != confirm_password:
            return make_response("Passwords do not match.", 400)

        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

        query = """INSERT INTO cust_info
                            (name, email, pass, phone_no)
                            VALUES (%s, %s, %s, %s);"""
        cur.execute(query, (name, email, hashed, phone_no))
        connection.commit()
        cur.close()

        return make_response("User successfully registered.", 200)
    
    except Exception as e:
        return make_response(f"An error occurred: {str(e)}", 500)
    

  
@app.route("/login", methods=['GET','POST'])
def login():
    if request.method == 'POST':
        try:
            data = request.get_json()
            email = data.get('email', '')
            password = data.get('pass', '')

            if not email or not password:
                return jsonify({'error': 'Email and Password are required'}), 400

            query_check_email = "SELECT pass FROM cust_info WHERE email = %s"
            cur.execute(query_check_email, (email,))
            email_exist = cur.fetchone()

            if email_exist is None:
                return jsonify({'error': 'Email does not exist in the database'}), 404

            stored_pass = email_exist[0].encode('utf-8')
            provided_pass = password.encode('utf-8')
            check_pass = bcrypt.checkpw(provided_pass, stored_pass)
            if not check_pass:
                return jsonify({'error': 'Incorrect password'}), 401
            
            # Define a secret key (this should be kept secret)
            secret_key = os.getenv('SECRET_KEY')

            # Define the payload (claims) of the token
            payload = {
                "email": email,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expiration time
            }

            # Generate the token
            token = jwt.encode(payload, secret_key, algorithm='HS256')

            return jsonify({'message': "Login successful"}), 200

        except Exception as e:
            return jsonify({'error': f'Error: {str(e)}'}), 500

        finally:
            # Always close the cursor and fetch all remaining results
            cur.close()
            connection.commit()
    # else:
    #     return render_template("login.html")


@app.route('/reset_pass', methods=['GET', 'POST'])
def reset_req():
    user = request.get_json()

    query_check_email = "SELECT email FROM cust_info WHERE email = %s"
    cur.execute(query_check_email, (user['email'],))
    email_exist = cur.fetchone()

    if email_exist is None:
        return jsonify({'error': 'Email does not exist in the database'}), 404
    else:

        send_mail()
        return redirect('/login')
    # return render_template('resest_req.html')

@app.route('/reset_pass/<token>', methods=['GET', 'POST'])
def reset_token(token):
    user = verify_token(token)
    if user is None:
        jsonify({'error': 'That is a invalid token or expired. Plaese try again.'}), 401
        return redirect('/reset_pass')
    else:
        try:
            password = request.form['password']
            confirm_password = request.form['confirm_password']

            if password != confirm_password:
                return make_response("Passwords do not match.", 400)

            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

            query = '''UPDATE cust_info 
                        SET pass = %s WHERE email = %s;'''
            cur.execute(query, (hashed, request.current_user['email']))
            connection.commit()
            cur.close()

            make_response("Password successfully changed.", 200)
            return redirect("/login")
        
        except Exception as e:
            return make_response(f"An error occurred: {str(e)}", 500)
    # return render_template("change_password.html")
        

@app.route('/displaybooks', methods=['GET', 'POST'])
def list_books():
    try:
        query = """SELECT * FROM books;"""
        cur.execute(query)
        res = cur.fetchall()
        if not res:
                return jsonify({'error': 'No books found'}), 404
        user_data = [{'book_name': row[1], 'author': row[2], 'price': row[3]} for row in res]
        return jsonify(user_data),200
    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}),500
    finally:
        cur.close()

@app.route("/addcart", methods=['POST'])
def addcart():
    user = request.get_json()
    if 'book_name' not in user:
        return jsonify({'error': "Book's name is required"}),400
    if 'price' not in user:
        return jsonify({'error': "Book's price is required"}),400
    try:
        query = """INSERT INTO cart
                            ( email, book_name, price)
                            VALUES (%s, %s, %s);"""
        cur.execute(query, (request.current_user['email'], user['book_name'], user['price']))
        connection.commit()

        return jsonify({'message': "Success"}), 200
    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}),500
    finally:
        cur.close()

@app.route('/display_cartbooks', methods=['GET', 'POST'])
def list_cartbooks():
    try:
        query = """SELECT * FROM cart WHERE email = %s;"""
        cur.execute(query, (request.current_user['email'],))
        

        res = cur.fetchall()
        if not res:
                return jsonify({'error': 'No books found'}), 404
        user_data = [{'book_name': row[1], 'price': row[2]} for row in res]
        return jsonify(user_data),200
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401

    except jwt.InvalidTokenError as e:
        # Add logging to inspect the specific error
        app.logger.error(f"Invalid token error: {e}")
        return jsonify({'error': f'Invalid token: {str(e)}'}), 401
    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}),500
    finally:
        cur.close()
    
@app.route('/addtransaction', methods=['GET', 'POST'])
def add_transaction():
    user = request.get_json()
    if 'book_name' not in user:
        return jsonify({'error': 'Book Name is required'}),400
    if 'price' not in user:
        return jsonify({'error': 'Price is required'}),400
    if 'quantity' not in user:
        return jsonify({'error': 'Quantity is required'}),400
    try:
        query = """INSERT INTO transaction
                            (email, book_name, price, quantity)
                            VALUES (%s, %s, %s, %s);"""
        cur.execute(query, (request.current_user['email'], user['book_name'],user['price'],user['quantity']))
        query2 = """DELETE FROM cart WHERE email = %s AND book_name = %s;"""
        cur.execute(query2, (request.current_user['email'],user['book_name']))
        connection.commit()
        return make_response("Your order has been placed. It will be delivered to you in 2-4 business days.", 200)
    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}),500
    finally:
        cur.close()



@app.route("/getUserName", methods=['POST'])
def getUserName():
    user = request.get_json()
    if 'name' not in user:
        return jsonify({'error': 'User name is required'}),400
    try:
        query = """SELECT * FROM cust_info
                            WHERE name = %s """
        cur.execute(query,(user['name'],))
        res = cur.fetchall()
        if not res:
            return jsonify({'error': 'User not found'}), 404
        
        user_data = [{'name': row[0], 'email': row[1]} for row in res]
        return jsonify(user_data),200
    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}),500
    finally:
        cur.close()


@app.route("/updateName", methods=['POST'])
def updateName():
    user = request.get_json()
    if 'name' not in user:
        return jsonify({'error': 'User name is required'}),400
    if 'email' not in user:
        return jsonify({'error': 'Email is required'}),400
    try:
        query_check_email ="SELECT COUNT(*) FROM cust_info WHERE email = %s"
        cur.execute(query_check_email,(user['email'],))
        email_exist = cur.fetchone()[0]

        if email_exist == 0:
            return jsonify({'error':'Email does not exist in the database'}), 404
        
        query = """UPDATE cust_info
                            SET name = %s
                            WHERE email = %s;"""
        cur.execute(query, (user['name'], user['email']))
        connection.commit()

        return jsonify({'message': "Success"}), 200
    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}),500
    finally:
        cur.close()
    


@app.route("/addbook", methods=['POST'])
def addBook():
    user = request.get_json()
    query = """INSERT INTO books
                            (book_id, book_name, author, price)
                            VALUES (%s, %s, %s, %s);"""
    cur.execute(query, (user['id'], user['name'], user['author'], user['price']))
    connection.commit()
    cur.close()
    return make_response("Successful",200)

if __name__=="__main__":
    app.run(debug=True)
