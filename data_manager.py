import connection
import hashing_utility


@connection.connection_handler
def add_user(cursor, register_form):
    hashed_password = hashing_utility.hash_password(register_form['password'])
    cursor.execute("""
                        INSERT INTO users (user_name, user_login, password, email) VALUES ('%s', '%s', '%s', '%s')"""
                   % (register_form['user_name'], register_form['name'], hashed_password, register_form['email']))

@connection.connection_handler
def check_login_password(cursor, login_data):
    cursor.execute("""
    SELECT password FROM users WHERE user_name = '%s'
     """ % (login_data['user_name']))
    db_password = cursor.fetchall()
    if len(db_password) == 0:
        return False
    else:
        compare = hashing_utility.verify_password(login_data['password'],db_password[0]['password'])
        print(compare)
        return compare

@connection.connection_handler
def check_login_user_name(cursor, login_data):
    cursor.execute("""
     SELECT user_name FROM users WHERE user_name = '%s' 
    """ % (login_data['user_name']))

    compare_result = cursor.fetchall()
    if len(compare_result) == 0:
        return False
    else:
        return True

@connection.connection_handler
def check_user(cursor, register_form):
    cursor.execute("""
     SELECT user_name, email FROM users WHERE user_name = '%s' OR email = '%s'
    """ % (register_form['user_name'], register_form['email']))

    compare_result = cursor.fetchall()
    if len(compare_result) == 0:
        add_user(register_form)
        return 'registration successfull'
    else:
        return 'user with these data already exist'