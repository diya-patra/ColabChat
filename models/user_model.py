from bson import ObjectId
import bcrypt

def get_user_by_email(users_col, email: str):
    return users_col.find_one({"email": email})

def get_user_by_id(users_col, user_id: str):
    return users_col.find_one({"_id": ObjectId(user_id)})

def create_user(users_col, username: str, email: str, password: str):
    if get_user_by_email(users_col, email):
        return None, "Email already registered"
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    res = users_col.insert_one({
        "username": username,
        "email": email,
        "passwordHash": pw_hash
    })
    return str(res.inserted_id), None