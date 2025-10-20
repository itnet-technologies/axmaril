from flask import jsonify, Blueprint,request, url_for
# from pymongo import MongoClient
from modules.required_packages import (
    encode_token, has_role, mail_sender, parse_json, safe_access, secret_access, 
    secrets, users, shares, decrypt, encrypt, get_userid_by_token, isErrorKey, run_dag,
    validation, salt, jwt, db002, file_server_url, delete_safe_util
)
import mysql.connector


class sql_command:
    def __init__(self, host, port, username, password, db_name):
        self.conn = mysql.connector.connect(
            host=host,
            port=port,
            user=username,
            password=password,
            database=db_name
        )
        self.curs = self.conn.cursor()

    def add(self, table, values_dict):
        columns, values = "", ""
        for key, value  in values_dict.items():
            columns += (f"{key}, ")
            values += (f"'{value}', ")
        columns, values = columns[:-2], values[:-2]

        self.curs.execute(f"INSERT INTO {table} ({columns}) VALUES({values})")
        self.conn.commit()
        result = self.curs.fetchall()
        return (result) if len(result) != 0 else ["Row created"]

    def update(self, table, column, new_value, unique_key, unique_key_value):
        self.curs.execute(f"UPDATE {table} SET {column} = '{new_value}' WHERE {unique_key} = '{unique_key_value}'")
        self.conn.commit()
        result = self.curs.fetchall()
        return (result) if len(result) != 0 else ["Row modified"]
    def close(self):
        self.conn.close()


COMMAND_REQUEST = Blueprint("command", __name__)

@COMMAND_REQUEST.route('/', methods=['POST'])
def send_command():
    validated = validation(allowNullData=False)
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        config = req['config']
        operation = req['operation']
        if req["db_type"] == 'sql':
            sender = sql_command(
                config['host'],
                config['port'],
                config['username'],
                config['password'],
                config['db_name']
            )
        if operation['command'] == 'add':
            response = sender.add(operation['table'], operation['values'])
        elif operation['command'] == 'update':
            response = sender.update(operation['table'], operation['column'],
            operation['new_value'], operation['unique_key'], operation['unique_key_value'])

        sender.close()
        return jsonify({
            "message": str(response),
            "status": "success"
        }),200
    except Exception as e:
        sender.close()
        return jsonify({
            "message": str(e),
            "status": "failed"
        }),400