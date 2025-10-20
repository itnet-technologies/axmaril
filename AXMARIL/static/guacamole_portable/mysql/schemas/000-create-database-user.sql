ALTER USER 'root'@'localhost' IDENTIFIED BY 'Password01*';
ALTER USER 'root'@'localhost' PASSWORD EXPIRE NEVER;
CREATE DATABASE guacamole_db;
CREATE USER 'guacamole_user'@'localhost' IDENTIFIED BY 'Password01*';
GRANT ALL PRIVILEGES ON guacamole_db.* TO 'guacamole_user'@'localhost';
FLUSH PRIVILEGES;